#Requires -Version 3.0
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Citrix Worker Deployment Hyper-V Gen2
.Description
    Erstellt anhand einer XML alle benötigten Worker.
.PARAMETER Path
    Pfad zur XML.
.PARAMETER VLAN
    Optinoal Setzt auf den VMs gleich den passend VLAN Tag.
.PARAMETER ISO
    Optional Fügt die ISO der VM hinzu und ändert die Boot Reihnfolge auf CD.
.PARAMETER DHCP_PVS
    Optional Fügt eine DHCP Reservierung für PVS Adapter hinzu.
.PARAMETER DHCP_PROD
    Optional Fügt eine DHCP Reservierung für Prod Adapter hinzu.
.PARAMETER PVS
    Optional Fügt direkt im PVS das Device mit der passenden MAC Adresse hinzu.
.EXAMPLE
    .\Citrix Worker Deployment Hyper-V Gen2.ps1 -Path "S:\Development\_Scripte\hp_Citrix_Worker_Deployment\Beispiel.xml"
    Erstellt VM wie in der XML angegeben und ist für PXE Boot vorgehesen.
.EXAMPLE
    .\Citrix Worker Deployment Hyper-V Gen2.ps1 -Path "S:\Development\_Scripte\hp_Citrix_Worker_Deployment\Beispiel.xml" -VLAN
    Setzt zusätzlich den VLAN Tag auf den Netwerk Adaptern.
.EXAMPLE
    .\Citrix Worker Deployment Hyper-V Gen2.ps1 -Path "S:\Development\_Scripte\hp_Citrix_Worker_Deployment\Beispiel.xml" -VLAN -PVS
    Setzt zusätzlich den VLAN Tag auf den Netwerk Adaptern und fügt die Angelegten VM gleich zum PVS hinzu.
.NOTES
    Author: 
    Patrik Horn (PHo)
    Link:	
    www.hornpa.de
    History:
    2017-04-13 - v0.03 - Bug fixing - wrong variable for PVS MAC Device (PHo)
    2017-02-10 - v0.02 - Some bug fixing and code cleanup (PHo)
    2016-12-29 - v0.01 - Script created (PHo)
#>

Param (

    [Parameter(Mandatory=$false,Position=1)]
    [string]$Path ,

    [switch]$VLAN = $false ,

    [switch]$ISO = $false ,

    [switch]$DHCP_PVS = $false ,

    [switch]$DHCP_PROD = $false ,

    [switch]$PVS = $false

)

#-----------------------------------------------------------[Pre-Initialisations]------------------------------------------------------------
#region

	#Set Error Action to Silently Continue
	$ErrorActionPreference = 'Stop'

	#Set Verbose Output
	$VerbosePreference = "SilentlyContinue" # Continue = Shows Verbose Output / SilentlyContinue = No Verbose Output

	#Get Start Time
	$StartPS = (Get-Date)

	#Set Enviorements
	Write-Verbose "Set Variable with MyInvocation"
	$scriptName_PS = Split-Path $MyInvocation.MyCommand -Leaf
	$scriptDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
    $scriptHelp = Get-Help "$scriptDirectory\$scriptName_PS" -Full
    $scriptName_SYNOPSIS = $scriptHelp.SYNOPSIS
    $scriptName_NOTES =  $scriptHelp.alertSet.alert.text
    	
	# Load the Windows Forms assembly
	Add-Type -Assembly System.Windows.Forms

	#Check Log Folder
	Write-Verbose "Log Variables"
	$LogPS = "$env:windir\Logs\Scripts\"+(Get-Date -Format yyyy-MM-dd_HHmm)+"_"+$scriptName_SYNOPSIS+".log"
	IF (!(Test-Path (Split-Path $LogPS))){
		Write-Verbose "Create Log Folder"
		New-Item (Split-Path $LogPS) -Type Directory | Out-Null
	}

#endregion
#-----------------------------------------------------------[Functions]----------------------------------------------------------------------
#region

# Based on pvsgen2.ps1 from citrix pvs folders
function Add-VMNetworkAdapterWithIDGen2() {
<#
    .SYNOPSIS
     ! Noch Offen !
    .DESCRIPTION
     ! Noch Offen !
    .PARAMETER IDFName
     ! Noch Offen !
    .EXAMPLE
     ! Noch Offen !
    .NOTES
     AUTHOR: Patrik Horn
     LASTEDIT: 29.12.2016
     VERSION: 1.00
    .LINK
     http://www.hornpa.de
#>
    [CmdletBinding(SupportsShouldProcess=$True)]
    param(
        [string]$ComputerName = "localhost",
        [Parameter(Mandatory=$false,Position=1)]
        [string]$VMName,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$VSIGuid,
        [Parameter(Mandatory=$false,Position=2)]
        [string]$NIC_Name
    )
	
    #The well known PVS Virtual System Identifier for the Streaming synthetic NIC 
    #$VSIGuid = "{c40165e3-3bce-43f6-81ec-8733731ddcba}"

    #Retrieve the Hyper-V Management Service, The ComputerSystem class for the VM and the VM’s SettingData class. 
    $Msvm_VirtualSystemManagementService = Get-WmiObject -ComputerName $ComputerName -Namespace root\virtualization\v2 -Class Msvm_VirtualSystemManagementService 

    $Msvm_ComputerSystem = Get-WmiObject -ComputerName $ComputerName -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem -Filter "ElementName='$vmName'" 
    $Msvm_ComputerSystem

    $Msvm_VirtualSystemSettingData = ($Msvm_ComputerSystem.GetRelated("Msvm_VirtualSystemSettingData", "Msvm_SettingsDefineState", $null, $null, "SettingData", "ManagedElement", $false, $null) | % {$_}) 

    #Retrieve the default (primordial) resource pool for Synthetic Ethernet Port’s 
    $Msvm_ResourcePool = Get-WmiObject -ComputerName $ComputerName -Namespace root\virtualization\v2 -Class Msvm_ResourcePool -Filter "ResourceSubType = 'Microsoft:Hyper-V:Synthetic Ethernet Port' and Primordial = True" 

    #Retrieve the AllocationCapabilities class for the Resource Pool 
    $Msvm_AllocationCapabilities = ($Msvm_ResourcePool.GetRelated("Msvm_AllocationCapabilities", "Msvm_ElementCapabilities", $null, $null, $null, $null, $false, $null) | % {$_}) 

    #Query the relationships on the AllocationCapabilities class and find the default class (ValueRole = 0) 
    $Msvm_SettingsDefineCapabilities = ($Msvm_AllocationCapabilities.GetRelationships("Msvm_SettingsDefineCapabilities") | Where-Object {$_.ValueRole -eq "0"}) 

    #The PartComponent is the Default SyntheticEthernetPortSettingData class values 
    $Msvm_SyntheticEthernetPortSettingData = [WMI]$Msvm_SettingsDefineCapabilities.PartComponent 

    #Specify a unique identifier, a friendly name and specify dynamic mac addresses 
    $Msvm_SyntheticEthernetPortSettingData.VirtualSystemIdentifiers = $VSIGuid 
    $Msvm_SyntheticEthernetPortSettingData.ElementName = $NIC_Name 
    $Msvm_SyntheticEthernetPortSettingData.StaticMacAddress = $false 

    #Add the network adapter to the VM 
    $Msvm_VirtualSystemManagementService.AddResourceSettings($Msvm_VirtualSystemSettingData, $Msvm_SyntheticEthernetPortSettingData.GetText(1))

}

# Function Add-PVSDevice
function Add-PVSDevice() {
<#
    .SYNOPSIS
     ! Noch Offen !
    .DESCRIPTION
     ! Noch Offen !
    .PARAMETER IDFName
     ! Noch Offen !
    .EXAMPLE
     ! Noch Offen !
    .NOTES
     AUTHOR: Patrik Horn
     LASTEDIT: 28.03.2015
     VERSION: 1.00
    .LINK
     http://www.makrofactory.de
     http://www.hornpa.de
#>
    [CmdletBinding(SupportsShouldProcess=$True)]
    param(
        [string]$Computername = 'localhost',
        [Parameter(Mandatory=$True,Position=1)]
        [string]$DeviceName,
        [Parameter(Mandatory=$True,Position=2)]
        [string]$DeviceMac,
        [Parameter(Mandatory=$True,Position=3)]
        [string]$CollectionName,
        [Parameter(Mandatory=$True,Position=4)]
        [string]$SiteName
    )
    # Variable
    $MCLI = "C:\Program Files\Citrix\Provisioning Services\MCLI.exe"
    # Check if PVS is Installed
    # ! Noch Offen !
    # Add Device to Collection
    Invoke-Command -ComputerName $Computername -ScriptBlock {&"$using:MCLI" add Device -r deviceName=$using:DeviceName deviceMac=$using:DeviceMac collectionName=$using:CollectionName SiteName=$using:SiteName} -Authentication Default
}

#endregion
#-----------------------------------------------------------[Main-Initialisations]-----------------------------------------------------------
#region

    ## Host Output
    $WelcomeMessage =   "##################################"  + [System.Environment]::NewLine + `
                        " $scriptName_SYNOPSIS"  + [System.Environment]::NewLine + `
                        " "  + [System.Environment]::NewLine + `
                        " $scriptName_NOTES"+ [System.Environment]::NewLine + `
                        "##################################"
                        
    Write-Host $WelcomeMessage -ForegroundColor Gray

    ## Load Preq
	Write-Host "Unlock all Functions" -ForegroundColor Cyan
    $UnblockFiles = Get-ChildItem -Path $scriptDirectory -Recurse -Filter "*.ps1" | Unblock-File
    Write-Host "Loading System Variable" -ForegroundColor Cyan
	$OS = Get-WmiObject -Class win32_operatingsystem

    ## Requierments
	Write-Host "Checking Requierments" -ForegroundColor Cyan

	Write-Verbose "Checking Path Variable"
	IF([string]::IsNullOrEmpty($Path)) 
    {            
		Write-Verbose "Select XML file..."
		$Path = (Get-ChildItem -Path $scriptDirectory -Filter "*.xml" | Out-GridView -Title "Bitte eine Datei auswählen" -PassThru).FullName
    }

	Write-Verbose "Checking for Server OS"
	Switch ($OS.ProductType)
    {
		3 {
			Write-Verbose "Server OS detected, contiune"
		} 
		Default {
			Write-Host "Skript unterstützt nur Server OS, Skript wird abgebrochen!"  -ForegroundColor Red
			Exit
		}
	}

	Write-Verbose "Checking Windows Feautre RSAT-Hyper-V-Tools"
	If (!(Get-WindowsFeature RSAT-Hyper-V-Tools).Installed) 
    {
			Write-Host "Das Feature RSAT-Hyper-V-Tools muss installiert werden, Skript wird abgebrochen!" -ForegroundColor Red
			Exit
	}
    
    IF($DHCP_PVS -or $DHCP_PROD)
    {
	    Write-Verbose "Checking Windows Feautre RSAT-DHCP"
	    If (!(Get-WindowsFeature RSAT-DHCP).Installed) 
        {
			    Write-Host "Das Feature RSAT-DHCP muss installiert werden, Skript wird abgebrochen!" -ForegroundColor Red
			    Exit
	    }
    }

    ## Load Variable
    Write-Host "Loading Global Variable" -ForegroundColor Cyan
    $xmlfile = [XML] (Get-Content -Path $Path)
    $GL_SystemDisk_Name = $xmlfile.Deployment_VM.Global.SystemDisk_Name
    [int64]$GL_SystemDiske_Size = 1GB*($xmlfile.Deployment_VM.Global.SystemDisk_Size)
	$GL_CacheDisk_Name = $xmlfile.Deployment_VM.Global.CacheDisk_Name
	[int64]$GL_CachDiske_Size = 1GB*($xmlfile.Deployment_VM.Global.CacheDisk_Size)
	$GL_NIC_PVS_ID = $xmlfile.Deployment_VM.Global.NIC_ID_PVS
	$GL_NIC_SRV_ID = $xmlfile.Deployment_VM.Global.NIC_ID_SRV
	$GL_NIC_Name_PVS_Legacy = $xmlfile.Deployment_VM.Global.NIC_Name_PVS_Legacy
	$GL_NIC_Name_PVS = $xmlfile.Deployment_VM.Global.NIC_Name_PVS
	$GL_NIC_Name_SRV = $xmlfile.Deployment_VM.Global.NIC_Name_SRV
	$GL_Switch_Name_PVS = $xmlfile.Deployment_VM.Global.Switch_Name_PVS
	$GL_Switch_Name_SRV = $xmlfile.Deployment_VM.Global.Switch_Name_SRV
	$GL_Switch_VLAN_PVS = $xmlfile.Deployment_VM.Global.Switch_VLAN_PVS
	$GL_Switch_VLAN_SRV = $xmlfile.Deployment_VM.Global.Switch_VLAN_SRV
    $GL_SecureBoot = $xmlfile.Deployment_VM.Global.SecureBoot
	$GL_DHCP_Server_SRV = $xmlfile.Deployment_VM.Global.DHCP_Server_SRV
	$GL_DHCP_Scope_SRV = $xmlfile.Deployment_VM.Global.DHCP_Scope_SRV
	$GL_DHCP_Server_PVS = $xmlfile.Deployment_VM.Global.DHCP_Server_PVS
	$GL_DHCP_Scope_PVS = $xmlfile.Deployment_VM.Global.DHCP_Scope_PVS
	$GL_PVS_Server = $xmlfile.Deployment_VM.Global.PVS_Server
	$GL_PVS_SiteName = $xmlfile.Deployment_VM.Global.PVS_Sitename
	$GL_NIC_Guid_PVS = $xmlfile.Deployment_VM.Global.NIC_GUID_Gen2_PVS
    $GL_NIC_Guid_SRV = $xmlfile.Deployment_VM.Global.NIC_GUID_Gen2_SRV
	$VMs = $xmlfile.Deployment_VM.VMs.VM
	$Hosts = $xmlfile.Deployment_VM.Hosts.Host
	$Result = @{}

#endregion
#-----------------------------------------------------------[Execution]----------------------------------------------------------------------	
#region

    $SelectVMs = $VMS | Out-GridView -Title "Bitte eine oder mehrere VMs auswählen" -PassThru
	
	Foreach ($VM in $SelectVMs){
		# Variable
		$VM_Host = $VM.VM_Host
		$VM_Name =  $VM.VM_Name
		$VM_CPU = $VM.VM_CPU
		[int64]$VM_RAM = 1GB*($VM.VM_RAM)
		$VM_Path = $VM.VM_Path
		$MAC_PVS = $VM.MAC_PVS
		$MAC_SRV = $VM.MAC_SRV
		$IP_Adresse_PVS = $VM.IP_Adresse_PVS
		$IP_Adresse_SRV = $VM.IP_Adresse_SRV
		$PVS_Collection = $VM.PVS_Collection
		$ISO_Path = $VM.ISO_Path
		
		Write-Host -NoNewline "Running: " 
		Write-Host $VM_Name
		# Create VM
		Write-Host -NoNewline " - Create VM.."

        # Checking if VM already exists
        IF((Get-VM -ComputerName $VM_Host).Name -like "$VM_Name")
        {
            $Msg = "Exists"
            Write-Host $Msg -ForegroundColor Yellow
            $Tmp_Result_VM = $Msg
            Continue
        }

        # Create VM
        Try
        {
            New-VM -ComputerName $VM_Host -Name $VM_Name -Generation 2 -NoVHD -Path $VM_Path  | Out-Null
            $Msg = "Successfully"
            Write-Host $Msg -ForegroundColor Green
            $Tmp_Result_VM = $Msg
        }
        Catch
        {
            $Msg = "Error: " + $Error[0].Exception.Message
            Write-Host $Msg -ForegroundColor Red
            $Tmp_Result_VM = $Msg
            Continue
        }

        # Remove All Network Adapter
		Write-Host -NoNewline " - Remove All Network Adapter..."
        Try
        {
            Get-VMNetworkAdapter -ComputerName $VM_Host -VMName $VM_Name | Remove-VMNetworkAdapter | Out-Null            
            $Msg = "Successfully"
            Write-Host $Msg -ForegroundColor Green
            $Tmp_Result_Remove_Default_Network_Adapter = $Msg
        }
        Catch
        {
            $Msg = "Error: " + $Error[0].Exception.Message
            Write-Host $Msg -ForegroundColor Red
            $Tmp_Result_Remove_Default_Network_Adapter = $Msg
        }

		# Set CPU, RAM, Settings
		Write-Host -NoNewline " - Set CPU, RAM and Settings..."
        Try
        {
		    Set-VM -ComputerName $VM_Host -Name $VM_Name -ProcessorCount $VM_CPU -MemoryStartupBytes $VM_RAM -AutomaticStopAction ShutDown -AutomaticStartAction Nothing | Out-Null
            $Msg = "Successfully"
            Write-Host $Msg -ForegroundColor Green
            $Tmp_Result_VM_Settings = $Msg
        }
        Catch
        {
            $Msg = "Error: " + $Error[0].Exception.Message
            Write-Host $Msg -ForegroundColor Red
            $Tmp_Result_VM_Settings = $Msg
        }

        # Add PVS Network Adapter
		Write-Host -NoNewline " - Add PVS Network Adapter..."
        Try
        {
		    Add-VMNetworkAdapterWithIDGen2 -ComputerName $VM_Host -VMName $VM_Name -NIC_Name $GL_NIC_Name_PVS -VSIGuid $GL_NIC_Guid_PVS | Out-Null
            $Msg = "Successfully"
            Write-Host $Msg -ForegroundColor Green
            $Tmp_Result_Add_PVS_Network_Adapter = $Msg
        }
        Catch
        {
            $Msg = "Error: " + $Error[0].Exception.Message
            Write-Host $Msg -ForegroundColor Red
            $Tmp_Result_Add_PVS_Network_Adapter = $Msg
        }

        # Add SRV Network Adapter
		Write-Host -NoNewline " - Add SRV Network Adapter..."
        Try
        {
		    Add-VMNetworkAdapterWithIDGen2 -ComputerName $VM_Host -VMName $VM_Name -NIC_Name $GL_NIC_Name_SRV -VSIGuid $GL_NIC_Guid_SRV | Out-Null
            $Msg = "Successfully"
            Write-Host $Msg -ForegroundColor Green
            $Tmp_Result_Add_PROD_Network_Adapter = $Msg
        }
        Catch
        {
            $Msg = "Error: " + $Error[0].Exception.Message
            Write-Host $Msg -ForegroundColor Red
            $Tmp_Result_Add_PROD_Network_Adapter = $Msg
        }

		# Create Cache Disk
		Write-Host -NoNewline " - Create Cache Disk..."
        Try
        {
		    Invoke-Command -ComputerName $VM_Host -ScriptBlock {New-VHD -Path "$using:VM_Path\$using:VM_Name\Virtual Hard Disks\$using:GL_CacheDisk_Name.vhdx" -SizeBytes $using:GL_CachDiske_Size -Dynamic | Mount-VHD -Passthru |Initialize-Disk -PartitionStyle MBR -Passthru | New-Partition -AssignDriveLetter:$FALSE -UseMaximumSize | Format-Volume -FileSystem NTFS -Confirm:$false -Force | Set-Volume -NewFileSystemLabel "Cache" | Out-Null } -Authentication Default
		    Invoke-Command -ComputerName $VM_Host -ScriptBlock {Get-VHD -Path "$using:VM_Path\$using:VM_Name\Virtual Hard Disks\$using:GL_CacheDisk_Name.vhdx" | Dismount-VHD -Passthru | Out-Null} -Authentication Default
            $Msg = "Successfully"
            Write-Host $Msg -ForegroundColor Green
            $Tmp_Result_Create_CacheDisk = $Msg
        
        }
        Catch
        {
            $Msg = "Error: " + $Error[0].Exception.Message
            Write-Host $Msg -ForegroundColor Red
            $Tmp_Result_Create_CacheDisk = $Msg
        }

        # Add Cache Disk
		Write-Host -NoNewline " - Add Cache Disk to VM..."
        Try
        {
		    Add-VMHardDiskDrive -ComputerName $VM_Host -VMName $VM_Name -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 1 -Path "$VM_Path\$VM_Name\Virtual Hard Disks\$GL_CacheDisk_Name.vhdx"  | Out-Null
            $Msg = "Successfully"
            Write-Host $Msg -ForegroundColor Green
            $Tmp_Result_Add_CacheDisk = $Msg
        }
        Catch
        {
            $Msg = "Error: " + $Error[0].Exception.Message
            Write-Host $Msg -ForegroundColor Red
            $Tmp_Result_Add_CacheDisk = $Msg
        }

        # Change Boot Order
		Write-Host -NoNewline " - Change Boot Order to PVS PXE..."
        Try
        {
            $VM_BootOrder_network = Get-VMNetworkAdapter -ComputerName $VM_Host -VMName $VM_Name | Where-Object { $_.Name -like $GL_NIC_Name_PVS }
            Set-VMFirmware -ComputerName $VM_Host -VMName $VM_Name -BootOrder $VM_BootOrder_network
            $Msg = "Successfully"
            Write-Host $Msg -ForegroundColor Green
            $Tmp_Result_BootOrder = $Msg
        }
        Catch
        {
            $Msg = "Error: " + $Error[0].Exception.Message
            Write-Host $Msg -ForegroundColor Red
            $Tmp_Result_BootOrder = $Msg
        }

		# Set MAC Adress
		Write-Host -NoNewline " - Set MAC Adress..."
        Try
        {
		    Set-VMNetworkAdapter -ComputerName $VM_Host -VMName $VM_Name -VMNetworkAdapterName $GL_NIC_Name_PVS -StaticMacAddress $VM.MAC_PVS | Out-Null
		    Set-VMNetworkAdapter -ComputerName $VM_Host -VMName $VM_Name -VMNetworkAdapterName $GL_NIC_Name_SRV -StaticMacAddress $VM.MAC_SRV | Out-Null
            $Msg = "Successfully"
            Write-Host $Msg -ForegroundColor Green
            $Tmp_Result_SET_MAC_Adress = $Msg
        }
        Catch
        {
            $Msg = "Error: " + $Error[0].Exception.Message
            Write-Host $Msg -ForegroundColor Red
            $Tmp_Result_SET_MAC_Adress = $Msg
        }

		# Connect vSwitch to VM
		Write-Host -NoNewline " - Connect vSwitch to VM..."
        Try
        {
		    Connect-VMNetworkAdapter -ComputerName $VM_Host -VMName $VM_Name -Name $GL_NIC_Name_PVS -SwitchName $GL_Switch_Name_PVS | Out-Null
		    Connect-VMNetworkAdapter -ComputerName $VM_Host -VMName $VM_Name -Name $GL_NIC_Name_SRV -SwitchName $GL_Switch_Name_SRV | Out-Null
            $Msg = "Successfully"
            Write-Host $Msg -ForegroundColor Green
            $Tmp_Result_Connect_vSwitch = $Msg
        }
        Catch
        {
            $Msg = "Error: " + $Error[0].Exception.Message
            Write-Host $Msg -ForegroundColor Red
            $Tmp_Result_Connect_vSwitch = $Msg
        }

		# Set Network Adapter VLANs
		IF($VLAN)
        {
			Write-Host -NoNewline " - Set Network Adapter VLAN..."
            Try
            {
			    Set-VMNetworkAdapterVlan -ComputerName $VM_Host -VMName $VM_Name -VMNetworkAdapterName $GL_NIC_Name_PVS -VlanId $GL_Switch_VLAN_PVS -Access | Out-Null
			    Set-VMNetworkAdapterVlan -ComputerName $VM_Host -VMName $VM_Name -VMNetworkAdapterName $GL_NIC_Name_SRV -VlanId $GL_Switch_VLAN_SRV -Access | Out-Null
                $Msg = "Successfully"
                Write-Host $Msg -ForegroundColor Green
                $Tmp_Result_Add_VLANs_Network_Adapter = $Msg
            }
            Catch
            {
                $Msg = "Error: " + $Error[0].Exception.Message
                Write-Host $Msg -ForegroundColor Red
                $Tmp_Result_Add_VLANs_Network_Adapter = $Msg
            }
			
		}

        # Disable SecureBoot
        IF($GL_SecureBoot -like "0")
        {
            Write-Host -NoNewline " - Disable SecureBoot..."
            Try
            {
                Set-VMFirmware -ComputerName $VM_Host -VMName $VM_Name -EnableSecureBoot Off
                $Msg = "Successfully"
                Write-Host $Msg -ForegroundColor Green
                $Tmp_Result_DHCP_Reservation = $Msg
            }
            Catch
            {
                $Msg = "Error: " + $Error[0].Exception.Message
                Write-Host $Msg -ForegroundColor Red
                $Tmp_Result_DHCP_Reservation = $Msg
            }
        }

		# Add ISO to VM
		IF($ISO)
        {
			Write-Host -NoNewline " - Change Boot Order..."
            Try{
                Write-Host " - Add DVD Drive to VM..."
                Get-VM -ComputerName $VM_Host -Name $VM_Name | Add-VMDvdDrive -Path $VM_ISO | Out-Null
			    Write-Host " - Change Boot Order to DVD Drive..." 
                $VM_BootOrder_dvd = Get-VMDvdDrive -ComputerName $VM_Host -VMName $VM_Name
                Set-VMFirmware -ComputerName $VM_Host -VMName $VM_Name -BootOrder $VM_BootOrder_dvd,$VM_BootOrder_vhd,$VM_BootOrder_network
                $Msg = "Successfully"
                Write-Host $Msg -ForegroundColor Green
                $Tmp_Result_ISO = $Msg
                }Catch{
                $Msg = "Error: " + $Error[0].Exception.Message
                Write-Host $Msg -ForegroundColor Red
                $Tmp_Result_ISO = $Msg
            }

		}

		# Add DHCP Reservation to DHCP Server, for PVS
		IF($DHCP_PVS)
        {
            Write-Host -NoNewline " - Add DHCP Reservation to DHCP Server (PVS)..."
            IF((Get-DhcpServerv4Reservation -ComputerName $GL_DHCP_Server_PVS -ScopeId $GL_DHCP_Scope_PVS).Name -like "$VM_Name")
            {
                $Msg = "Exists"
                Write-Host $Msg -ForegroundColor Yellow
                $Tmp_Result_DHCP_Reservation = $Msg
            }
            Else
            {
                Try
                {
				    Add-DhcpServerv4Reservation -ComputerName $GL_DHCP_Server_PVS -Name $VM_Name -ScopeId $GL_DHCP_Scope_PVS -IPAddress $IP_Adresse_PVS -ClientId $MAC_PVS -Description 'Provisionierter Terminalserver' | Out-Null
                    $Msg = "Successfully"
                    Write-Host $Msg -ForegroundColor Green
                    $Tmp_Result_DHCP_Reservation = $Msg
                }
                Catch
                {
                    $Msg = "Error: " + $Error[0].Exception.Message
                    Write-Host $Msg -ForegroundColor Red
                    $Tmp_Result_DHCP_Reservation = $Msg
                }
            }
			
		}

		# Add DHCP Reservation to DHCP Server, for PROD
		IF($DHCP_PROD)
        {
            Write-Host -NoNewline " - Add DHCP Reservation to DHCP Server (PROD)..."
            IF((Get-DhcpServerv4Reservation -ComputerName $GL_DHCP_Server_SRV -ScopeId $GL_DHCP_Scope_SRV).Name -like $VM_Name)
            {
                $Msg = "Exists"
                Write-Host $Msg -ForegroundColor Yellow
                $Tmp_Result_DHCP_Reservation = $Msg
            }
            Else
            {
                Try
                {
				    Add-DhcpServerv4Reservation -ComputerName $GL_DHCP_Server_SRV -Name $VM_Name -ScopeId $GL_DHCP_Scope_SRV -IPAddress $IP_Adresse_SRV -ClientId $MAC_SRV -Description 'Provisionierter Terminalserver' | Out-Null
                    $Msg = "Successfully"
                    Write-Host $Msg -ForegroundColor Green
                    $Tmp_Result_DHCP_Reservation = $Msg
                }
                Catch
                {
                    $Msg = "Error: " + $Error[0].Exception.Message
                    Write-Host $Msg -ForegroundColor Red
                    $Tmp_Result_DHCP_Reservation = $Msg
                }
            }
			
		}

		# Add Device to PVS SiteName
		IF($PVS)
        {
			Write-Host -NoNewline " - Add Device to PVS SiteName..."
            Try
            {
		        Add-PVSDevice -Computername $GL_PVS_Server -DeviceName $VM_Name -DeviceMac $MAC_PVS -CollectionName $PVS_Collection -SiteName $GL_PVS_SiteName | Out-Null
                $Msg = "Please Check manuelly in PVS Console"
                Write-Host $Msg -ForegroundColor Yellow
                $Tmp_Result_PVS_SiteName = $Msg
            }
            Catch
            {
                $Msg = "Error: Please Check manuelly in PVS Console"
                Write-Host $Msg -ForegroundColor Red
                $Tmp_Result_PVS_SiteName = $Msg
            }
		}

        $Tmp_Result_Summary = @{
            "Create VM" = $Tmp_Result_VM
            "Set CPU, RAM, Settings" = $Tmp_Result_VM_Settings
            "Change Boot Order" = $Tmp_Result_BootOrder
            "Create Cache Disk" = $Tmp_Result_Create_CacheDisk
            "Add Cache Disk" = $Tmp_Result_Add_CacheDisk
            "Remove All Network Adapter" = $Tmp_Result_Remove_Default_Network_Adapter
            "Add PVS Network Adapter" = $Tmp_Result_Add_PVS_Network_Adapter
            "Add SRV Network Adapter" = $Tmp_Result_Add_PROD_Network_Adapter
            "Set MAC Adress" = $Tmp_Result_SET_MAC_Adress
            "Connect vSwitch to VM" = $Tmp_Result_Connect_vSwitch
            "Set Network Adapter VLANs" = $Tmp_Result_Add_VLANs_Network_Adapter
            "Add ISO to VM" = $Tmp_Result_ISO
            "Add DHCP Reservation to DHCP Server, for PVS Legacy" = $Tmp_Result_DHCP_Reservation
            "Add Device to PVS SiteName" = $Tmp_Result_PVS_SiteName
        }

        $Result.Add($VM_Name,$Tmp_Result_Summary)

	}

    $Path_Result = $scriptDirectory+"\"+(Get-Date -Format yyyy-MM-dd_HHmm)+"_Result.xml"

    #$Result | Export-Clixml -Path $Path_Result

#endregion
#-----------------------------------------------------------[End]----------------------------------------------------------------------------
#region

#endregion