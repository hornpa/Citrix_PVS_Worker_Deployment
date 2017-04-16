#Requires -Version 3.0
#Requires -RunAsAdministrator

<#
.SYNOPSIS
Citrix Worker Deployment Hyper-V Gen1 - MTD
    .Description
    Fügt einem Worker eine System HDD hinzu und stellt die Boot Reihenfolge um.
.NOTES
    Author: 
    Patrik Horn (PHo)
    Link:	
    www.hornpa.de
    History:
    2017-02-10 - v0.01 - Script created (PHo)
#>

Param (

    [Parameter(Mandatory=$false,Position=1)]
    [string]$Path

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
	IF([string]::IsNullOrEmpty($Path)) {            
		Write-Verbose "Select XML file..."
		$Path = (Get-ChildItem -Path $scriptDirectory -Filter "*.xml" | Out-GridView -Title "Bitte eine Datei auswählen" -PassThru).FullName
    }

	Write-Verbose "Checking for Server OS"
	Switch ($OS.ProductType){
		3 {
			Write-Verbose "Server OS detected, contiune"
		} 
		Default {
			Write-Host "Skript unterstützt nur Server OS, Skript wird abgebrochen!"  -ForegroundColor Red
			Exit
		}
	}

	Write-Verbose "Checking Windows Feautre RSAT-Hyper-V-Tools"
	If (!(Get-WindowsFeature RSAT-Hyper-V-Tools).Installed) {
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
	$GL_NIC_Name_PVS_Legacy = $xmlfile.Deployment_VM.Global.NIC_Name_PVS_Legacy
	$GL_NIC_Name_PVS = $xmlfile.Deployment_VM.Global.NIC_Name_PVS
	$GL_NIC_Name_SRV = $xmlfile.Deployment_VM.Global.NIC_Name_SRV
	$GL_Switch_Name_PVS = $xmlfile.Deployment_VM.Global.Switch_Name_PVS
	$GL_Switch_Name_SRV = $xmlfile.Deployment_VM.Global.Switch_Name_SRV
	$GL_Switch_VLAN_PVS = $xmlfile.Deployment_VM.Global.Switch_VLAN_PVS
	$GL_Switch_VLAN_SRV = $xmlfile.Deployment_VM.Global.Switch_VLAN_SRV
	$GL_DHCP_Server_SRV = $xmlfile.Deployment_VM.Global.DHCP_Server_SRV
	$GL_DHCP_Scope_SRV = $xmlfile.Deployment_VM.Global.DHCP_Scope_SRV
	$GL_DHCP_Server_PVS = $xmlfile.Deployment_VM.Global.DHCP_Server_PVS
	$GL_DHCP_Scope_PVS = $xmlfile.Deployment_VM.Global.DHCP_Scope_PVS
	$GL_PVS_Server = $xmlfile.Deployment_VM.Global.PVS_Server
	$GL_PVS_SiteName = $xmlfile.Deployment_VM.Global.PVS_Sitename
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
		$VM_Path = $VM.VM_Path
        $GL_SystemDisk_Name = $VM_Name + "_" + $xmlfile.Deployment_VM.Global.SystemDisk_Name + "HDD0"

		Write-Host -NoNewline "Running: " 
		Write-Host $VM_Name

        # Checking if VM already exists
        IF(!((Get-VM -ComputerName $VM_Host).Name -like "$VM_Name"))
        {
            $Msg = "Doesen't Exists, exit"
            Write-Host $Msg -ForegroundColor Yellow
            $Tmp_Result_VM = $Msg
            Continue
        }

		# Create System Disk
		Write-Host -NoNewline " - Create System Disk..."
        Try
        {
            Invoke-Command -ComputerName $VM_Host -ScriptBlock {New-VHD -Path "$using:VM_Path\$using:VM_Name\Virtual Hard Disks\$using:GL_SystemDisk_Name.vhdx" -SizeBytes $using:GL_SystemDiske_Size -Dynamic | Out-Null } -Authentication Default
            $Msg = "Successfully"
            Write-Host $Msg -ForegroundColor Green
            $Tmp_Result_Create_SystemDisk = $Msg
        
        }
        Catch
        {
            $Msg = "Error: " + $Error[0].Exception.Message
            Write-Host $Msg -ForegroundColor Red
            $Tmp_Result_Create_SystemDisk = $Msg
        }

        # Add System Disk
		Write-Host -NoNewline " - Add System Disk to VM..."
        Try
        {
            Add-VMHardDiskDrive -ComputerName $VM_Host -VMName $VM_Name -ControllerType IDE -ControllerNumber 0 -ControllerLocation 0 -Path "$VM_Path\$VM_Name\Virtual Hard Disks\$GL_SystemDisk_Name.vhdx"  | Out-Null
            $Msg = "Successfully"
            Write-Host $Msg -ForegroundColor Green
            $Tmp_Result_Add_SystemDisk = $Msg
        }
        Catch
        {
            $Msg = "Error: " + $Error[0].Exception.Message
            Write-Host $Msg -ForegroundColor Red
            $Tmp_Result_Add_SystemDisk = $Msg
        }
		
		# Add DVD Drive
		Write-Host -NoNewline " - Add DVD Drive to VM..."
        Try
        {
			Add-VMDvdDrive -ComputerName $VM_Host -VMName $VM_Name -ControllerNumber 1 -ControllerLocation 0 | Out-Null
            $Msg = "Successfully"
            Write-Host $Msg -ForegroundColor Green
            $Tmp_Result_Add_DVDDrive = $Msg
        }
        Catch
        {
            $Msg = "Error: " + $Error[0].Exception.Message
            Write-Host $Msg -ForegroundColor Red
            $Tmp_Result_Add_DVDDrive = $Msg
        }

        # Change Boot Order
		Write-Host -NoNewline " - Change Boot Order to PXE(PROD), System..."
        Try
        {
		    Get-VM -ComputerName $VM_Host -Name $VM_Name | Set-VMBios -StartupOrder @("LegacyNetworkAdapter","CD", "IDE", "Floppy")
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

        # Change Network vSwitch for Legacy Adapter
		Write-Host -NoNewline " - Change Network Legacy from PVS to PROD..."
        Try
        {
            Connect-VMNetworkAdapter -ComputerName $VM_Host -VMName $VM_Name -Name $GL_NIC_Name_PVS_Legacy -SwitchName $GL_Switch_Name_SRV | Out-Null
            Set-VMNetworkAdapterVlan -ComputerName $VM_Host -VMName $VM_Name -VMNetworkAdapterName $GL_NIC_Name_PVS_Legacy -VlanId $GL_Switch_VLAN_SRV -Access -ErrorAction SilentlyContinue| Out-Null
            $Msg = "Successfully"
            Write-Host $Msg -ForegroundColor Green
            $Tmp_Result_Network = $Msg
        }
        Catch
        {
            $Msg = "Error: " + $Error[0].Exception.Message
            Write-Host $Msg -ForegroundColor Red
            $Tmp_Result_Network = $Msg
        }

        $Tmp_Result_Summary = @{
            "Create System Disk" = $Tmp_Result_Create_SystemDisk
            "Add System Disk" = $Tmp_Result_Add_SystemDisk
			"Add DVD Drive" = $Tmp_Result_Add_DVDDrive
            "Change Boot Order" = $Tmp_Result_BootOrder
            "Change Network Legacy from PVS to PROD" = $Tmp_Result_Network
        }

        $Result.Add($VM_Name,$Tmp_Result_Summary)

    }

#endregion
#-----------------------------------------------------------[End]----------------------------------------------------------------------------
#region

#endregion