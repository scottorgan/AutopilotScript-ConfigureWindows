<#
.SYNOPSIS
    Remove select built-in Windows 11 apps and sets the required registry entries to prevent unnecessary bloatware .
.DESCRIPTION
    This script removes specified built-in apps from Windows 11.  The list of apps to be removed is downloaded from  
    a .txt file hosted on GitHub, allowing it to be updated without modifying the actual script.

    It also prevents the Chat (Consumer Teams) app from being reinstalled, which requires modifying a (normally) Read-Only registry key.
.NOTES
    "If you take from one author, it's plagiarism; if you take from many, it's research." -Wilson Mizner
    This script and the ideas behind it are all largely taken from the works of Nickolaj Anderson, Ben Whitmore and Mike Plichta.
#>

$ScriptVersion = "1"
$BlockedAppsListUrl = "https://raw.githubusercontent.com/scottorgan/AutoPilotScript/master/AppsToRemove.txt"
$LogFileName = "AutopilotCustomConfig.log"

#region ---FUNCTIONS---
function Disable-ChatAutoInstall {
        # Get rights to the registry key that controls controls installation
        $rootKey = 'LocalMachine'
        $subKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Communications'
        [System.Security.Principal.SecurityIdentifier]$administratorsGroup = 'S-1-5-32-544'
        [System.Security.Principal.SecurityIdentifier]$trustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'

        $import = '[DllImport("ntdll.dll")] public static extern int RtlAdjustPrivilege(ulong a, bool b, bool c, ref bool d);'
        $ntdll = Add-Type -Member $import -Name NtDll -PassThru
        $privileges = @{ SeTakeOwnership = 9; SeBackup =  17; SeRestore = 18 }
        foreach ($i in $privileges.Values) {
            $null = $ntdll::RtlAdjustPrivilege($i, 1, 0, [ref]0)
        }

        $regKey = [Microsoft.Win32.Registry]::$rootKey.OpenSubKey($subKey, 'ReadWriteSubTree', 'TakeOwnership')
        $acl = New-Object System.Security.AccessControl.RegistrySecurity
        # take ownership of the key, so that we can modify rights
        $acl.SetOwner($administratorsGroup)
        $regKey.SetAccessControl($acl)
        # change the rights
        $acl.SetAccessRuleProtection($false, $false)
        $regKey.SetAccessControl($acl)
        # return ownership back to TrustedInstaller
        $acl.SetOwner($trustedInstaller)
        $regKey.SetAccessControl($acl)

        # Finally we can set the key value
        $Name = 'ConfigureChatAutoInstall'
        $Path = 'HKLM:\' + $subKey
        $Value = '0'
        If (-Not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWORD -Force | Out-Null
        Write-LogEntry -Value "Chat (Consumer Teams) auto install disabled." -Severity 1
    }
    
    function New-RegistryValue {
        param(
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$Name,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$Path,

            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$Value
        )

        If (-Not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWORD -Force | Out-Null
        Write-LogEntry -Value "$Path\$Name set to: $Value" -Severity 1
    }

    function Remove-PreInstalledApps {
        try {
            $BlockedAppsList = (New-Object System.Net.WebClient).DownloadString($BlockedAppsListUrl)
        } catch {
            # Could not retrieve the online list - Notify and use hard-coded list below
            Write-LogEntry -Value "Could not retreive online Blocked App List - Using built in list!" -Severity 2
            $BlockedAppsList =    
            "Clipchamp.Clipchamp
                Microsoft.549981C3F5F10
                Microsoft.GamingApp
                Microsoft.GetHelp
                Microsoft.Getstarted
                Microsoft.MicrosoftOfficeHub
                Microsoft.MicrosoftSolitaireCollection
                Microsoft.People
                Microsoft.PowerAutomateDesktop
                Microsoft.Todos
                Microsoft.WindowsCommunicationsApps
                Microsoft.WindowsFeedbackHub
                Microsoft.WindowsMaps
                Microsoft.Xbox.TCUI
                Microsoft.XboxGameOverlay
                Microsoft.XboxGamingOverlay
                Microsoft.XboxIdentityProvider
                Microsoft.XboxSpeechToTextOverlay
                Microsoft.YourPhone
                Microsoft.ZuneMusic
                Microsoft.ZuneVideo
                MicrosoftTeams"
        }

        $SplitBlockedAppsList = $BlockedAppsList -split "`n" | Foreach-Object { $_.trim() }

        $BlockedAppsListArray = New-Object -TypeName System.Collections.ArrayList
        foreach ($app in $SplitBlockedAppsList) {
            $BlockedAppsListArray.AddRange(@($app))
        }

        if ($($BlockedAppsListArray.Count) -ne 0) {
            Write-LogEntry -Value "Apps marked for removal: $($BlockedAppsListArray)" -Severity 1

            $AppsNotFound = New-Object -TypeName System.Collections.ArrayList
            $InstalledApps = Get-AppxProvisionedPackage -Online | Select-Object -ExpandProperty DisplayName

            foreach ($app in $BlockedAppsListArray) {
                if ($app -in $InstalledApps) {
                    try {
                        $AppxProvisioningPackageName = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $app } | Select-Object -ExpandProperty PackageName -First 1
                        Write-LogEntry -Value "$($app) found.  Attemping removal..." -Severity 1

                        $RemoveAppx = Remove-AppxProvisionedPackage -PackageName $AppxProvisioningPackageName -Online -AllUsers

                        $AppxProvisioningPackageNameReCheck = Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like $app} | Select-Object -ExpandProperty PackageName -First 1

                        if ([string]::IsNullOrEmpty($AppxProvisioningPackageNameReCheck) -and ($RemoveAppx.Online -eq $true)) {
                            Write-LogEntry -Value "$($app) removed." -Severity 1
                        }
                    } catch {
                        Write-LogEntry -Value "Error attempting to remove $($AppToRemove)" -Severity 2
                    }
                } else {
                    $AppsNotFound.AddRange(@($app))
                }
            }

            if (!([string]::IsNullOrEmpty($AppsNotFound))) {
                Write-LogEntry -Value "The following apps were not removed.  Either they were already removed or the Package Name is invalid:" -Severity 2
                Write-LogEntry -Value "$($AppsNotFound)" -Severity 2
            }
        } else {
            Write-LogEntry -Value "Blocked Apps list could not be processed." -Severity 2
        }
    }

    function Write-LogEntry {
        param (
            [parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
            [ValidateNotNullOrEmpty()]
            [string]$Value,
            [parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
            [ValidateNotNullOrEmpty()]
            [ValidateSet("1", "2", "3")]
            [string]$Severity,
            [parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")]
            [ValidateNotNullOrEmpty()]
            [string]$FileName = $LogFileName
        )
        # Determine log file location
        $LogFilePath = Join-Path -Path $env:SystemRoot -ChildPath $("Temp\$FileName")
        
        # Construct time stamp for log entry
        $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), " ", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
        
        # Construct date for log entry
        $Date = (Get-Date -Format "MM-dd-yyyy")
        
        # Construct context for log entry
        $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        
        # Construct final log entry
        $LogText = "[ $($Value) ] <time=""$($Time)"" date=""$($Date)"" component=""$($LogFileName)"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
        
        # Add value to log file
        try {
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
            if ($Severity -eq 1) {
                Write-Verbose -Message $Value
            }
            elseif ($Severity -eq 3) {
                Write-Warning -Message $Value
            }
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry to $LogFileName.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }
#endregion ---FUNCTIONS---

#region ---INITIALIZE---

    Write-LogEntry -Value "Initiating Autopilot custom config." -Severity 1

    #Check to see if current version of script has already been applied
    try {
        $AppliedVersion = (Get-ItemProperty -Path HKLM:\SOFTWARE\Custom -Name "ApConfigVersion" -ErrorAction Stop).ApConfigVersion
        if ($AppliedVersion -ge $ScriptVersion) {
            Write-LogEntry -Value "This script version has already been applied! - Exiting." -Severity 2
            Return $False | Out-Null
        }
    } catch {
        New-Item -Path HKLM:\SOFTWARE -Name "Custom" -Force | Out-Null
        New-ItemProperty -Path HKLM:\SOFTWARE\Custom\ -Name "ApConfigVersion" -Value "0" -PropertyType DWORD -Force | Out-Null
    }
#endregion ---INITIALIZE---

#region **** MAIN ****

    # Prevent Chat from automatically reinstalling
    Disable-ChatAutoInstall
    # Disable Chat icon on taskbar
    New-RegistryValue -Name "ChatIcon" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" -Value "3"
    # Disable Windows Consumer Features
    New-RegistryValue -Name "DisableWindowsConsumerFeatures" -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Value "1"
    # Disable Widgets
    New-RegistryValue -Name "TaskbarDa" -Path ""
    # Disable Hiberboot/Fast Startup
    New-RegistryValue -Name "HiberbootEnabled" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Value "0"
    # Remove all Pre-Installed Apps listed in the online $BlockedAppListUrl file
    Remove-PreInstalledApps

#endregion **** MAIN ****

#region ---END---
    New-ItemProperty -Path HKLM:\SOFTWARE\Custom\ -Name "ApConfigVersion" -Value $ScriptVersion -PropertyType DWORD -Force | Out-Null
    Write-LogEntry -Value "Sucessfully completed custom configuration." -Severity 1
#endregion ---END---
