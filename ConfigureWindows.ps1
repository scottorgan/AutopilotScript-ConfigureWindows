<#
.SYNOPSIS
    Remove select built-in Windows 11 apps and set the required registry entries to prevent unnecessary bloatware .

.DESCRIPTION
    This script customizes Windows 11's built in UWP Apps.  The list of apps to be removed are downloaded from  
    a .txt file hosted on GitHub, allowing the list to be updated without modifying the script.
    It also disables the Chat (Consumer Teams) app which requires modifying a (normally) Read Only registry key.

.NOTES

    "If you take from one author, it's plagiarism; if you take from many, it's research." -Wilson Mizner
    This script and the ideas behind it are all largely taken from the works of Nickolaj Anderson, Ben Whitmore and Mike Plichta.
#>

Begin {

    #Log Function
    function Write-LogEntry {
        param (
            [parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string]$Value,
            [parameter(Mandatory = $false)]
            [ValidateNotNullOrEmpty()]
            [string]$FileName = "AppXRemoval.log",
            [switch]$Stamp
        )
    
        #Build Log File appending System Date/Time to output
        Set-TimeZone -Id "Central Standard Time"
        $LogFile = Join-Path -Path $env:SystemRoot -ChildPath $("Logs\$FileName")
        $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), " ", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
        $Date = (Get-Date -Format "MM-dd-yyyy")
    
        If ($Stamp) {
            $LogText = "<$($Value)> <time=""$($Time)"" date=""$($Date)"">"
        }
        else {
            $LogText = "$($Value)"   
        }
        
        Try {
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFile -ErrorAction Stop
        }
        Catch [System.Exception] {
            Write-Warning -Message "Unable to add log entry to $LogFile.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }
    
    # Disable Chat (Consumer Teams) automatic (re)installation
    Function Disable-ChatAutoInstall {
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
        $Path = 'HKLM:\' + $subKey
        $Name = 'ConfigureChatAutoInstall'
        $Value = '0'
        If (-Not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWORD -Force | Out-Null
        Write-LogEntry -Value "Chat (Consumer Teams) auto install disabled."
    }
    
    #Function to Remove AppxProvisionedPackage
    Function Remove-AppxProvisionedPackageCustom {
    
        # Attempt to remove AppxProvisioningPackage
        if (!([string]::IsNullOrEmpty($BlackListedApp))) {
            try {
                
                # Get Package Name
                $AppProvisioningPackageName = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $BlackListedApp } | Select-Object -ExpandProperty PackageName -First 1
                Write-Host "$($BlackListedApp) found. Attempting removal ... " -NoNewline
                Write-LogEntry -Value "$($BlackListedApp) found. Attempting removal ... "
    
                # Attempt removeal
                $RemoveAppx = Remove-AppxProvisionedPackage -PackageName $AppProvisioningPackageName -Online -AllUsers
                    
                #Re-check existence
                $AppProvisioningPackageNameReCheck = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $BlackListedApp } | Select-Object -ExpandProperty PackageName -First 1
    
                If ([string]::IsNullOrEmpty($AppProvisioningPackageNameReCheck) -and ($RemoveAppx.Online -eq $true)) {
                    Write-Host @CheckIcon
                    Write-Host " (Removed)"
                    Write-LogEntry -Value "$($BlackListedApp) removed"
                }
            }
            catch [System.Exception] {
                Write-Host " (Failed)"
                Write-LogEntry -Value "Failed to remove $($BlackListedApp)"
            }
        }
    }

    Write-LogEntry -Value "##################################"
    Write-LogEntry -Stamp -Value "Remove-Appx Started"
    Write-LogEntry -Value "##################################"

    # Black List of Appx Provisioned Packages to Remove for All Users
    $BlackListedAppsURL = $null
    $BlackListedAppsURL = "https://raw.githubusercontent.com/scottorgan/AutoPilotScript/master/AppsToRemove.txt"
    Write-LogEntry -Value "BlackListedAppsURL:$($BlackListedAppsURL)"

    #Attempt to obtain list of BlackListedApps
    Try {
        $BlackListedAppsFile = $null
        $BlackListedAppsFile = (New-Object System.Net.WebClient).DownloadString($BlackListedAppsURL)
    } 
    Catch {
        # Could not retrieve online app list - Notify and use default list below
        Write-LogEntry -Value "Could not reach Github.  Using built-in app list!"
        Write-Warning $_.Exception
        $BlackListedAppsFile =
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
            Microsoft.WindowsTerminal
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

    #Read apps from file and split lines
    $BlackListedAppsConvertToArray = $BlackListedAppsFile -split "`n" | Foreach-Object { $_.trim() }
    
    #Create array of bad apps
    $BlackListedAppsArray = New-Object -TypeName System.Collections.ArrayList
    Foreach ($App in $BlackListedAppsConvertToArray) {
        $BlackListedAppsArray.AddRange(@($App))
    }

    #Define Icons
    $CheckIcon = @{
        Object          = [Char]8730
        ForegroundColor = 'Green'
        NoNewLine       = $true
    }

    #Define App Count
    [int]$AppCount = 0

    #OS Check
    $OS = (Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber
    Switch -Wildcard ( $OS ) {
        '21*' {
            $OSVer = "Windows 10"
            Write-Warning "This script is intended for use on Windows 11 devices. $($OSVer) was detected..."
            Write-LogEntry -Value "This script is intended for use on Windows 11 devices. $($OSVer) was detected..."

            Exit 1
        }
    }
}

Process {

    # First:  Prevent Chat from automatically reinstalling.
    Disable-ChatAutoInstall
    
    
    # Next:  Disable Chat Icon and other Windows Consumer Features
    $Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat'
    $Name = 'ChatIcon'
    $Value = '3'
    If (-Not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWORD -Force | Out-Null
    Write-LogEntry -Value "Chat taskbar icon disabled."

    $Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
    $Name = 'DisableWindowsConsumerFeatures'
    $Value = '1'
    If (-Not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWORD -Force | Out-Null
    Write-LogEntry -Value "Consumer Features disabled."
    
    #Then disable Hiberboot/Fast Startup
    $Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
    $Name = 'HiberbootEnabled'
    $Value = '0'
    If (-Not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWORD -Force | Out-Null
    Write-LogEntry -Value "Hiberboot/Fast Startup disabled."
    
    # Finally:  Remove desingated UWP Apps
    If ($($BlackListedAppsArray.Count) -ne 0) {

        Write-Output `n"The following $($BlackListedAppsArray.Count) apps were targeted for removal from the device:-"
        Write-LogEntry -Value "The following $($BlackListedAppsArray.Count) apps were targeted for removal from the device:-"
        Write-LogEntry -Value "Apps marked for removal:$($BlackListedAppsArray)"
        Write-Output ""
        $BlackListedAppsArray

        #Initialize list for apps not targeted
        $AppNotTargetedList = New-Object -TypeName System.Collections.ArrayList

        # Get Appx Provisioned Packages
        Write-Output `n"Gathering installed Appx Provisioned Packages..."
        Write-LogEntry -Value "Gathering installed Appx Provisioned Packages..."
        Write-Output ""
        $AppArray = Get-AppxProvisionedPackage -Online | Select-Object -ExpandProperty DisplayName

        # Loop through each Provisioned Package
        foreach ($BlackListedApp in $BlackListedAppsArray) {

            # Function call to Remove Appx Provisioned Packages defined in the Black List
            if (($BlackListedApp -in $AppArray)) {
                $AppCount ++
                Try {
                    Remove-AppxProvisionedPackageCustom -BlackListedApp $BlackListedApp -ErrorAction Stop
                }
                Catch {
                    Write-Warning `n"There was an error while attempting to remove $($BlakListedApp)"
                    Write-LogEntry -Value "There was an error when attempting to remove $($BlakListedApp)"
                }
            }
            else {
                $AppNotTargetedList.AddRange(@($BlackListedApp))
            }
        }

        #Update Output Information
        If (!([string]::IsNullOrEmpty($AppNotTargetedList))) { 
            Write-Output `n"The following apps were not removed. Either they were already removed or the Package Name is invalid:-"
            Write-LogEntry -Value "The following apps were not removed. Either they were already removed or the Package Name is invalid:-"
            Write-LogEntry -Value "$($AppNotTargetedList)"
            Write-Output ""
            $AppNotTargetedList
        }
        If ($AppCount -eq 0) {
            Write-Output `n"No apps were removed. Most likely reason is they had been removed previously."
            Write-LogEntry -Value "No apps were removed. Most likely reason is they had been removed previously."
        }
    }
    else {
        Write-Output "No Black List Apps defined in array"
        Write-LogEntry -Value "No Black List Apps defined in array"
    }
}
