#Run PowerShell in x64 context
If ($ENV:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    Try {
        &"$ENV:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -File $PSCOMMANDPATH
    }
    Catch {
        Throw "Failed to start $PSCOMMANDPATH"
    }
    Exit
}

Function CleanUpAndExit() {
    Param(
        [Parameter(Mandatory=$True)][String]$ErrorLevel
    )

    # Write results to registry for Detection
    $Key = "HKEY_LOCAL_MACHINE\Software\Mountainburg\AutoPilot\Configured"
    $NOW = Get-Date -Format "MM/dd/yyyy HH:mm"

    If ($ErrorLevel -eq "0") {
        [microsoft.win32.registry]::SetValue($Key, "Success", $NOW)
    } else {
        [microsoft.win32.registry]::SetValue($Key, "Failure", $NOW)
        [microsoft.win32.registry]::SetValue($Key, "Error Code", $Errorlevel)
    }
    
    # Exit Script with the specified ErrorLevel
    EXIT $ErrorLevel
}

Function Remove-UwpApps {
    
    $AppsList = "Microsoft.DesktopAppInstaller",
            "Microsoft.Messaging",
            "Microsoft.Microsoft3DViewer",
            "Microsoft.MicrosoftOfficeHub",
            "Microsoft.MicrosoftSolitaireCollection",
            "Microsoft.OneConnect",
            "Microsoft.Print3D",
            "Microsoft.SkypeApp",
            "Microsoft.Wallet",
            "Microsoft.Xbox.TCUI",
            "Microsoft.XboxApp",
            "Microsoft.XboxGameOverlay",
            "Microsoft.XboxIdentityProvider",
            "Microsoft.XboxSpeechToTextOverlay",
            "Microsoft.ZuneMusic",
            "Microsoft.ZuneVideo"

    ForEach ($App in $AppsList) {
        $PackageFullName = (Get-AppxPackage $App).PackageFullName
        $ProPackageFullName = (Get-AppxProvisionedPackage -Online | Where {$_.Displayname -eq $App}).PackageName
 
        If ($PackageFullName) {
            Remove-AppxPackage -Package $PackageFullName
        }
 
        If ($ProPackageFullName) {
            Remove-AppxProvisionedPackage -Online -PackageName $ProPackageFullName
        }
    }
}

$Error.Clear()

# Remove the unwanted Windows 10 Apps
Remove-UwpApps

# Configure the default Windows 10 Start Menu and Taskbar
Import-StartLayout -LayoutPath "$PSScriptRoot\StartMenuAndTaskbar.xml" -MountPath $env:SystemDrive\

If ($Error.Count -gt 0) {
    CleanUpAndExit -ErrorLevel 101
}

CleanUpAndExit -ErrorLevel 0