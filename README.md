# Customize Windows 10 during AutoPilot
#### Powershell script used to remove unwanted UWP Apps and set the default layout of the Start Menu and Taskbar.

*This is mainly here for my own reference, but if somone else stumbles across it, watch out for my district name in the custom registry entry.*

 Deployed during AutoPilot as a Win32 app using the Microsoft Content Prep Tool available at: https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool

#### When adding to Intune:
**Install command:** PowerShell.exe -NoProfile -ExecutionPolicy Bypass -file .\ConfigureWindows.ps1
**Uninstall command:** (Same as above)
**Manually configure detection rules**
**Rule type:** Registry
**Key Path:** HKEY_LOCAL_MACHINE\Software\Mountainburg\AutoPilot\Configured
**Value Name:** Success
**Detection Method:** Value exists

**Update Enrollment Status Page to include script as a required app!**