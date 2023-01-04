# Customize Windows 11 during AutoPilot
#### Powershell script used to remove unwanted UWP Apps and configure select settings.

This script customizes Windows 11's built in UWP Apps.  The list of apps to be removed is downloaded from  
a .txt file hosted on GitHub, allowing the list to be updated without modifying the actual script.  In the
event that it fails to get the list from the GitHub repository, it falls back to a predefined list of apps
contained within the script itself.

It also disables the Chat (Consumer Teams) app which requires modifying a (normally) Read Only registry key.


"If you take from one author, it's plagiarism; if you take from many, it's research." -Wilson Mizner
This script and the ideas behind it are all largely taken from the works of Nickolaj Anderson, Ben Whitmore and Mike Plichta.
