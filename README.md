# IR-Script       :+1:
### Compilation of commands entered into a script for Information Gathering on system that may be infected.
##

#### Examine the local system for a quick analysis.  Sometimes you may get an alert or need to investigate something and want to pull some local system information.
#### This script can pull services, local users, network configuration and other items.

#### To enable or disable a line, edit the file and add/remove REM.

#### Output goes to the SHARE location you setup.
####   Account used to run needs to be a Local Administrator and needs MODIFY on the share location.

#### This script calls other programs such as (These are prerequisites if you wish to enable):
```
- some nirsoft tools
- some sysinternals tools
```

## 


**Run local or remote with psexec.**  (Download PSExec from Microsoft and place in C:\Analysis\ or modify as desired)

## 

***DATA the Script will Gather - Commands to Enable/Disable (edit the file and add/remove REM)***
```
	Autoruns VirusTotal lookup
	Autoruns
	Browsing History
	Last Activity View
	USB Device View
	PS Info
	RAM Map collection
	PS Logged On
	TCP End Point Viewer
	TCP Converstion
	Task List (Several different switches)
	WMIC to capture startup
	System Info output
	Event log export (Security, System, Applicatrion, Powershell)
	Scheduled Task output
	IpConfig
	Arp output
	Hosts file copy to verify if changed
	Netstat (Several different switches)
	Route Print
	NetSH WLAN
	WMIC Get Installed software
	WMIC Get local system accounts
	WMIC Get Services and Process List
	WMIC Shares
	Admin Group list
	Remote Desktop User List
	Scheduled Jobs
	Find Files (Adjustment/Tuning needed)
	Update McAfee
	Update Windows Defender
```	

## Some adjustments do need to be made in the file.

1.  Create a C:\Analysis\ folder

2.  Download files and extact to it C:\Analysis\

3.  Edit 'Working.bat'
```
    --REQUIREMENTS:   **SET LINE 14 of 'Working.bat'**
    -- Need a \\server\share\ and 
	          a sub folder called Utilities
	          a sub folder called SystemOutput
ie.  \\Server\Share\
		                 Utilities  (location for all tools)
		                 SystemOutput  (location where all output files will be copied to.  Self creates a folder the same as the computer name)
                     
    -- Drive 'L:' for map drive - auto created and destroyed on target computer  (L: Drive is a \\Server\Share location)
    
    -- Need admin permissions to run on target system and also modify on L: drive location
```    
4.  **Place all these files in \\Server\Share\Utilities**
```
(Google for download locations)
From SysInternals:
	autorunsc64.exe
	PsInfo64.exe
	RAMMap.exe
	PSLoggedon64.exe
	tcpvcon.exe

From Nirsoft:
	BrowsingHistoryView.exe
	LastActivityView.exe
	USBDeView.exe
```
     
5.  Edit 'Computers.txt' with your computernames
7.  Run from **elevated** command prompt:  
  Local run: 'C:\Analysis\LaunchAnalysis.bat'
  Remote run: 
    C:\Analysis\PsExec64.exe \\computername -u domain\<username> -w c:\temp -f -e -h -c "C:\Analysis\Working.bat"
or with list of computers in file.
    C:\Analysis\PsExec64.exe @c:\analysis\computers.txt -u domain\<username> -w c:\temp -f -e -h -c "C:\Analysis\Working.bat"

![Sample](https://github.com/BCoc16/IR-Script/blob/master/Working1.png)

