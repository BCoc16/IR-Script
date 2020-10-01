# IR-Script
Compilation of commands entered into a script for Information Gathering on system that may be infected.
_______________________________________________

Examine the local system for a quick analysis.  Sometimes you may get an alert or need to investigate something and want to pull some local system information.
This script can pull services, local users, network configuration and other items.

To enable or disable a line, edit the file and add/remove rem.

This script call other programs such as
-- some nirsoft tools
-- some sysinternals tools
These are prerequisites.

_______________________________________________

Run local or remote with psexec.  (Download PSExec from Microsoft and place in C:\PsTools\ or modify as desired)

_______________________________________________

Some adjustments do need to be made in the file.

1.  Create a C:\Analysis folder

2.  Download files and extact to it C:\Analysis

3.  Edit 'Working.bat'
    --REQUIREMENTS:   SET LINE 29 of 'Working.bat'
    -- Need a \\server\share\ and 
	          a sub folder called Utilities
	          a sub folder called SystemOutput
ie.  \\Server\Share\
		                 Utilities  (location for all tools)
		                 SystemOutput  (location where all output files will be copied to.  Self creates a folder the same as the computer name)
                     
    -- Drive 'L:' for map drive - auto created and destroyed on target computer  (L: Drive is a \\Server\Share location)
    -- Need admin permissions to run on target system and also modify on L: drive location
    
4.  Place all these files in \\Server\Share\Utilities
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
     
5.  Edit 'Computers.txt' with your computernames
6.  Edit 'LaunchAnalysis.bat' and adjust with your <domain\username>
7.  Run from elevated command prompt:  'C:\Analysis\LaunchAnalysis.bat'


NOT COMPLETED:  Check Back in a few Weeks.
