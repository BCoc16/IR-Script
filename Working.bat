@ECHO off
TITLE Basic Analysis Run.

REM - Set LINE 29
rem  REQUIREMENTS: need a \\server\share\utilities folder and 'L:' for map drive
rem					need admin to run on target system and also modify on L: drive location

REM -  To Run Local : Admin CMD> "C:\Analysis\Working.bat"
REM -  To Run Remote: C:\Analysis\PsExec64.exe \\computername -u domain\<username> -w c:\temp -f -e -h -c "C:\Analysis\Working.bat"
REM							Note:  You can add the -d switch - exits psexec but process still runs on remote system

ECHO  Set Network Share to L Drive
rem  Where do you want the output to go?  Set LINE 14
net use L: \\Server\Share

If EXIST L:\SystemOutput\%computername%\ (REN "L:\SystemOutput\%computername%" "%computername%__RENAMED_%date:/=_%-%time::=_%")
If NOT EXIST L:\SystemOutput\%computername%\ (mkdir L:\SystemOutput\%computername%\)

If EXIST C:\%computername%\ (RMDIR /S /Q C:\%computername%\)
If NOT EXIST C:\%computername%\ (mkdir C:\%computername%\)

REM -  Mark your output directory
mkdir "c:\%computername%\Utilities"
robocopy L:\Utilities\ C:\%computername%\Utilities\ /MT:32 /V /LOG:L:\SystemOutput\%computername%\zROBO-%computername%.log /NJH /NJS

rem  Get CMD history
rem doskey /history > "C:\%computername%\%computername%_doskey.txt"
ECHO +
ECHO   Running UTILITIES files:  lastactivityview, browsehistoryview, autoruns, rammap...
ECHO +
ECHO   To VirusTotal.com for hash Check. ~5-10+ extra minutes...  --  Did you SET before running?
rem  			Virustotal.com check (-m removes Microsoft Entries)
"C:\%computername%\Utilities\autorunsc64.exe" /accepteula -a * -m -u -v -vt -c > "C:\%computername%\%computername%_autoruns_VT.csv"
rem      run autoruns without the virus total lookup.
"C:\%computername%\Utilities\autorunsc64.exe" /accepteula -a * -c > "C:\%computername%\%computername%_autoruns.csv"
"C:\%computername%\Utilities\BrowsingHistoryView.exe" /scomma "c:\%computername%\%computername%_browse.csv"
"C:\%computername%\Utilities\LastActivityView.exe" /scomma "C:\%computername%\%computername%_last.csv"
"C:\%computername%\Utilities\USBDeview.exe" /shtml "C:\%computername%\%computername%_USBdevices.html" /sort ~connected /sort "Device Type" /sort Description /DisplayDisconnected 1
"C:\%computername%\Utilities\PsInfo64.exe" /accepteula -h -s -d -nobanner > "C:\%computername%\%computername%_PsInfo.txt"
"C:\%computername%\Utilities\RAMMap.exe" /accepteula "C:\%computername%\%computername%_RAMMAP.rmp"
"C:\%computername%\Utilities\psloggedon64.exe" /accepteula \\%computername% -nobanner > "C:\%computername%\%computername%_LoggedOnUser.txt"
echo T or U, Service, PID, STATE, Local, REMOTE > "C:\%computername%\%computername%_TCP_EndPointViewer.csv"
echo + >> "C:\%computername%\%computername%_TCP_EndPointViewer.csv"
"C:\%computername%\Utilities\tcpvcon.exe" /accepteula -a -c >> "C:\%computername%\%computername%_TCP_EndPointViewer.csv"
REM   run live??? https://live.sysinternals.com/procexp64.exe
ECHO +
ECHO   Get tasklist output
tasklist /SVC > "C:\%computername%\%computername%_tasklist.txt"
tasklist /V /FO csv > "C:\%computername%\%computername%_tasklist_output.csv"
tasklist /M /FO csv > "C:\%computername%\%computername%_tasklist_Module.csv"
tasklist /APPS /V /FO csv > "C:\%computername%\%computername%_tasklist_APPS.csv"
ECHO +
ECHO   What is SET to run at STARTUP - output running...
wmic /namespace:\\root\CIMV2\ path Win32_StartupCommand get caption,command,description,location,name > "C:\%computername%\%computername%-StartupRUN.txt"
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" > "C:\%computername%\%computername%-OS_Version.txt"
ECHO +
ECHO   Get Event Logs -    Did you SET before running?
rem wevtutil epl Security "C:\%computername%\%computername%_Security.evtx"
rem wevtutil epl System "C:\%computername%\%computername%_System.evtx"
rem wevtutil epl Application "C:\%computername%\%computername%_Application.evtx"
rem wevtutil epl Microsoft-Windows-PowerShell/Operational "C:\%computername%\%computername%_Powershell.evtx"
ECHO +
ECHO   GET Scheduled Tasks
schtasks /query /fo list /v > "C:\%computername%\%computername%-SchdTasks.txt"
schtasks /query /fo csv /v > "C:\%computername%\%computername%-schdTasks.csv"
ECHO +
ECHO   Get Network Stats, route, hosts file...
ipconfig /allcompartments /all > "C:\%computername%\%computername%-IPconfig.txt"
ipconfig /displaydns > "C:\%computername%\%computername%-IPconfig_DisplayDNS.txt"
arp -a > "C:\%computername%\%computername%-ARP.txt"
copy C:\Windows\System32\drivers\etc\hosts "C:\%computername%\%computername%_hosts"
netstat -naob > "C:\%computername%\%computername%-NetStat-naob.txt"
netstat -nr > "C:\%computername%\%computername%-NetStat-nr.txt"
netstat -vb > "C:\%computername%\%computername%-NetStat-vb.txt"
net use > "C:\%computername%\%computername%-NetUse.txt"
net session > "C:\%computername%\%computername%-NetSessions.txt"
net view \\127.0.0.1 > "C:\%computername%\%computername%-NetView.txt"
route print > "C:\%computername%\%computername%-RoutePrint.txt"
netsh wlan show all > "C:\%computername%\%computername%-WLAN.txt"
ECHO +
ECHO   Getting Installed Software List...
wmic /namespace:\\root\CIMV2\ path Win32_Product get name,caption,description,installdate,installlocation > "C:\%computername%\%computername%-SoftInstalled.txt"
ECHO +
ECHO   Getting Local System Accounts...
wmic /namespace:\\root\CIMV2\ path Win32_SystemAccount > "C:\%computername%\%computername%-SystemAccts.txt"
ECHO +
ECHO   Getting service and process list (memory)
net start > "C:\%computername%\%computername%-NetStart.csv"
wmic service list config > "C:\%computername%\%computername%-ServiceList.csv"
wmic process list memory > "C:\%computername%\%computername%-MemoryList.csv"

ECHO +
ECHO   Getting Shares on system...
wmic /namespace:\\root\CIMV2\ path Win32_Share > "C:\%computername%\%computername%-Shares.csv"

ECHO +
ECHO   List users in Local Admin
net localgroup administrators > "C:\%computername%\%computername%-GroupLocalAdmins.txt"

rem  DO NOT RUN THIS wmic ONE.  Get users in Local Remote Desktop Users
rem wmic /namespace:\\root\CIMV2\ path win32_groupuser where (groupcomponent="win32_group.name=\"Remote Desktop Users\",domain=\"%computername%\"") > "C:\%computername%\%computername%-GroupRemoteDesktop_Members.csv"
ECHO +
ECHO   Getting Remote Desktop Users with NetLocalGroup
net localgroup "Remote Desktop Users" > "C:\%computername%\%computername%-GroupLocalRemoteDU.txt"
ECHO +
ECHO   Getting Scheduled Jobs...
REM  Get scheduled jobs
wmic /namespace:\\root\CIMV2\ path Win32_ScheduledJob > "C:\%computername%\%computername%-ScheduledJobs.csv"
ECHO +
ECHO   Getting additional network details...
REM  Additional network details.
wmic /namespace:\\root\CIMV2\ path Win32_NetworkAdapterConfiguration get DefaultIPGateway,DHCPEnabled,DHCPServer,DNSServerSearchOrder,IPAddress,IPSubnet,TcpWindowSize,caption > "C:\%computername%\%computername%-NetworkAdapterConfig.csv"
ECHO +
ECHO   Find .exe files newer than specific date  -- Did you SET before running?
rem forfiles /p C:\ /M *.exe /S /D +4/13/2020 /C "cmd /c echo @fdate @ftime @path" > "C:\%computername%\%computername%-New_EXE.csv"
ECHO +

REM Copy all output from Local IR %computername% location to share IR location
RMDIR /S /Q C:\%computername%\Utilities
robocopy.exe c:\%computername% L:\SystemOutput\%computername% /E /MOVE /MT:32 /DCOPY:D /V /LOG:L:\SystemOutput\%computername%\ROBO-%computername%.log /NJH /NJS
net use L: /delete
ECHO +
ECHO   UPDATE MCAFEE  ******  Enable for Windows 10 - Update Quietly  *******
REM "C:\Program Files\McAfee\Endpoint Security\Threat Prevention\amcfg.exe" /update /quiet
ECHO +
REM  Run Windows Defender Update and Scan
ECHO   Defender Scan Starting...  --  Did you SET before running?
rem "%ProgramFiles%\Windows Defender\MpCmdRun.exe" -signatureupdate
rem "%ProgramFiles%\Windows Defender\MpCmdRun.exe" -scan -1 -Timeout 1
ECHO +
REM   DO NOT USE THIS COMMAND - Gets groups - (also gets domain groups)  can be a big list :(  USE WITH CAUTION  )
rem wmic /namespace:\\root\CIMV2\ path Win32_Group get caption,domain,localaccount,name,sid,status > "C:\%computername%\%computername%-Groups.csv"

rem  DO NOT RUN THIS wmic ONE.  RUNS FOREVER.  Get accounts on system - ALL
rem wmic /namespace:\\root\CIMV2\ path Win32_UserAccount get AccountType,Caption,Description,Disabled,Fullname,InstallDate,LocalAccount,Lockout,name,PasswordChangeable,PasswordExpires,PasswordRequired,Status > "C:\%computername%\%computername%-UserAccounts.csv"

rem  DO NOT RUN THIS wmic ONE.  RUNS FOREVER.
rem wmic /namespace:\\root\CIMV2\ path win32_groupuser where (groupcomponent="win32_group.name=\"administrators\",domain=\"%computername%\"") > "C:\%computername%\%computername%-GroupAdmin_Members.csv"

REM  DO NOT RUN THIS.  Network Adapters - Not very usefull!!!
rem wmic /namespace:\\root\CIMV2\ path Win32_NetworkAdapter get caption,description,deviceid,macaddress,networkaddresses,PermanentAddress,netenabled > "C:\%computername%\%computername%-NetAdapters.csv"

REM   DO NOT RUN THIS.   Can Verify if password is set  - Not very usefull!!!
rem wmic /namespace:\\root\CIMV2\ path Win32_ComputerSystem get adminpasswordstatus,currenttimezone,name,poweronpasswordstatus,lastloadinfo > "C:\%computername%\%computername%-ComputerSystem.csv"

rem
Exit