# thanks to
# https://github.com/cluberti/VDI/blob/master/ConfigAsVDI.ps1

## basic
$script_name = $MyInvocation.MyCommand.Name;
$script_path = $PSScriptRoot;
$log_path    = "$($script_path)\$($script_name).log";
$lines = Get-Item -Path "$($script_path)\$($script_name).ps1" | Get-Content -Tail 1

#
#1 Changing firewall rules
$netrulenames = [string[]](
"SNMPTRAP-In-UDP",
"EventForwarder-In-TCP",
"EventForwarder-RPCSS-In-TCP",
"RemoteFwAdmin-In-TCP-NoScope",
"RemoteFwAdmin-In-TCP",
"WMI-RPCSS-In-TCP-NoScope",
"WMI-WINMGMT-In-TCP-NoScope",
"WMI-ASYNC-In-TCP-NoScope",
"FPS-NB_Session-In-TCP-NoScope",
"FPS-SMB-In-TCP-NoScope",
"FPS-NB_Name-In-UDP-NoScope",
"FPS-NB_Datagram-In-UDP-NoScope",
"FPS-SpoolSvc-In-TCP-NoScope",
"FPS-RPCSS-In-TCP-NoScope",
"FPS-ICMP4-ERQ-In-NoScope",
"FPS-ICMP6-ERQ-In-NoScope",
"NETDIS-UPnPHost-In-TCP-NoScope",
"NETDIS-NB_Name-In-UDP-NoScope",
"NETDIS-NB_Datagram-In-UDP-NoScope",
"NETDIS-WSDEVNTS-In-TCP-NoScope",
"NETDIS-WSDEVNT-In-TCP-NoScope",
"NETDIS-SSDPSrv-In-UDP-Active",
"NETDIS-SSDPSrv-In-UDP",
"NETDIS-FDPHOST-In-UDP",
"NETDIS-DAS-In-UDP",
"NETDIS-LLMNR-In-UDP",
"NETDIS-FDRESPUB-WSD-In-UDP",
"RemoteAssistance-RAServer-In-TCP-NoScope-Active",
"RemoteAssistance-DCOM-In-TCP-NoScope-Active",
"RemoteAssistance-In-TCP-EdgeScope-Active",
"RemoteAssistance-SSDPSrv-In-UDP-Active",
"RemoteAssistance-SSDPSrv-In-TCP-Active",
"RemoteAssistance-PnrpSvc-UDP-In-EdgeScope-Active",
"MSDTC-In-TCP-NoScope",
"MSDTC-KTMRM-In-TCP-NoScope",
"RemoteEventLogSvc-In-TCP-NoScope",
"RemoteEventLogSvc-NP-In-TCP-NoScope",
"RemoteEventLogSvc-RPCSS-In-TCP-NoScope",
"RemoteSvcAdmin-In-TCP-NoScope",
"RemoteSvcAdmin-NP-In-TCP-NoScope",
"RemoteSvcAdmin-RPCSS-In-TCP-NoScope",
"PerfLogsAlerts-PLASrv-In-TCP-NoScope",
"PerfLogsAlerts-DCOM-In-TCP-NoScope",
"RemoteTask-In-TCP-NoScope",
"RemoteTask-RPCSS-In-TCP-NoScope",
"WINRM-HTTP-In-TCP-NoScope",
"WINRM-HTTP-Compat-In-TCP-NoScope",
"RemoteDesktop-UserMode-In-TCP",
"RemoteDesktop-UserMode-In-UDP"
)
#For Debug only
#Write-Host $netrulenames.Length

$i=0
do {
    #For Debug only
    #Get-NetFirewallRule -Name $netrulenames[$i]
    Set-NetFirewallRule -Name $netrulenames[$i] -Profile Domain -Enabled True | Out-file -Append -FilePath $log_path
    #For Debug only
    #Write-Host $netrulenames[$i]
    #Write-Host $i
    $i++
    Write-Progress -Activity "Changing firewall rules" -Status "Completed:" -PercentComplete ($i/$netrulenames.Count*100)
} until ($i -ge $netrulenames.Length)
#1 Changing firewall rules
$Task="Changing firewall rules"
Write-Progress -Activity "Started Task" -Status $Task
Write-Progress -Activity "Implementig Task" -Status "is completed"

#2 Remove MS Mail and Calendar
$Task="Remove MS Mail and Calendar"
Write-Progress -Activity "Started Task" -Status $Task
Remove-AppxProvisionedPackage -Online -AllUsers -PackageName microsoft.windowscommunicationsapps_16005.13426.20920.0_neutral_~_8wekyb3d8bbwe | Out-file -Append -FilePath $log_path
Write-Progress -Activity "Implementig Task" -Status "is completed"

#3 Setting Up Power Scheme to Ultra Perfomance and Disable Hibernate
$Task="Setting Up Power Scheme to Ultra Perfomance and Disable Hibernate"
Write-Progress -Activity "Started Task" -Status $Task
powercfg /s e9a42b02-d5df-448d-aa00-03f14749eb61
powercfg /l | Out-file -Append -FilePath $log_path
powercfg /H OFF
Write-Progress -Activity "Implementig Task" -Status "is completed"

#4 Setting Up VMware Horizon Logon Monitor Service to Automatic
$Task="Setting Up VMware Horizon Logon Monitor Service to Automatic"
Write-Progress -Activity "Started Task" -Status $Task
Set-Service -Name vmlm -StartupType Automatic | Out-file -Append -FilePath $log_path
Write-Progress -Activity "Implementig Task" -Status "is completed"

#5 Setting Up For Roaming Profile Support
$Task="Setting Up For Roaming Profile Support"
Write-Progress -Activity "Started Task" -Status $Task
#The required policy (https://docs.microsoft.com/en-us/windows-server/storage/folder-redirection/deploy-roaming-user-profiles)
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SpecialRoamingOverrideAllowed' -PropertyType DWORD -Value 1 | Out-file -Append -FilePath $log_path
#Support for the APPX for the Roaming Profiles
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx' -Name 'AllowDeploymentInSpecialProfiles' -PropertyType DWORD -Value 1 | Out-file -Append -FilePath $log_path
Write-Progress -Activity "Implementig Task" -Status "is completed"

#6 Disable First Logon Animation
$Task="Disable First Logon Animation"
Write-Progress -Activity "Started Task" -Status $Task
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableFirstLogonAnimation' -PropertyType DWORD -Value 0 | Out-file -Append -FilePath $log_path
Write-Progress -Activity "Implementig Task" -Status "is completed"

#7 Enable Guest Authentication in SMB Share Folders
$Task="Enable Guest Authentication in SMB Share Folders"
Write-Progress -Activity "Started Task" -Status $Task
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'AllowInsecureGuestAuth' -PropertyType DWORD -Value 1 | Out-file -Append -FilePath $log_path
Write-Progress -Activity "Implementig Task" -Status "is completed"

#8 Changing Visual Effects for Better Perfomance
$Task="Changing Visual Effects for Better Perfomance"
Write-Progress -Activity "Started Task" -Status $Task
#Setting Up Visual Effects for Perfomance Mode
Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name UserPreferencesMask -Value ([byte[]](0x9E,0x2C,0x07,0x80,0x10,0x00,0x00,0x00)) | Out-file -Append -FilePath $log_path
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name 'VisualFxSetting' -PropertyType DWORD -Value 2 | Out-file -Append -FilePath $log_path
#Disable Transparency Effect
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'EnableTransparency' -Value '0' | Out-file -Append -FilePath $log_path
#Diabling windows animation for all users
Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop\WindowMetrics' -Name MinAnimate -Value 0 | Out-file -Append -FilePath $log_path
#Disable Logon Background Image
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DisableLogonBackgroundImage' -Value '1' | Out-file -Append -FilePath $log_path



## other
Write-Host "Configuring Windows Update Service to run in standalone svchost..." -ForegroundColor Green;
Write-Host "";
sc.exe config wuauserv type= own | Out-file -Append -FilePath $log_path;
Write-Host "";

##
Write-Host "Bring back execution policy" -ForegroundColor Green;
Write-Host "";
Set-ExecutionPolicy Restricted;
Write-Host "";

##
Write-Host "Disabling System Restore..." -ForegroundColor Green;
Write-Host "";
Disable-ComputerRestore -Drive "C:\";
Write-Host "";

##
Write-Host "Disabling Machine Account Password Changes..." -ForegroundColor Green;
Write-Host "";
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'DisablePasswordChange' -Value '1';
Write-Host "";

##
Write-Host "Disabling Memory Dump Creation..." -ForegroundColor Green;
Write-Host "";
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'CrashDumpEnabled' -Value '1';
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'LogEvent' -Value '0';
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'SendAlert' -Value '0';
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'AutoReboot' -Value '1';
Write-Host "";

##
Write-Host "Increasing Service Startup Timeout To 180 Seconds..." -ForegroundColor Green;
Write-Host "";
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'ServicesPipeTimeout' -Value '180000';
Write-Host "";

##
Write-Host "Disabling IE First Run Wizard..." -ForegroundColor Green;
Write-Host "";
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft' -Name 'Internet Explorer' | Out-Null;
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer' -Name 'Main' | Out-Null;
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main' -Name DisableFirstRunCustomize -PropertyType DWORD -Value '1' | Out-Null;
Write-Host "";

##
Write-Host "Removing Previous Versions Capability..." -ForegroundColor Green;
Write-Host "";
Set-ItemProperty -Path 'HKLM:\SOFTWARE\\Microsoft\Windows\CurrentVersion\Explorer' -Name 'NoPreviousVersionsPage' -Value '1';
Write-Host "";

##
Write-Host "Configuring Windows Explorer..." -ForegroundColor Green;
Write-Host "";
New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -PropertyType DWORD -Value '1' | Out-Null;
Write-Host "";

##
Write-Host "Configuring Search Options..." -ForegroundColor Green;
Write-Host "";
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowSearchToUseLocation' -PropertyType DWORD -Value '0' | Out-Null;
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'ConnectedSearchUseWeb' -PropertyType DWORD -Value '0' | Out-Null;
New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name 'SearchboxTaskbarMode' -PropertyType DWORD -Value '1' | Out-Null;
Write-Host "";



# disabled
<#
##
Write-Host "Disabling NTFS Last Access Timestamps..." -ForegroundColor Green;
Write-Host "";
FSUTIL behavior set disablelastaccess 1 | Out-Null;
Write-Host "";

##
Write-Host "Changing SMB Parameters..."
Write-Host "";
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'DisableBandwidthThrottling' -PropertyType DWORD -Value '1' | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'DisableLargeMtu' -PropertyType DWORD -Value '0' | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'FileInfoCacheEntriesMax' -PropertyType DWORD -Value '8000' | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'DirectoryCacheEntriesMax' -PropertyType DWORD -Value '1000' | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'FileNotFoundcacheEntriesMax' -PropertyType DWORD -Value '1' | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'MaxCmds' -PropertyType DWORD -Value '8000' | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'EnableWsd' -PropertyType DWORD -Value '0' | Out-Null 
Write-Host "";
#>


##
Write-Host "Disabling Scheduled Tasks..." -ForegroundColor Green;
Write-Host "";
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Autochk\Proxy" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Bluetooth\UninstallDeviceTask" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Diagnosis\Scheduled" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Location\Notifications" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Maintenance\WinSAT" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Maps\MapsToastTask" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Maps\MapsUpdateTask" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Ras\MobilityManager" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Registry\RegIdleBackup" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\RetailDemo\CleanupOfflineContent" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Shell\FamilySafetyMonitor" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Shell\FamilySafetyRefresh" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\SystemRestore\SR" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\UPnP\UPnPHostConfig" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\WDI\ResolutionHost" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\WOF\WIM-Hash-Management" | Out-Null;
Disable-ScheduledTask -TaskName "\Microsoft\Windows\WOF\WIM-Hash-Validation" | Out-Null; 
Write-Host "";

##
Write-Host "Run registry optimize performance (Optimized System Properties, Performance Options)" -ForegroundColor Green;
Write-Host "";
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer" /v ShellState /t REG_BINARY /d 240000003C2800000000000000000000 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v IconsOnly /t REG_DWORD /d 1 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewAlphaSelect /t REG_DWORD /d 0 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ListviewShadow /t REG_DWORD /d 0 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowCompColor /t REG_DWORD /d 1 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowInfoTip /t REG_DWORD /d 1 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAnimations /t REG_DWORD /d 0 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 3 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\DWM" /v EnableAeroPeek /t REG_DWORD /d 0 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\DWM" /v AlwaysHiberNateThumbnails /t REG_DWORD /d 0 /f;
reg add "HKLM\Temp\Control Panel\Desktop" /v DragFullWindows /t REG_SZ /d 0 /f;
reg add "HKLM\Temp\Control Panel\Desktop" /v FontSmoothing /t REG_SZ /d 2 /f;
reg add "HKLM\Temp\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 9032078010000000 /f;
reg add "HKLM\Temp\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 01 /t REG_DWORD /d 0 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /t REG_DWORD /d 0 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353694Enabled /t REG_DWORD /d 0 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353696Enabled /t REG_DWORD /d 0 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f;
reg add "HKLM\Temp\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.Photos_8wekyb3d8bbwe" /v Disabled /t REG_DWORD /d 1 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.Photos_8wekyb3d8bbwe" /v DisabledByUser /t REG_DWORD /d 1 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.SkypeApp_kzf8qxf38zg5c" /v Disabled /t REG_DWORD /d 1 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.SkypeApp_kzf8qxf38zg5c" /v DisabledByUser /t REG_DWORD /d 1 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.YourPhone_8wekyb3d8bbwe" /v Disabled /t REG_DWORD /d 1 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.YourPhone_8wekyb3d8bbwe" /v DisabledByUser /t REG_DWORD /d 1 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" /v Disabled /t REG_DWORD /d 1 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" /v DisabledByUser /t REG_DWORD /d 1 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.PPIProjection_cw5n1h2txyewy" /v Disabled /t REG_DWORD /d 1 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.PPIProjection_cw5n1h2txyewy" /v DisabledByUser /t REG_DWORD /d 1 /f;
reg add "HKLM\Temp\Software\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f;
reg add "HKLM\Temp\Software\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f;
reg add "HKLM\Temp\Software\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f;
reg add "HKLM\Temp\Software\Microsoft\InputPersonalization\TrainedDataStore" /v HarvestContacts /t REG_DWORD /d 0 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v ScoobeSystemSettingEnabled /t REG_DWORD /d 0 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v ScoobeSystemSettingEnabled /t REG_DWORD /d 0 /f;
reg add "HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v ScoobeSystemSettingEnabled /t REG_DWORD /d 0 /f;
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f;
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f;
Write-Host "";

## Hard drive
Write-Host "Disabling Hard Disk Timeouts..." -ForegroundColor Green;
Write-Host "";
POWERCFG /SETACVALUEINDEX 381b4222-f694-41f0-9685-ff5bb260df2e 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
POWERCFG /SETDCVALUEINDEX 381b4222-f694-41f0-9685-ff5bb260df2e 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
Write-Host "";

##
Write-Host "Increasing Disk I/O Timeout to 200 Seconds..." -ForegroundColor Green;
Write-Host "";
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Disk' -Name 'TimeOutValue' -Value '200';
Write-Host "";

##
Write-Host "Cleanup system drive" -ForegroundColor Green;
Write-Host "";
cleanmgr /verylowdisk
Write-Host "";


## network
Write-Host "Configuring Network List Service to start Automatic..." -ForegroundColor Green;
Write-Host "";
Set-Service netprofm -StartupType Automatic | Out-file -Append -FilePath $log_path;
Write-Host "";

##
Write-Host "Disabling TCP Large Send Offload..." -ForegroundColor Green;
Write-Host "";
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters -Name 'DisableTaskOffload' -PropertyType DWORD -Value '1' | Out-Null;
Write-Host "";

##
Write-Host "Disabling New Network Dialog..." -ForegroundColor Green;
Write-Host "";
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Network' -Name 'NewNetworkWindowOff' | Out-Null;
Write-Host "";

##
Write-Host "Clearup routes...." -ForegroundColor Green;
Write-Host "";
route -f;
Write-Host "";

Write-Host "Fixing winsock..." -ForegroundColor Green;
Write-Host "";
netsh winsock reset;
Write-Host "";

Write-Host "ipconfig release and flush dns..." -ForegroundColor Green;
Write-Host "";
ipconfig /release;
ipconfig /flushdns;
Write-Host "";

Write-Host "Waiting for 7 seconds..." -ForegroundColor Green;
Write-Host "";
TIMEOUT /T 10 /NOBREAK;
Write-Host "";

Write-Host "Clearing event logs...";
Write-Host "";
Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log };
Write-Host "";

Write-Host "SHUTDOWN"
Write-Host ""
shutdown /s /t 0;
