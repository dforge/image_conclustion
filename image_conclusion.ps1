# thanks to
# https://github.com/cluberti/VDI/blob/master/ConfigAsVDI.ps1

## basic
$script_name = $MyInvocation.MyCommand.Name;
$script_path = $PSScriptRoot;
$log_path    = "$($script_path)\$($script_name).log";


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

##
Write-Host "Clearing event logs...";
Write-Host "";
Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log };
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


## view/animation
Write-Host "Diabling windows animation for all users" -ForegroundColor Green;
Write-Host "";
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f >nul 2>&1;
Write-Host "";

##
Write-Host "Configuring Winlogon..." -ForegroundColor Green
Write-Host "";
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DisableLogonBackgroundImage' -Value '1';
Write-Host "";

## 
Write-Host "Removing Transparency Effects..." -ForegroundColor Green;
Write-Host "";
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'EnableTransparency' -Value '0';

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


## software
Write-Host "Remove mail app, calendar, microsoft BA";
Write-Host "";
Remove-AppxProvisionedPackage -Online -PackageName "Microsoft.windowscommunicationsapps" -Allusers | Out-Null
Remove-AppxPackage -Package "Microsoft.windowscommunicationsapps" | Out-Null
Write-Host ""; 


## scom/sccm fix
Write-Host "Stopping ccmexec..." -ForegroundColor Green;
Write-Host "";
net stop CcmExec;
Write-Host "";

Write-Host "Removing smscfg.ini" -ForegroundColor Green;
Write-Host "";
del c:\windows\SMSCFG.ini;
Write-Host ""; 

Write-Host "Removing ssl store SMS SMS" -ForegroundColor Green;
Write-Host "";
certutil –delstore SMS SMS;
Write-Host ""; 


## powerplan
Write-Host "Disabling Hibernate..." -ForegroundColor Green;
Write-Host "";
POWERCFG -h off;
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

Write-Host "SHUTDOWN"
Write-Host ""
shutdown /s /t 0;
