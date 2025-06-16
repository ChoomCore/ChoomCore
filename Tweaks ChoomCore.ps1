Stop-Service "Connected User Experiences and Telemetry" -Force
Set-Service "Connected User Experiences and Telemetry" -StartupType Disabled
Stop-Service MapsBroker -Force
Set-Service MapsBroker -StartupType Disabled
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_Recommendations" /t REG_DWORD /d 0 /f
Get-ScheduledTask | Where-Object {$_.TaskName -like "*XblGameSave*"} | Disable-ScheduledTask
Get-ScheduledTask | Where-Object {$_.TaskName -like "*MicrosoftEdge*" -or $_.TaskName -like "*OfficeClickToRun*"} | Disable-ScheduledTask
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
Stop-Service DiagTrack -Force
Set-Service DiagTrack -StartupType Disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
Stop-Service WerSvc -Force
Set-Service WerSvc -StartupType Disabled
Stop-Service DusmSvc -Force
Set-Service DusmSvc -StartupType Disabled
Stop-Service SCardSvr -Force
Set-Service SCardSvr -StartupType Disabled
Stop-Service WbioSrvc -Force
Set-Service WbioSrvc -StartupType Disabled
Stop-Service bthserv -Force
Set-Service bthserv -StartupType Disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Network" /v NoFileSharing /t REG_DWORD /d 1 /f
reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v AutoEndTasks /t REG_SZ /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 01 /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v WaitToKillAppTimeout /t REG_SZ /d 2000 /f
reg add "HKCU\Control Panel\Desktop" /v HungAppTimeout /t REG_SZ /d 2000 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Feedback" /v DisableFeedbackNotifications /t REG_DWORD /d 1 /f
sc stop DiagTrack
sc config DiagTrack start=disabled
sc stop dmwappushsvc
sc config dmwappushsvc start=disabled
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v CEIPEnable /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Edge\Main" /v AllowPrelaunch /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Edge\Main" /v AllowTabPreloading /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\MicrosoftEdge\Main" /v AllowPrelaunch /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v AllowTabPreloading /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Edge" /v NewTabPageContentEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Edge" /v NewTabPageHideDefaultTopSites /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Edge" /v HubsSidebarEnabled /t REG_DWORD /d 0 /f
schtasks /Change /TN "\Microsoft\EdgeUpdate\EdgeUpdateTaskMachineCore" /Disable
schtasks /Change /TN "\Microsoft\EdgeUpdate\EdgeUpdateTaskMachineUA" /Disable
reg add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v CreateDesktopShortcutDefault /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v RemoveDesktopShortcutDefault /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Google\Chrome" /v MetricsReportingEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Google\Chrome" /v CrashReportingEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\BraveSoftware\Brave" /v PrerenderFromOmnibox /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\BraveSoftware\Brave" /v MetricsReportingEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\BraveSoftware\Brave" /v CrashReportingEnabled /t REG_DWORD /d 0 /f
schtasks /Change /TN "\BraveSoftware\BraveUpdateTaskMachineCore" /Disable
schtasks /Change /TN "\BraveSoftware\BraveUpdateTaskMachineUA" /Disable
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.WindowsStore" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v ToastEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v DoubleClickSpeed /t REG_SZ /d 200 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v OneDrive /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Edge /t REG_SZ /d "" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" /v "PenAndTouch" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "LaunchTo" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoRecentDocsMenu" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "StartupDelayInMSec" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "AlwaysShowMenus" /t REG_DWORD /d 1 /f
Stop-Service dmwappushservice -Force
Set-Service dmwappushservice -StartupType Disabled
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v PeriodInNanoSeconds /t REG_QWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience\" | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Autochk\" | Disable-ScheduledTask
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowRecommendations /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f
reg add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 0 /f
Get-PnpDevice | Where-Object { $_.FriendlyName -like "*touch*" -and $_.Status -eq "OK" } | Disable-PnpDevice -Confirm:$false
reg add "HKCU\Control Panel\Desktop" /v LogPixels /t REG_DWORD /d 96 /f
reg add "HKCU\Control Panel\Desktop" /v Win8DpiScaling /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Mouse" /v MouseTrails /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Keyboard" /v KeyboardSpeed /t REG_SZ /d 31 /f
reg add "HKCU\Control Panel\Keyboard" /v KeyboardDelay /t REG_SZ /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Ndu" /v Start /t REG_DWORD /d 4 /f
lodctr /Q
lodctr /R
lodctr /D
Stop-Service -Name DiagSvc -Force
Set-Service -Name DiagSvc -StartupType Disabled
Stop-Service lfsvc -Force
Set-Service lfsvc -StartupType Disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f
bcdedit /set hypervisorlaunchtype off
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v FolderContentsInfoTip /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowInfoTip /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\GameBar" /v ShowStartupPanel /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v HungAppTimeout /t REG_SZ /d 1000 /f
reg add "HKCU\Control Panel\Desktop" /v WaitToKillAppTimeout /t REG_SZ /d 1000 /f
reg add "HKCU\Software\Microsoft\Input\TIPC" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ActionCenterEnabled /t REG_DWORD /d 0 /f
Stop-Service SensorService -Force
Set-Service SensorService -StartupType Disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /v ChatEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v DiagTrack /t REG_DWORD /d 0 /f
Stop-Service -Name DiagTrack -Force
Set-Service -Name DiagTrack -StartupType Disabled
reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarMn /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAi /t REG_DWORD /d 0 /f
reg add "HKCU\Console" /v ForceV2 /t REG_DWORD /d 0 /f
taskkill /f /im GameBarPresenceWriter.exe
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f
Stop-Service -Name WpnUserService -Force
Set-Service -Name WpnUserService -StartupType Disabled
Stop-Service -Name bthserv -Force
Set-Service -Name bthserv -StartupType Disabled
reg add "HKLM\SYSTEM\ControlSet001\Services\Ndu" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v TimeStampInterval /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v value /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
Disable-MMAgent -mc
Stop-Service -Name WpnService -Force
Set-Service -Name WpnService -StartupType Disabled
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowDeviceNameInTelemetry /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v EnableInPlace /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v EdgeTargetMargin /t REG_DWORD /d 0 /f
taskkill /f /im TextInputHost.exe
Stop-Service -Name WerSvc -Force
Set-Service -Name WerSvc -StartupType Disabled
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v HarvestContacts /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpynetReporting /t REG_DWORD /d 0 /f
Stop-Service -Name "dmwappushservice" -Force
Set-Service -Name "dmwappushservice" -StartupType Disabled
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory" /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d 1 /f
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "1000" /f
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\USB\Parameters" /v DisableSelectiveSuspend /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v StartupDelayInMSec /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v NoRecentDocsMenu /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v MouseDataQueueSize /t REG_DWORD /d 120 /f
reg add "HKCU\Software\Microsoft\Avalon.Graphics" /v DisableHWVSync /t REG_DWORD /d 1 /f
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d 2 /f
Stop-Service "CDPUserSvc" -Force
Set-Service "CDPUserSvc" -StartupType Disabled
Stop-Service "PcaSvc" -Force
Set-Service "PcaSvc" -StartupType Disabled
Stop-Service "AppVClient" -Force
Set-Service "AppVClient" -StartupType Disabled
Get-ScheduledTask -TaskName "Consolidator" | Disable-ScheduledTask
Get-ScheduledTask -TaskName "UsbCeip" | Disable-ScheduledTask
reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f  
reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f  
Stop-Service PhoneSvc -Force
Set-Service PhoneSvc -StartupType Disabled
Stop-Service MessagingService -Force
Set-Service MessagingService -StartupType Disabled
Stop-Service SharedAccess -Force
Set-Service SharedAccess -StartupType Disabled
Stop-Service RetailDemo -Force
Set-Service RetailDemo -StartupType Disabled
Stop-Service DiagSvc -Force
Set-Service DiagSvc -StartupType Disabled
Stop-Service SensrSvc -Force
Set-Service SensrSvc -StartupType Disabled
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /Disable
schtasks /Change /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
schtasks /Change /TN "\Microsoft\Windows\Location\Notifications" /Disable
schtasks /Change /TN "\Microsoft\Windows\Location\WindowsActionDialog" /Disable
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\LoginCheck" /Disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\Registration" /Disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable
Stop-Service RemoteRegistry -Force
Set-Service RemoteRegistry -StartupType Disabled
Stop-Service SSDPSRV -Force
Set-Service SSDPSRV -StartupType Disabled
Stop-Service upnphost -Force
Set-Service upnphost -StartupType Disabled
Stop-Service iphlpsvc -Force
Set-Service iphlpsvc -StartupType Disabled
Disable-WindowsOptionalFeature -Online -FeatureName Printing-PrintToPDFServices-Features -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName FaxServicesClientPackage -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName Internet-Explorer-Optional -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName XPS-Viewer -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName MediaPlayback -NoRestart
Disable-NetAdapterBinding -Name "*" -ComponentID ms_rspndrStop-Service WpcMonSvc -Force
Set-Service WpcMonSvc -StartupType Disabled
schtasks /Change /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "\Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" /DisableStop-Service dmwappushservice -Force
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoDetect /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" /v Start /t REG_DWORD /d 4 /f
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Stop-Service fdPHost -Force
Set-Service fdPHost -StartupType Disabled
Stop-Service FDResPub -Force
Set-Service FDResPub -StartupType Disabled
Stop-Service -Name 'BDESVC' -Force
Set-Service -Name 'BDESVC' -StartupType Disabled
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v EnableBDE /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v EncryptionMethodWithXtsFdv /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v EncryptionMethodWithXtsOs /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v FDVEncryptionType /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v RDVDisableBDE /t REG_DWORD /d 1 /f
sc stop MapsBroker
Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart
logman stop perfdiag -ets
Stop-Service -Name "DmEnrollmentSvc" -Force -ErrorAction SilentlyContinue
Set-Service -Name "DmEnrollmentSvc" -StartupType Disabled
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v KeyboardDataQueueSize /t REG_DWORD /d 120 /f
dism /Online /Disable-Feature /FeatureName:Printing-PrintToPDFServices-Features
dism /Online /Disable-Feature /FeatureName:WindowsMediaPlayer
dism /Online /Disable-Feature /FeatureName:Internet-Explorer-Optional-amd64
Get-AppxPackage *windowsfeedback* | Remove-AppxPackage
Get-AppxPackage *DiagnosticsHub* | Remove-AppxPackage
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /v "CdpSessionUserAuthzPolicy" /t REG_DWORD /d 0 /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /v "CdpSessionUserAuthzPolicy" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-PLA/Operational" /v Enabled /t REG_DWORD /d 0 /f   
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational" /v Enabled /t REG_DWORD /d 0 /f
Get-AppxPackage *MicrosoftCorporationII.QuickAssist* | Remove-AppxPackage  
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like "*QuickAssist*"} | Remove-AppxProvisionedPackage -Online
Get-AppxPackage *WindowsBackup* | Remove-AppxPackage
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like "*WindowsBackup*"} | Remove-AppxProvisionedPackage -Online
Get-AppxPackage *Microsoft.YourPhone* | Remove-AppxPackage  
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like "*YourPhone*"} | Remove-AppxProvisionedPackage -Online
Get-AppxPackage *Microsoft.Getstarted* | Remove-AppxPackage  
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like "*Getstarted*"} | Remove-AppxProvisionedPackage -Online
Get-AppxPackage *Microsoft.WindowsFamily* | Remove-AppxPackage  
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like "*WindowsFamily*"} | Remove-AppxProvisionedPackage -Online 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
logman stop perfdiag -ets
reg add "HKCU\Software\Microsoft\Clipboard" /v EnableClipboardHistory /t REG_DWORD /d 0 /f  
reg add "HKCU\Software\Microsoft\Clipboard" /v EnableCloudClipboard /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\FileHistory" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v SnapAssist /t REG_DWORD /d 0 /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v SnapFlyoutSuggest /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_Recommendations /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /t REG_DWORD /d 0 /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f  
Stop-Service wisvc -Force  
Set-Service wisvc -StartupType Disabled  
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /v "CdpSessionUserAuthzPolicy" /t REG_DWORD /d 0 /f
Get-AppxPackage *WebExperience* | Remove-AppxPackage  
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like "*WebExperience*"} | Remove-AppxProvisionedPackage -Online
Stop-Service FrameServer -Force  
Set-Service FrameServer -StartupType Disabled
Stop-Service SEMgrSvc -Force  
Set-Service SEMgrSvc -StartupType Disabled
Stop-Service PerceptionSimulation -Force  
Set-Service PerceptionSimulation -StartupType Disabled
Stop-Service SCardSvr -Force  
Stop-Service PhoneSvc -Force  
Stop-Service CaptureService -Force  
Set-Service CaptureService -StartupType Disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f    
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarMn /t REG_DWORD /d 0 /f  
reg add "HKCU\Software\Microsoft\Narrator" /v "UserPrefNarratorHotkey" /t REG_DWORD /d 0 /f  
reg add "HKCU\Software\Microsoft\Narrator" /v "UserPrefStartNarratorOnStartup" /t REG_DWORD /d 0 /f  
reg add "HKCU\Software\Microsoft\Narrator" /v "WinEnterLaunchEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v Configuration /t REG_SZ /d "" /f  
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v DebugOutput /t REG_DWORD /d 0 /f
Stop-Service BTAGService -Force  
Set-Service BTAGService -StartupType Disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Accessibility" /v SoundSentryFlags /t REG_DWORD /d 0 /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Accessibility" /v SoundSentryAnimation /t REG_DWORD /d 0 /f
Get-AppxPackage *Accessibility* | Remove-AppxPackage  
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like "*Accessibility*"} | Remove-AppxProvisionedPackage -Online
reg add "HKCU\Software\Microsoft\Accessibility" /v "LiveCaptionsEnabled" /t REG_DWORD /d 0 /f  
reg add "HKCU\Software\Microsoft\Accessibility" /v "LiveCaptionsOnboardingComplete" /t REG_DWORD /d 1 /f  
reg add "HKCU\Software\Microsoft\Accessibility" /v "LiveCaptionsLanguage" /t REG_SZ /d "" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v NOC_GLOBAL_SETTING_TOASTS_ENABLED /t REG_DWORD /d 0 /f 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t REG_SZ /d Deny /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v Enabled /t REG_DWORD /d 0 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" /v Enabled /t REG_DWORD /d 0 /f
logman delete trace "Diagtrack-Listener"
bcdedit /set vsmlaunchtype Off  
Stop-Service RpcLocator -Force
Set-Service RpcLocator -StartupType Disabled
reg add "HKLM\SOFTWARE\Microsoft\Ole" /v EnableDCOM /t REG_SZ /d "N" /f
reg add "HKLM\SOFTWARE\Microsoft\Rpc" /v DCOMProtocol /t REG_MULTI_SZ /d "" /f
auditpol /set /category:* /success:disable /failure:disable
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsBackup" /v DisableBackup /t REG_DWORD /d 1 /f
Stop-Service BDESVC -Force
Set-Service BDESVC -StartupType Disabled
sc delete BDESVC
reg add "HKCU\Control Panel\Desktop" /v MouseHoverTime /t REG_SZ /d 10 /f
Get-Service | Where-Object { $_.Name -like "*Nahimic*" -or $_.Name -like "*DTS*" -or $_.Name -like "*Sonic*" } | Stop-Service -Force
Get-Service | Where-Object { $_.Name -like "*Nahimic*" -or $_.Name -like "*DTS*" -or $_.Name -like "*Sonic*" } | Set-Service -StartupType Disabled
reg add "HKCU\Control Panel\Mouse" /v MouseHoverTime /t REG_SZ /d 10 /f
reg add "HKLM\SOFTWARE\Microsoft\COM3" /v DisableClassStore /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\pci\Parameters" /v EnableASPM /t REG_DWORD /d 0 /f
sc.exe config KtmRm start= disabled
Stop-Service KtmRm -Force
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsDisableCompression /t REG_DWORD /d 1 /f
Stop-Service PcaSvc -Force
Set-Service PcaSvc -StartupType Disabled
Stop-Service SensorDataService -Force
Set-Service SensorDataService -StartupType Disabled
Stop-Service SmsRouter -Force
Set-Service SmsRouter -StartupType Disabled
cmd /c "sc config CldFlt start=disabled"
sc.exe config storqosflt start=disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WpnUserService" /v Start /t REG_DWORD /d 4 /f
& sc.exe config WiaRpc start= disabled
Stop-Service WiaRpc -Force
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" /v SMBDeviceEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f
Stop-Service DeviceAssociationBrokerSvc -Force
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\TriggerInfo" /v Start /t REG_DWORD /d 4 /f
Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "FaxServicesClientPackage" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart
Stop-Service -Name "cbdhsvc" -Force
Set-Service -Name "cbdhsvc" -StartupType Disabled
Stop-Service -Name "UdkUserSvc" -Force
Set-Service -Name "UdkUserSvc" -StartupType Disabled
Stop-Service -Name "PhoneSvc" -Force
Set-Service -Name "PhoneSvc" -StartupType Disabled
Stop-Service -Name "MessagingService" -Force
Set-Service -Name "MessagingService" -StartupType Disabled
Stop-Service -Name "SEMgrSvc" -Force
Set-Service -Name "SEMgrSvc" -StartupType Disabled
Stop-Service -Name "PerceptionSimulation" -Force
Set-Service -Name "PerceptionSimulation" -StartupType Disabled
Stop-Service -Name "FrameServer" -Force
Set-Service -Name "FrameServer" -StartupType Disabled
Stop-Service -Name "CaptureService" -Force
Set-Service -Name "CaptureService" -StartupType Disabled
Stop-Service -Name "WSAIFabricSvc" -Force
Set-Service -Name "WSAIFabricSvc" -StartupType Disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot" /v "AlternateShell" /t REG_SZ /d "cmd.exe" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging" /t REG_DWORD /d 2 /f
Disable-WindowsOptionalFeature -Online -FeatureName "LegacyComponents" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "MSRDC-Infrastructure" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "Printing-Foundation-Features" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "Printing-Foundation-InternetPrinting-Client" -NoRestart
Stop-Service -Name "embeddedmode" -Force
Stop-Service -Name "icssvc" -Force
Set-Service -Name "icssvc" -StartupType Disabled
Stop-Service -Name "NaturalAuthentication" -Force
Set-Service -Name "NaturalAuthentication" -StartupType Disabled
Stop-Service -Name "HvHost" -Force
Set-Service -Name "HvHost" -StartupType Disabled
Stop-Service -Name "vmickvpexchange" -Force
Set-Service -Name "vmickvpexchange" -StartupType Disabled
Stop-Service -Name "vmicguestinterface" -Force
Set-Service -Name "vmicguestinterface" -StartupType Disabled
dism /online /Disable-Feature /FeatureName:MicrosoftWindowsPowerShellV2Root /NoRestart
dism /online /Disable-Feature /FeatureName:WorkFolders-Client /NoRestart
dism /online /Disable-Feature /FeatureName:Printing-PrintToPDFServices-Features /NoRestart
dism /online /Disable-Feature /FeatureName:Printing-XPSServices-Features /NoRestart
dism /online /Disable-Feature /FeatureName:Microsoft-Hyper-V-All /NoRestart
dism /online /Disable-Feature /FeatureName:LegacyComponents /NoRestart
Stop-Service -Name "DusmSvc" -Force
Set-Service -Name "DusmSvc" -StartupType Disabled
reg add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v SmoothMouseXCurve /t REG_BINARY /d 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 /f
reg add "HKCU\Control Panel\Mouse" /v SmoothMouseYCurve /t REG_BINARY /d 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 /f
Stop-Service "HvHost" -Force ; Set-Service "HvHost" -StartupType Disabled
Stop-Service "vmickvpexchange" -Force ; Set-Service "vmickvpexchange" -StartupType Disabled
Stop-Service "vmicguestinterface" -Force ; Set-Service "vmicguestinterface" -StartupType Disabled
Stop-Service "WpcMonSvc" -Force ; Set-Service "WpcMonSvc" -StartupType Disabled
Stop-Service "PhoneSvc" -Force ; Set-Service "PhoneSvc" -StartupType Disabled
Stop-Service "SEMgrSvc" -Force ; Set-Service "SEMgrSvc" -StartupType Disabled
schtasks /Change /TN "\Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
Stop-Service -Name "AssignedAccessManagerSvc" -Force ; Set-Service -Name "AssignedAccessManagerSvc" -StartupType Disabled
Stop-Service -Name "BluetoothUserService" -Force ; Set-Service -Name "BluetoothUserService" -StartupType Disabled
Stop-Service -Name "CDPSvc" -Force ; Set-Service -Name "CDPSvc" -StartupType Disabled
Stop-Service -Name "CertPropSvc" -Force ; Set-Service -Name "CertPropSvc" -StartupType Disabled
Stop-Service -Name "icssvc" -Force ; Set-Service -Name "icssvc" -StartupType Disabled
Stop-Service -Name "lfsvc" -Force ; Set-Service -Name "lfsvc" -StartupType Disabled
Stop-Service -Name "MapsBroker" -Force ; Set-Service -Name "MapsBroker" -StartupType Disabled
Stop-Service -Name "RetailDemo" -Force ; Set-Service -Name "RetailDemo" -StartupType Disabled
Stop-Service -Name "RemoteRegistry" -Force ; Set-Service -Name "RemoteRegistry" -StartupType Disabled
Stop-Service -Name "PcaSvc" -Force ; Set-Service -Name "PcaSvc" -StartupType Disabled
Stop-Service -Name "SCPolicySvc" -Force ; Set-Service -Name "SCPolicySvc" -StartupType Disabled
Stop-Service -Name "SensorDataService" -Force ; Set-Service -Name "SensorDataService" -StartupType Disabled
Stop-Service -Name "SensorService" -Force ; Set-Service -Name "SensorService" -StartupType Disabled
Stop-Service -Name "SharedAccess" -Force ; Set-Service -Name "SharedAccess" -StartupType Disabled
Stop-Service -Name "TrkWks" -Force ; Set-Service -Name "TrkWks" -StartupType Disabled
Stop-Service -Name "WbioSrvc" -Force ; Set-Service -Name "WbioSrvc" -StartupType Disabled
Stop-Service -Name "Wecsvc" -Force ; Set-Service -Name "Wecsvc" -StartupType Disabled
Stop-Service -Name "wisvc" -Force ; Set-Service -Name "wisvc" -StartupType Disabled
Stop-Service -Name "WpcMonSvc" -Force ; Set-Service -Name "WpcMonSvc" -StartupType Disabled
Stop-Service -Name "WPDBusEnum" -Force ; Set-Service -Name "WPDBusEnum" -StartupType Disabled
Stop-Service -Name "WpnService" -Force ; Set-Service -Name "WpnService" -StartupType Disabled
Stop-Service -Name "WpnUserService" -Force ; Set-Service -Name "WpnUserService" -StartupType Disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsDisableLastAccessUpdate /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsDisable8dot3NameCreation /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableAutoTray" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\GameBar" /v "AllowGameBar" /t REG_DWORD /d 0 /f