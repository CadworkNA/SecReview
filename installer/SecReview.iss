; Inno Setup script for SecReview. Compiles with Inno Setup 6.3 or later and 7.
;
; Installs what build.ps1 staged (artifacts\stage) into Program Files, for all users. The
; programs then cannot be replaced by an ordinary user, which the administrator checks rely on.
;
; Build:   build.ps1 -Installer            (output: artifacts\installer\SecReview-<version>-setup.exe)
; Signed:  build.ps1 -Installer -Sign      (setup and uninstaller signed through scripts\sign.ps1)
; Silent:  SecReview-<version>-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
;          add /MERGETASKS="!autostart" to leave out the icon at sign-in
;
; What setup changes on the PC, all of it removed by the uninstaller:
;   - the files in {autopf}\SecReview and a Start menu shortcut;
;   - one value under HKLM\...\Run that starts the notification-area icon at sign-in (a task,
;     on by default; each user can switch the icon off in SecReview's settings);
;   - the entry in "Installed apps".
; SecReview's own data (settings, last results, log) is per user, in %LOCALAPPDATA%\SecReview,
; and is left alone by install and uninstall.

#define AppName "SecReview"
#define AppExe "SecReview.exe"
#define CliExe "SecReviewCli.exe"
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
; Four numbers, for the version resource of the setup program.
#ifndef FileVersion
  #define FileVersion "0.0.0.0"
#endif
#ifndef Stage
  #define Stage "..\artifacts\stage"
#endif
#ifndef Publisher
  #define Publisher "SecReview"
#endif
#ifndef OutputFolder
  #define OutputFolder "..\artifacts\installer"
#endif

[Setup]
; Identifies SecReview to Windows across versions. Never change it.
AppId={{9133D268-5237-4719-B107-00C0C086FCDE}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#Publisher}
AppPublisherURL=https://github.com/CadworkNA/SecReview
AppSupportURL=https://github.com/CadworkNA/SecReview/issues
VersionInfoVersion={#FileVersion}
VersionInfoProductTextVersion={#AppVersion}
VersionInfoDescription={#AppName} setup
DefaultDirName={autopf}\{#AppName}
; Always Program Files: the folder is not asked for.
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Windows 10, version 2004: the oldest Windows SecReview runs on.
MinVersion=10.0.19041
SetupIconFile=..\resources\SecReview.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
OutputDir={#OutputFolder}
OutputBaseFilename={#AppName}-{#AppVersion}-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; Running copies are ended by setup itself (see [Code]), also where nobody can be asked.
CloseApplications=no
#ifdef SIGN
; "artifactsigning" is defined on the compiler's command line. Signs setup and the uninstaller.
SignTool=artifactsigning
SignedUninstaller=yes
#endif

[Tasks]
Name: autostart; Description: "Keep SecReview in the notification area (starts when a user signs in)"

[Files]
Source: "{#Stage}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; Files an earlier version installed and this one no longer has go here, one line each
; ([InstallDelete] Type: files; Name: "{app}\<file>"). There is no earlier version yet.

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"

[Registry]
; The notification-area icon at sign-in, for every user. Removed when the task is not chosen
; (also on an upgrade) and on uninstall.
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#AppName}"; ValueData: """{app}\{#AppExe}"" --tray"; Flags: uninsdeletevalue; Tasks: autostart
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: none; ValueName: "{#AppName}"; Flags: deletevalue; Tasks: not autostart

[Run]
; As the user who started setup, never with setup's administrator rights. Not after a silent
; install: there the icon comes at the next sign-in.
Filename: "{app}\{#AppExe}"; Parameters: "--tray"; Flags: nowait runasoriginaluser skipifsilent; Tasks: autostart
Filename: "{app}\{#AppExe}"; Description: "Open {#AppName}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
; A running copy would keep its files from being removed.
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM {#AppExe}"; Flags: runhidden; RunOnceId: "StopSecReview"
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM {#CliExe}"; Flags: runhidden; RunOnceId: "StopSecReviewCli"

[Code]
// Ends running copies of SecReview before its files are replaced: the window and the
// notification-area icon of every signed-in user. SecReview writes its files in one step, so
// being ended loses nothing. Nothing running is not an error.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#AppExe}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#CliExe}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := '';
end;
