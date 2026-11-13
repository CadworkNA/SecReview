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
;   - the files in {autopf}\SecReview and a Start menu shortcut, which carries SecReview's
;     identity for app notifications and the class Windows starts when one is clicked;
;   - that class, HKLM\Software\Classes\CLSID\{ToastActivator}: it starts
;     "SecReview.exe --notification-click", which takes nothing from the command line;
;   - one value under HKLM\...\Run that starts the notification-area icon at sign-in (a task,
;     on by default; each user can switch the icon off in SecReview's settings);
;   - the entry in "Installed apps".
; SecReview's own data (settings, last results, log) is per user, in %LOCALAPPDATA%\SecReview,
; and is left alone by install and uninstall.

#define AppName "SecReview"
#define AppExe "SecReview.exe"
#define CliExe "SecReviewCli.exe"
; App notifications: the identity Windows files them under and the class it starts for a
; click. Both are in SecReview.Tray.AppNotification too (a test compares them). Never change them.
#define AppUserModelId "Cadwork.SecReview"
#define ToastActivator "164B92DB-C7E7-4DDB-B345-C9BFAD05817F"
#define NotificationClickSwitch "--notification-click"
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
; The folder is not asked for, and /DIR is refused (see [Code]): only Program Files.
DisableDirPage=yes
UsePreviousAppDir=no
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
; What an earlier version left in the folder is removed first (see [Code]), so the folder
; holds exactly this version afterwards.
Source: "{#Stage}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; The identity and the class are what make SecReview's notifications stay in the notification
; centre and open the window when clicked.
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; AppUserModelID: "{#AppUserModelId}"; AppUserModelToastActivatorCLSID: "{#ToastActivator}"

[Registry]
; What Windows starts when a notification is clicked. The click's arguments come from Windows,
; and SecReview takes only what its own notifications hold.
Root: HKLM; Subkey: "Software\Classes\CLSID\{{{#ToastActivator}}"; ValueType: string; ValueName: ""; ValueData: "{#AppName} notification click"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\CLSID\{{{#ToastActivator}}\LocalServer32"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExe}"" {#NotificationClickSwitch}"
; The notification-area icon at sign-in, for every user. Removed when the task is not chosen
; (also on an upgrade) and on uninstall.
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#AppName}"; ValueData: """{app}\{#AppExe}"" --tray"; Flags: uninsdeletevalue; Tasks: autostart
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: none; ValueName: "{#AppName}"; Flags: deletevalue; Tasks: not autostart

[Run]
; Not after a silent install: there the icon comes at the next sign-in.
;
; The icon is started as the user who started setup. Where that user started setup with
; administrator rights already, the icon notices and does not stay (it then comes at the next
; sign-in): it must not keep those rights all day.
Filename: "{app}\{#AppExe}"; Parameters: "--tray"; Flags: nowait runasoriginaluser skipifsilent; Tasks: autostart
; The window is opened through the desktop, so it runs as the signed-in user without
; administrator rights, however setup itself was started.
Filename: "{win}\explorer.exe"; Parameters: """{app}\{#AppExe}"""; Description: "Open {#AppName}"; Flags: nowait postinstall skipifsilent runasoriginaluser
; After an update that SecReview installed itself (silent, with /RELAUNCH=1): the window opens
; again, the same way. SecReview's helper asks for this only when the user who asked for the
; update is the one whose administrator rights are used.
Filename: "{win}\explorer.exe"; Parameters: """{app}\{#AppExe}"""; Flags: nowait runasoriginaluser; Check: RelaunchAsked

[UninstallDelete]
; Where SecReview's own updates are downloaded to (administrators only): what the last one left.
Type: filesandordirs; Name: "{autopf}\{#AppName}.Update"

[UninstallRun]
; A running copy would keep its files from being removed.
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM {#AppExe}"; Flags: runhidden; RunOnceId: "StopSecReview"
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM {#CliExe}"; Flags: runhidden; RunOnceId: "StopSecReviewCli"

[Code]
// SecReview goes into Program Files and nowhere else: the administrator checks start a helper
// from the install folder with administrator rights, so it must be a folder ordinary users
// cannot write to. /DIR on the command line could point anywhere; this refuses it.
function InProgramFiles(): Boolean;
begin
  Result := CompareText(RemoveBackslashUnlessRoot(WizardDirValue), ExpandConstant('{autopf}\{#AppName}')) = 0;
end;

// Before anything is changed: the folder is checked, then running copies of SecReview are
// ended so their files can be replaced (the window and the notification-area icon of every
// signed-in user). SecReview writes its own files in one step, so being ended loses nothing.
// Nothing running is not an error.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  if not InProgramFiles() then
  begin
    Result := '{#AppName} can only be installed in ' + ExpandConstant('{autopf}\{#AppName}') + '. Start setup again without /DIR.';
    Exit;
  end;

  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#AppExe}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#CliExe}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := '';
end;

// Removes what an earlier version installed, except the uninstaller and its records, so a
// file this version no longer has does not stay behind (an old DLL next to the programs
// could still be loaded). Only ever in SecReview's own folder in Program Files.
procedure RemoveEarlierFiles();
var
  Found: TFindRec;
  Path: String;
begin
  if not InProgramFiles() then
    Exit;

  if FindFirst(ExpandConstant('{app}\*'), Found) then
  begin
    try
      repeat
        if (Found.Name <> '.') and (Found.Name <> '..') and (Pos('unins', Lowercase(Found.Name)) <> 1) then
        begin
          Path := ExpandConstant('{app}\') + Found.Name;
          if (Found.Attributes and FILE_ATTRIBUTE_DIRECTORY) <> 0 then
            DelTree(Path, True, True, True)
          else
            DeleteFile(Path);
        end;
      until not FindNext(Found);
    finally
      FindClose(Found);
    end;
  end;
end;

// Whether SecReview's own update asked for the window to be opened again (/RELAUNCH=1).
function RelaunchAsked(): Boolean;
begin
  Result := ExpandConstant('{param:RELAUNCH|0}') = '1';
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
    RemoveEarlierFiles();
end;
