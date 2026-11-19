; ShadowProxy Inno Setup 脚本
#define MyAppName "ShadowProxy"
#define MyAppVersion "0.2.6"
#define MyAppPublisher "ShadowProxy Team"
#define MyAppURL "https://github.com/jnnmia/shadow-proxy"
#define MyAppExeName "bin\shadow-gui.exe"

[Setup]
AppId={{5E28B02F-8AC4-4C7E-9781-B1FF2579040D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={localappdata}\Programs\{#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=.
OutputBaseFilename=ShadowProxy-Setup-v{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
AppMutex=Global\ShadowProxy_App_Mutex_2026,ShadowProxy_App_Mutex_2026
CloseApplications=yes
RestartApplications=no
CloseApplicationsFilter=*.exe,*.dll
ShowLanguageDialog=auto

[Languages]
Name: "chinesesimplified"; MessagesFile: "compiler:Default.isl,ChineseSimplified.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
chinesesimplified.CreateDesktopIcon=创建桌面快捷方式(&D)
en.CreateDesktopIcon=Create a &desktop shortcut
chinesesimplified.AdditionalIcons=附加图标:
en.AdditionalIcons=Additional shortcuts:
chinesesimplified.LaunchProgram=启动 %1
en.LaunchProgram=Launch %1
chinesesimplified.UninstallProgram=卸载 %1
en.UninstallProgram=Uninstall %1

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "ShadowProxy\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs restartreplace

[UninstallDelete]
Type: files; Name: "{app}\bin\*.old*"

[Icons]
Name: "{autoprograms}\{#MyAppName}\{#MyAppName}"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\start-gui.vbs"""; WorkingDir: "{app}"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{autoprograms}\{#MyAppName}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\start-gui.vbs"""; WorkingDir: "{app}"; IconFilename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{sys}\wscript.exe"; Parameters: """{app}\start-gui.vbs"""; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
procedure KillRunningProcesses();
var
  TaskKillPath: String;
  ResultCode: Integer;
begin
  TaskKillPath := ExpandConstant('{sys}\taskkill.exe');
  Exec(TaskKillPath, '/f /t /im shadow-gui.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(TaskKillPath, '/f /t /im shadow-cli.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(TaskKillPath, '/f /t /im shadow-injector32.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(500);
end;

procedure CleanupOldBackupFiles(BinDir: String);
var
  FindRec: TFindRec;
begin
  if not DirExists(BinDir) then
    Exit;
  if FindFirst(BinDir + '\*.old*', FindRec) then
  begin
    try
      repeat
        if (FindRec.Attributes and FILE_ATTRIBUTE_DIRECTORY) = 0 then
          DeleteFile(BinDir + '\' + FindRec.Name);
      until not FindNext(FindRec);
    finally
      FindClose(FindRec);
    end;
  end;
end;

procedure MoveLockedFileAside(FilePath: String);
var
  BackupPath: String;
  Index: Integer;
begin
  if not FileExists(FilePath) then
    Exit;
  if DeleteFile(FilePath) then
    Exit;
  for Index := 1 to 20 do
  begin
    BackupPath := FilePath + '.old' + IntToStr(Index);
    if FileExists(BackupPath) then
      DeleteFile(BackupPath);
    if not FileExists(BackupPath) then
    begin
      if RenameFile(FilePath, BackupPath) then
        Exit;
    end;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  BinDir: String;
begin
  KillRunningProcesses();
  BinDir := ExpandConstant('{app}\bin');
  CleanupOldBackupFiles(BinDir);
  if DirExists(BinDir) then
  begin
    MoveLockedFileAside(BinDir + '\shadow-gui.exe');
    MoveLockedFileAside(BinDir + '\shadow-cli.exe');
    MoveLockedFileAside(BinDir + '\shadow-injector32.exe');
    MoveLockedFileAside(BinDir + '\WebView2Loader.dll');
    MoveLockedFileAside(BinDir + '\shadow_hook.dll');
    MoveLockedFileAside(BinDir + '\shadow_hook32.dll');
  end;
  Result := '';
end;

function InitializeUninstall(): Boolean;
begin
  KillRunningProcesses();
  Result := True;
end;
