; Installer for Metsuki EXE Analyzer
; Compile via: ISCC.exe /DMyAppVersion="x.y.z" metsuki_installer.iss

#ifndef MyAppVersion
	#define MyAppVersion "0.1.0"
#endif

#ifndef SetupOutputBaseFilename
	#define SetupOutputBaseFilename "Metsuki_EXE_Analyzer_Setup_" + MyAppVersion
#endif

[Setup]
AppId={{B76B89E9-2011-4E12-A690-7A6EA46D2F02}
AppName=Metsuki EXE Analyzer
AppVersion={#MyAppVersion}
AppVerName=Metsuki EXE Analyzer {#MyAppVersion}
AppPublisher=Metsuki
DefaultDirName={autopf}\Metsuki EXE Analyzer
DefaultGroupName=Metsuki EXE Analyzer
UninstallDisplayIcon={app}\icon.ico
OutputDir=..\dist
OutputBaseFilename={#SetupOutputBaseFilename}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
WizardSizePercent=110
SetupIconFile=..\assets\icon.ico
WizardImageFile=..\installer\assets\wizard_large.bmp
WizardSmallImageFile=..\installer\assets\wizard_small.bmp
DisableDirPage=no
DisableProgramGroupPage=no
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
UsePreviousAppDir=yes
UsePreviousGroup=yes
UsePreviousTasks=yes
UsePreviousLanguage=yes
Uninstallable=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Types]
Name: "full"; Description: "{cm:SetupTypeFull}"
Name: "compact"; Description: "{cm:SetupTypeCompact}"

[Components]
Name: "main"; Description: "Core application files"; Types: full compact; Flags: fixed

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopIconTask}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "{cm:AutoStartTask}"; GroupDescription: "{cm:ExtraOptionsGroup}"; Flags: unchecked

[Dirs]
Name: "{app}\logs"

[Files]
; Always include app icon in installation directory for stable shortcut/uninstall icon display
Source: "..\assets\icon.ico"; DestDir: "{app}"; Flags: ignoreversion; Components: main
; Core binaries
Source: "..\dist\EXE_Analyzer\exe_tester_web_gui.exe"; DestDir: "{app}"; Flags: ignoreversion; Components: main
; Core engine (required!)
Source: "..\dist\EXE_Analyzer\.engine\analyzer_core.exe"; DestDir: "{app}\.engine"; Flags: ignoreversion; Components: main; Attribs: hidden
; Optional assets/helpers
Source: "..\dist\EXE_Analyzer\logo.png"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist; Components: main
Source: "..\dist\EXE_Analyzer\metsuki_logo.png"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist; Components: main

[Icons]
Name: "{group}\Metsuki EXE Analyzer"; Filename: "{app}\exe_tester_web_gui.exe"; IconFilename: "{app}\icon.ico"
Name: "{commondesktop}\Metsuki EXE Analyzer"; Filename: "{app}\exe_tester_web_gui.exe"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon

[Registry]
Root: HKA; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "Metsuki EXE Analyzer"; ValueData: """{app}\exe_tester_web_gui.exe"""; Flags: uninsdeletevalue; Tasks: autostart

[Run]
Filename: "{app}\exe_tester_web_gui.exe"; Description: "{cm:LaunchProgram,Metsuki EXE Analyzer}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{app}\exe_tester_web_gui.exe.WebView2"
Type: filesandordirs; Name: "{app}\EBWebView"

[CustomMessages]
english.DesktopIconTask=Create a desktop icon
russian.DesktopIconTask=Создать ярлык на рабочем столе
english.AutoStartTask=Launch Metsuki EXE Analyzer on Windows startup
russian.AutoStartTask=Запускать Metsuki EXE Analyzer при старте Windows
english.SetupTypeFull=Full installation (recommended)
russian.SetupTypeFull=Полная установка (рекомендуется)
english.SetupTypeCompact=Compact installation
russian.SetupTypeCompact=Компактная установка
english.ExtraOptionsGroup=Extra options:
russian.ExtraOptionsGroup=Дополнительные параметры:
