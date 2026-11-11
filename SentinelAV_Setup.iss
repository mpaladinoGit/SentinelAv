; Script Inno Setup para gerar o Instalador Oficial (Instalador_SentinelAV_Setup.exe)
[Setup]
AppId={{9A7C3E1D-4B2F-4D8A-8E5C-1F6B2D9E4A0C}
AppName=SentinelAV Security Suite
AppVersion=1.0.0
AppPublisher=SentinelAV Security
DefaultDirName={localappdata}\Programs\SentinelAV
DefaultGroupName=SentinelAV Security
DisableProgramGroupPage=yes
SetupIconFile=C:\Users\marco\projetos\Mypdf\SentinelAV\assets\shield.ico
UninstallDisplayIcon={app}\SentinelAV.exe
OutputDir=C:\Users\marco\projetos\Mypdf\SentinelAV
OutputBaseFilename=Instalador_SentinelAV_Setup
Compression=lzma2/fast
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "C:\Users\marco\projetos\Mypdf\SentinelAV\dist\SentinelAV\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "C:\Users\marco\projetos\Mypdf\SentinelAV\assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\SentinelAV Antivírus"; Filename: "{app}\SentinelAV.exe"; IconFilename: "{app}\assets\shield.ico"
Name: "{autodesktop}\SentinelAV Antivírus"; Filename: "{app}\SentinelAV.exe"; IconFilename: "{app}\assets\shield.ico"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Classes\*\shell\SentinelAV_Scan"; ValueType: string; ValueName: ""; ValueData: "Verificar ameaças com SentinelAV"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\*\shell\SentinelAV_Scan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\assets\shield.ico"""
Root: HKCU; Subkey: "Software\Classes\*\shell\SentinelAV_Scan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\SentinelAV.exe"" --scan ""%1"""
Root: HKCU; Subkey: "Software\Classes\Directory\shell\SentinelAV_Scan"; ValueType: string; ValueName: ""; ValueData: "Verificar pasta com SentinelAV"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\Directory\shell\SentinelAV_Scan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\assets\shield.ico"""
Root: HKCU; Subkey: "Software\Classes\Directory\shell\SentinelAV_Scan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\SentinelAV.exe"" --scan ""%1"""
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "SentinelAV"; ValueData: """{app}\SentinelAV.exe"" --minimized"; Flags: uninsdeletevalue

[Run]
Filename: "{app}\SentinelAV.exe"; Description: "Iniciar o SentinelAV Security agora"; Flags: nowait postinstall skipifsilent
