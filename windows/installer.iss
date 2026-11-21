; Compilar a partir de windows/: iscc /DMyAppVersion=0.5.0 installer.iss
#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif

[Setup]
AppId={{4BD6D780-A6BE-4442-846C-08744EAC3233}
AppName=Mandacaru
AppVersion={#MyAppVersion}
AppPublisher=Vandyck Diniz
PrivilegesRequired=lowest
DefaultDirName={localappdata}\Programs\Mandacaru
DisableProgramGroupPage=yes
OutputDir=dist\installer
OutputBaseFilename=Mandacaru-{#MyAppVersion}-setup
LicenseFile=..\LICENSE
UninstallDisplayIcon={app}\Mandacaru.exe
Compression=lzma2
SolidCompression=yes

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Files]
Source: "dist\Mandacaru\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{userprograms}\Mandacaru"; Filename: "{app}\Mandacaru.exe"

[Run]
Filename: "{app}\Mandacaru.exe"; Description: "{cm:LaunchProgram,Mandacaru}"; Flags: nowait postinstall skipifsilent

; Desinstalar não remove %LOCALAPPDATA%\Mandacaru (dados do usuário).
