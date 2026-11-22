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
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
DefaultDirName={localappdata}\Programs\Mandacaru
DisableProgramGroupPage=yes
OutputDir=dist\installer
OutputBaseFilename=Mandacaru-{#MyAppVersion}-setup
LicenseFile=..\LICENSE
UninstallDisplayIcon={app}\Mandacaru.exe
SetupIconFile=assets\mandacaru.ico
Compression=lzma2
SolidCompression=yes

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[InstallDelete]
Type: filesandordirs; Name: "{app}\_internal"

[Files]
Source: "dist\Mandacaru\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{userprograms}\Mandacaru"; Filename: "{app}\Mandacaru.exe"; AppUserModelID: "VandyckLN.Mandacaru"
Name: "{userdesktop}\Mandacaru"; Filename: "{app}\Mandacaru.exe"; AppUserModelID: "VandyckLN.Mandacaru"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Run]
Filename: "{app}\Mandacaru.exe"; Description: "{cm:LaunchProgram,Mandacaru}"; Flags: nowait postinstall skipifsilent
; Autoatualização: o app roda o setup com /VERYSILENT /ATUALIZACAO e fecha; aqui ele reabre.
; Uma instalação silenciosa comum (sem /ATUALIZACAO) continua sem abrir o app.
Filename: "{app}\Mandacaru.exe"; Flags: nowait; Check: EhAtualizacao

; Desinstalar não remove %LOCALAPPDATA%\Mandacaru (dados do usuário).

[Code]
// /ATUALIZACAO é parâmetro nosso (o Inno Setup ignora parâmetros que não conhece).
function EhAtualizacao: Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), '/ATUALIZACAO') = 0 then
      Result := True;
end;
