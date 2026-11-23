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
Name: "contextmenu"; Description: "Adicionar ""Varrer com Mandacaru"" ao menu de contexto do Explorer"; GroupDescription: "Integração com o Windows:"

[Registry]
; Menu de contexto por usuário (HKCU — sem precisar de administrador) para arquivos, pastas e fundo de pasta.
Root: HKCU; Subkey: "Software\Classes\*\shell\MandacaruScan"; ValueType: string; ValueName: ""; ValueData: "Varrer com Mandacaru"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\*\shell\MandacaruScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\Mandacaru.exe"",0"; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\*\shell\MandacaruScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\Mandacaru.exe"" --scan ""%1"""; Tasks: contextmenu

Root: HKCU; Subkey: "Software\Classes\Directory\shell\MandacaruScan"; ValueType: string; ValueName: ""; ValueData: "Varrer com Mandacaru"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\Directory\shell\MandacaruScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\Mandacaru.exe"",0"; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\Directory\shell\MandacaruScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\Mandacaru.exe"" --scan ""%1"""; Tasks: contextmenu

Root: HKCU; Subkey: "Software\Classes\Directory\Background\shell\MandacaruScan"; ValueType: string; ValueName: ""; ValueData: "Varrer com Mandacaru"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\Directory\Background\shell\MandacaruScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\Mandacaru.exe"",0"; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\Directory\Background\shell\MandacaruScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\Mandacaru.exe"" --scan ""%V"""; Tasks: contextmenu

; Destruição definitiva (sobrescreve com dados aleatórios e apaga) só no clique direto em arquivo ou pasta (nunca no fundo de pasta).
Root: HKCU; Subkey: "Software\Classes\*\shell\MandacaruShred"; ValueType: string; ValueName: ""; ValueData: "Destruir definitivamente com Mandacaru"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\*\shell\MandacaruShred"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\Mandacaru.exe"",0"; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\*\shell\MandacaruShred\command"; ValueType: string; ValueName: ""; ValueData: """{app}\Mandacaru.exe"" --shred ""%1"""; Tasks: contextmenu

Root: HKCU; Subkey: "Software\Classes\Directory\shell\MandacaruShred"; ValueType: string; ValueName: ""; ValueData: "Destruir definitivamente com Mandacaru"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\Directory\shell\MandacaruShred"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\Mandacaru.exe"",0"; Tasks: contextmenu
Root: HKCU; Subkey: "Software\Classes\Directory\shell\MandacaruShred\command"; ValueType: string; ValueName: ""; ValueData: """{app}\Mandacaru.exe"" --shred ""%1"""; Tasks: contextmenu

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
