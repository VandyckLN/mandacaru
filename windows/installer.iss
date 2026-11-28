; Compilar a partir de windows/: iscc /DMyAppVersion=0.5.0 installer.iss
;
; Dois modos (o Inno Setup pergunta no início):
;  - "Só para mim" (padrão, sem administrador): {localappdata}\Programs\Mandacaru, como sempre.
;  - "Para todos os usuários" (pede UAC uma vez): Arquivos de Programas e, com a tarefa
;    "Proteção avançada", o serviço MandacaruGuard (o próprio Mandacaru.exe --guard-servico, como
;    SYSTEM). O serviço só roda de uma pasta só de administradores — por isso só existe neste modo.
#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif

[Setup]
AppId={{4BD6D780-A6BE-4442-846C-08744EAC3233}
AppName=Mandacaru
AppVersion={#MyAppVersion}
AppPublisher=Vandyck Diniz
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; {autopf} = {localappdata}\Programs no modo só para mim (o mesmo caminho de antes) e Arquivos de Programas no outro.
DefaultDirName={autopf}\Mandacaru
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
Name: "{autoprograms}\Mandacaru"; Filename: "{app}\Mandacaru.exe"; AppUserModelID: "VandyckLN.Mandacaru"
Name: "{autodesktop}\Mandacaru"; Filename: "{app}\Mandacaru.exe"; AppUserModelID: "VandyckLN.Mandacaru"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "contextmenu"; Description: "Adicionar ""Varrer com Mandacaru"" ao menu de contexto do Explorer"; GroupDescription: "Integração com o Windows:"
Name: "protecaoavancada"; Description: "Proteção avançada (serviço MandacaruGuard): bloquear a rede de um programa, encerrar processos de outros usuários e remover persistência do sistema, sempre com Desfazer"; GroupDescription: "Segurança:"; Check: IsAdminInstallMode

[Registry]
; Menu de contexto (HKA = HKCU no modo só para mim, HKLM no modo para todos) para arquivos, pastas e fundo de pasta.
Root: HKA; Subkey: "Software\Classes\*\shell\MandacaruScan"; ValueType: string; ValueName: ""; ValueData: "Varrer com Mandacaru"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\*\shell\MandacaruScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\Mandacaru.exe"",0"; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\*\shell\MandacaruScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\Mandacaru.exe"" --scan ""%1"""; Tasks: contextmenu

Root: HKA; Subkey: "Software\Classes\Directory\shell\MandacaruScan"; ValueType: string; ValueName: ""; ValueData: "Varrer com Mandacaru"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\shell\MandacaruScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\Mandacaru.exe"",0"; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\shell\MandacaruScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\Mandacaru.exe"" --scan ""%1"""; Tasks: contextmenu

Root: HKA; Subkey: "Software\Classes\Directory\Background\shell\MandacaruScan"; ValueType: string; ValueName: ""; ValueData: "Varrer com Mandacaru"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\Background\shell\MandacaruScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\Mandacaru.exe"",0"; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\Background\shell\MandacaruScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\Mandacaru.exe"" --scan ""%V"""; Tasks: contextmenu

; Destruição definitiva (sobrescreve com dados aleatórios e apaga) só no clique direto em arquivo ou pasta (nunca no fundo de pasta).
Root: HKA; Subkey: "Software\Classes\*\shell\MandacaruShred"; ValueType: string; ValueName: ""; ValueData: "Destruir definitivamente com Mandacaru"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\*\shell\MandacaruShred"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\Mandacaru.exe"",0"; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\*\shell\MandacaruShred\command"; ValueType: string; ValueName: ""; ValueData: """{app}\Mandacaru.exe"" --shred ""%1"""; Tasks: contextmenu

Root: HKA; Subkey: "Software\Classes\Directory\shell\MandacaruShred"; ValueType: string; ValueName: ""; ValueData: "Destruir definitivamente com Mandacaru"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\shell\MandacaruShred"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\Mandacaru.exe"",0"; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\shell\MandacaruShred\command"; ValueType: string; ValueName: ""; ValueData: """{app}\Mandacaru.exe"" --shred ""%1"""; Tasks: contextmenu

[Run]
; A janela nunca roda elevada: no modo para todos o setup é administrador, então abre como o usuário original.
Filename: "{app}\Mandacaru.exe"; Description: "{cm:LaunchProgram,Mandacaru}"; Flags: nowait postinstall skipifsilent runasoriginaluser
; Autoatualização: o app roda o setup com /VERYSILENT /ATUALIZACAO e fecha; aqui ele reabre.
; Uma instalação silenciosa comum (sem /ATUALIZACAO) continua sem abrir o app.
Filename: "{app}\Mandacaru.exe"; Flags: nowait runasoriginaluser; Check: EhAtualizacao

[UninstallRun]
; Proteção avançada: apaga as regras de firewall Mandacaru-*, para e remove o serviço (nesta ordem).
Filename: "{app}\Mandacaru.exe"; Parameters: "--guard-remover-regras"; Flags: runhidden waituntilterminated; RunOnceId: "GuardRegras"; Check: IsAdminInstallMode
Filename: "{sys}\net.exe"; Parameters: "stop MandacaruGuard"; Flags: runhidden waituntilterminated; RunOnceId: "GuardParar"; Check: IsAdminInstallMode
Filename: "{sys}\sc.exe"; Parameters: "delete MandacaruGuard"; Flags: runhidden waituntilterminated; RunOnceId: "GuardRemover"; Check: IsAdminInstallMode

[UninstallDelete]
; Quarentena, backups do Desfazer e log do serviço ficam na pasta do app (só administradores).
Type: filesandordirs; Name: "{app}\dados"
Type: files; Name: "{app}\guard.json"
Type: files; Name: "{app}\guard.log*"

; Desinstalar não remove %LOCALAPPDATA%\Mandacaru (dados do usuário).

[Code]
const
  NomeServico = 'MandacaruGuard';

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

procedure Executar(const Programa, Parametros: String);
var
  Codigo: Integer;
begin
  Exec(Programa, Parametros, '', SW_HIDE, ewWaitUntilTerminated, Codigo);
end;

procedure PararServico;
begin
  // net stop espera o serviço parar (sc stop não espera); sem serviço instalado, só falha calado.
  Executar(ExpandConstant('{sys}\net.exe'), 'stop ' + NomeServico);
end;

// Antes de copiar: o serviço usa o mesmo Mandacaru.exe e os mesmos arquivos de _internal.
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if IsAdminInstallMode then
    PararServico;
end;

function EscaparJson(const S: String): String;
begin
  Result := S;
  StringChangeEx(Result, '\', '\\', True);
  StringChangeEx(Result, '"', '\"', True);
end;

procedure InstalarGuard;
var
  Exe, BinPath, Sc: String;
begin
  Exe := ExpandConstant('{app}\Mandacaru.exe');
  Sc := ExpandConstant('{sys}\sc.exe');
  // Só a janela instalada nesta pasta (só administradores) pode falar com o serviço.
  SaveStringToFile(ExpandConstant('{app}\guard.json'), '{"clientes": ["' + EscaparJson(Exe) + '"]}', False);
  BinPath := '"\"' + Exe + '\" --guard-servico"';
  Executar(Sc, 'create ' + NomeServico + ' binPath= ' + BinPath + ' start= auto obj= LocalSystem DisplayName= "Mandacaru Proteção avançada"');
  Executar(Sc, 'config ' + NomeServico + ' binPath= ' + BinPath + ' start= auto obj= LocalSystem');
  Executar(Sc, 'description ' + NomeServico + ' "Executa só as ações privilegiadas pedidas pelo Mandacaru (lista fechada, com Desfazer)."');
  Executar(Sc, 'failure ' + NomeServico + ' reset= 86400 actions= restart/5000/restart/60000//');
  Executar(Sc, 'start ' + NomeServico);
end;

procedure RemoverGuard;
begin
  // Reinstalação sem a tarefa marcada: tira o serviço e as regras, como na desinstalação.
  Executar(ExpandConstant('{app}\Mandacaru.exe'), '--guard-remover-regras');
  PararServico;
  Executar(ExpandConstant('{sys}\sc.exe'), 'delete ' + NomeServico);
  DeleteFile(ExpandConstant('{app}\guard.json'));
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and IsAdminInstallMode then
  begin
    if WizardIsTaskSelected('protecaoavancada') then
      InstalarGuard
    else
      RemoverGuard;
  end;
end;
