# Mandacaru para Windows

Interface gráfica (PySide6) do Mandacaru para Windows. Reaproveita o núcleo de
detecção do pacote `mandacaru-edr`.

## Instalar (usuário)

Passo a passo (inclusive a linha única para `Windows + R`) no
[README principal](../README.md#windows-aplicativo-com-janela). Não precisa de
administrador: instala em `%LOCALAPPDATA%\Programs\Mandacaru` e cria atalhos na
Área de Trabalho e no Menu Iniciar. Instalação silenciosa:
`Mandacaru-<versão>-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART`. Desinstalar não apaga `%LOCALAPPDATA%\Mandacaru`
(histórico, quarentena e exceções).

## Montar (desenvolvedor)

Na raiz do repositório, em um Python 3.10–3.13 no Windows:

```powershell
pip install . "./windows[dev]"
cd windows
python -m pytest -q
pyinstaller mandacaru-win.spec --noconfirm   # gera dist\Mandacaru\
dist\Mandacaru\Mandacaru.exe --selftest       # código de saída 0 = ok
iscc /DMyAppVersion=0.6.1 installer.iss       # gera dist\installer\ (requer Inno Setup)
```

O CI (`.github/workflows/windows.yml`) faz o mesmo e, em tags `v*`, anexa o
instalador ao release criado pelo `release.yml`.
