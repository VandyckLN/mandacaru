# Mandacaru para Windows

Interface gráfica (PySide6) do Mandacaru para Windows. Reaproveita o núcleo de
detecção do pacote `mandacaru-edr`.

## Instalar (usuário)

Baixe `Mandacaru-<versão>-setup.exe` na página de Releases e execute. Não
precisa de administrador: instala em `%LOCALAPPDATA%\Programs\Mandacaru` e cria
um atalho no Menu Iniciar. Desinstalar não apaga `%LOCALAPPDATA%\Mandacaru`
(histórico, quarentena e exceções).

## Montar (desenvolvedor)

Na raiz do repositório, em um Python 3.10+ no Windows:

```powershell
pip install . "./windows[dev]"
cd windows
python -m pytest -q
pyinstaller mandacaru-win.spec --noconfirm   # gera dist\Mandacaru\
dist\Mandacaru\Mandacaru.exe --selftest       # código de saída 0 = ok
iscc /DMyAppVersion=0.5.0 installer.iss       # gera dist\installer\ (requer Inno Setup)
```

O CI (`.github/workflows/windows.yml`) faz o mesmo e, em tags `v*`, anexa o
instalador ao release criado pelo `release.yml`.
