# -*- mode: python ; coding: utf-8 -*-
# Rodar a partir de windows/: pyinstaller mandacaru-win.spec --noconfirm
from PyInstaller.utils.hooks import collect_data_files

a = Analysis(
    ["src/mandacaru_win/__main__.py"],
    pathex=["src"],
    datas=collect_data_files("mandacaru") + collect_data_files("mandacaru_win"),  # regras YARA, modelos, ícone
    excludes=["psutil", "watchdog", "tkinter"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Mandacaru",
    console=False,
    icon="assets/mandacaru.ico",
)
coll = COLLECT(exe, a.binaries, a.datas, name="Mandacaru")
