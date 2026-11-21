"""Gera mandacaru.ico (exe/instalador) e o PNG da janela a partir dos SVGs desta pasta.

Rodar a partir de windows/: QT_QPA_PLATFORM=offscreen python assets/make_icon.py
Até 32 px usa mandacaru-small.svg (traço mais grosso, sem costelas), que fica nítido na barra de tarefas.
"""
import struct
import sys
from pathlib import Path

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QRectF, Qt
from PySide6.QtGui import QGuiApplication, QImage, QPainter
from PySide6.QtSvg import QSvgRenderer

HERE = Path(__file__).parent
SIZES = (16, 24, 32, 48, 64, 128, 256)


def render(svg: Path, size: int) -> bytes:
    img = QImage(size, size, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    QSvgRenderer(str(svg)).render(p, QRectF(0, 0, size, size))
    p.end()
    data = QByteArray()
    buf = QBuffer(data)
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    img.save(buf, "PNG")
    return bytes(data)


def ico(images: list[tuple[int, bytes]]) -> bytes:
    """ICO com entradas PNG (aceito pelo Windows Vista em diante)."""
    head = struct.pack("<HHH", 0, 1, len(images))
    offset = len(head) + 16 * len(images)
    entries, blobs = b"", b""
    for size, png in images:
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset)
        blobs += png
        offset += len(png)
    return head + entries + blobs


def main() -> None:
    QGuiApplication(sys.argv)
    imgs = [(s, render(HERE / ("mandacaru-small.svg" if s <= 32 else "mandacaru.svg"), s)) for s in SIZES]
    (HERE / "mandacaru.ico").write_bytes(ico(imgs))
    (HERE.parent / "src" / "mandacaru_win" / "assets" / "mandacaru.png").write_bytes(dict(imgs)[256])


if __name__ == "__main__":
    main()
