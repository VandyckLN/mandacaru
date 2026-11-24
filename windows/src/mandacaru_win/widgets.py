"""Componentes visuais leves do Mandacaru (PySide6).

Mantém a mesma interface dos widgets padrão do Qt, sem timers ativos em repouso
para não impactar a velocidade de varredura nem o consumo de CPU.
"""
from __future__ import annotations

import math
import time
from typing import Callable

from PySide6.QtCore import QRectF, QSize, Qt, QTimer
from PySide6.QtGui import QColor, QFontMetrics, QLinearGradient, QPainter, QPainterPath, QPalette, QPen
from PySide6.QtWidgets import QProgressBar, QStyle, QStyledItemDelegate, QStyleOptionViewItem

from mandacaru_win.progress import eta_text

# Paleta alinhada à identidade do Mandacaru (mandacaru.svg), como paradas de gradiente
# espalhadas por igual da esquerda para a direita da barra inteira:
# - normal: verde do cacto, do quase preto ao verde-claro
#   (CSS: linear-gradient(90deg, #001000, #004D00, #3F8F3A, #70C06A, #E1FFDE))
# - shred: terracota/vermelho (destruição definitiva)
# - warning: dourado dos óculos (interrompido / atenção)
# - error: vermelho escuro (falha)
_TONES: dict[str, tuple[str, ...]] = {
    "normal": ("#001000", "#004D00", "#3F8F3A", "#70C06A", "#E1FFDE"),
    "shred": ("#b71c1c", "#e65100"),
    "warning": ("#c49022", "#e8b948"),
    "error": ("#9a1b1b", "#d32f2f"),
}

TEXT_LIGHT = QColor("#ffffff")  # sobre o preenchimento escuro
TEXT_DARK = QColor("#000000")  # sobre o preenchimento claro; preto garante >= 4,5:1 em qualquer fundo


def _luminance(c: QColor) -> float:
    """Luminância relativa (WCAG 2)."""
    def ch(v: float) -> float:
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    return 0.2126 * ch(c.redF()) + 0.7152 * ch(c.greenF()) + 0.0722 * ch(c.blueF())


def contrast(a: QColor, b: QColor) -> float:
    la, lb = sorted((_luminance(a), _luminance(b)))
    return (lb + 0.05) / (la + 0.05)


def gradient_color(stops: tuple[str, ...], t: float) -> QColor:
    """Cor do gradiente na posição t (0..1), interpolada como o QLinearGradient faz."""
    if len(stops) == 1:
        return QColor(stops[0])
    t = min(max(t, 0.0), 1.0) * (len(stops) - 1)
    i = min(int(t), len(stops) - 2)
    f = t - i
    a, b = QColor(stops[i]), QColor(stops[i + 1])
    return QColor.fromRgbF(*(x + (y - x) * f for x, y in zip(a.getRgbF()[:3], b.getRgbF()[:3], strict=True)))


def _dark_text_spans(stops: tuple[str, ...], samples: int = 200) -> list[tuple[float, float]]:
    """Trechos (t0, t1) do gradiente onde o texto escuro contrasta mais que o branco."""
    spans: list[tuple[float, float]] = []
    start = None
    for k in range(samples + 1):
        t = k / samples
        c = gradient_color(stops, t)
        dark = contrast(TEXT_DARK, c) > contrast(TEXT_LIGHT, c)
        if dark and start is None:
            start = t
        elif not dark and start is not None:
            spans.append((start, t))
            start = None
    if start is not None:
        spans.append((start, 1.0))
    return spans


_DARK_SPANS = {tone: _dark_text_spans(stops) for tone, stops in _TONES.items()}


class MandacaruProgressBar(QProgressBar):
    """Barra de progresso personalizada em pílula com animação leve no modo indeterminado.

    Mostra uma frase inteira (set_caption) em vez de só "42%", em dois tons: escura sobre o
    trilho e branca sobre o preenchimento. Sem frase, volta ao "42%" de antes.
    """

    def __init__(self, parent=None, *, height: int = 18, show_text: bool = True,
                 clock: Callable[[], float] = time.monotonic):
        super().__init__(parent)
        self._tone = "normal"
        self._show_text = show_text
        self._caption = ""
        self._clock = clock
        self._started: float | None = None
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.setInterval(33)  # ~30 FPS apenas enquanto indeterminada e visível
        self._timer.timeout.connect(self._tick)
        self.setFixedHeight(height)
        self.setTextVisible(show_text)

    @property
    def tone(self) -> str:
        return self._tone

    def set_tone(self, tone: str) -> None:
        if tone not in _TONES:
            tone = "normal"
        if tone != self._tone:
            self._tone = tone
            self.update()

    def set_caption(self, text: str) -> None:
        """Frase dentro da barra; vazio volta ao "42%" padrão."""
        if text != self._caption:
            self._caption = text
            self.update()

    def caption(self) -> str:
        return self._caption

    def text(self) -> str:
        # É o que leitores de tela anunciam. Não usamos setFormat(): ele interpreta %p/%v/%m,
        # e a frase pode trazer nomes de arquivos e programas.
        return self._caption or super().text()

    def start_clock(self) -> None:
        """Marca o início para estimar o tempo restante (eta)."""
        self._started = self._clock()

    def eta(self) -> str:
        if self._started is None:
            return ""
        return eta_text(self._clock() - self._started, self.value() - self.minimum(),
                        self.maximum() - self.minimum())

    def is_indeterminate(self) -> bool:
        return self.minimum() == 0 and self.maximum() == 0

    def _sync_timer(self) -> None:
        should_run = self.is_indeterminate() and self.isVisible()
        if should_run and not self._timer.isActive():
            self._timer.start()
        elif not should_run and self._timer.isActive():
            self._timer.stop()

    def _tick(self) -> None:
        self._phase = (self._phase + 0.045) % 2.0
        self.update()

    def setRange(self, minimum: int, maximum: int) -> None:  # noqa: N802 - API Qt
        super().setRange(minimum, maximum)
        self._sync_timer()

    def setMinimum(self, minimum: int) -> None:  # noqa: N802
        super().setMinimum(minimum)
        self._sync_timer()

    def setMaximum(self, maximum: int) -> None:  # noqa: N802
        super().setMaximum(maximum)
        self._sync_timer()

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self._sync_timer()

    def hideEvent(self, event) -> None:  # noqa: N802
        super().hideEvent(event)
        self._sync_timer()

    def paintEvent(self, event) -> None:  # noqa: N802
        w, h = self.width(), self.height()
        if w <= 2 or h <= 2:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        # Detecta tema claro/escuro pela paleta da janela (sem depender de API específica do OS).
        win_bg = self.palette().color(QPalette.ColorRole.Window)
        dark = win_bg.lightness() < 128
        track_color = QColor("#2a2f2b") if dark else QColor("#e5ebe6")
        border_color = QColor("#3d4640") if dark else QColor("#c6d3c8")

        rect = QRectF(0.5, 0.5, w - 1.0, h - 1.0)
        radius = rect.height() / 2.0

        # Trilho de fundo
        painter.setPen(QPen(border_color, 1.0))
        painter.setBrush(track_color)
        painter.drawRoundedRect(rect, radius, radius)

        # Recorte interno para o preenchimento acompanhar as bordas arredondadas
        inner = rect.adjusted(1.0, 1.0, -1.0, -1.0)
        clip = QPainterPath()
        clip.addRoundedRect(inner, inner.height() / 2.0, inner.height() / 2.0)
        painter.setClipPath(clip)

        stops = _TONES.get(self._tone, _TONES["normal"])
        # O gradiente é ancorado na barra inteira: cheia, ela mostra todas as paradas;
        # no meio do caminho, a ponta tem a cor daquela posição (nunca some no trilho).
        grad = QLinearGradient(inner.topLeft(), inner.topRight())
        for k, c in enumerate(stops):
            grad.setColorAt(k / max(len(stops) - 1, 1), QColor(c))
        ratio = 0.0
        filled = QRectF()  # onde o texto troca de cor conforme o preenchimento

        if self.is_indeterminate():
            seg_w = max(inner.width() * 0.28, 36.0)
            # Movimento suave vai-e-volta com seno (sem salto brusco nas bordas)
            pos = 0.5 - 0.5 * math.cos(self._phase * math.pi)
            x0 = inner.left() + pos * (inner.width() - seg_w)
            seg = QRectF(x0, inner.top(), seg_w, inner.height())
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(grad)
            painter.drawRoundedRect(seg, inner.height() / 2.0, inner.height() / 2.0)
            filled = seg
        else:
            span = self.maximum() - self.minimum()
            if span > 0 and self.value() > self.minimum():
                ratio = max(0.0, min(1.0, (self.value() - self.minimum()) / span))
                fill_w = max(inner.width() * ratio, inner.height())
                fill = QRectF(inner.left(), inner.top(), min(fill_w, inner.width()), inner.height())
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(grad)
                painter.drawRoundedRect(fill, inner.height() / 2.0, inner.height() / 2.0)
                filled = fill

        painter.setClipping(False)

        text = ""
        if self._show_text:
            pct = int(round(ratio * 100))
            text = self._caption or (f"{pct}%" if pct > 0 and not self.is_indeterminate() else "")
        if text:
            font = painter.font()
            font.setPointSize(max(font.pointSize() - 1, 8))
            font.setBold(True)
            painter.setFont(font)
            text = QFontMetrics(font).elidedText(text, Qt.TextElideMode.ElideRight,
                                                 int(inner.width() - inner.height()))
            # A frase atravessa trilho e preenchimento, e o preenchimento vai do quase
            # preto ao verde-claro: cada trecho ganha a cor que mais contrasta com o fundo.
            painter.setPen(QColor("#e0e6e1") if dark else QColor("#243326"))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, text)
            if not filled.isEmpty():
                painter.setClipRect(filled)
                painter.setPen(TEXT_LIGHT)
                painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, text)
                for t0, t1 in _DARK_SPANS.get(self._tone, ()):
                    span = QRectF(inner.left() + t0 * inner.width(), rect.top(),
                                  (t1 - t0) * inner.width(), rect.height()).intersected(filled)
                    if not span.isEmpty():
                        painter.setClipRect(span)
                        painter.setPen(TEXT_DARK)
                        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, text)
                painter.setClipping(False)

        painter.end()


# Cores de pílula suave: (fundo_rgba, borda_rgba, texto_hex) para claro e escuro.
_BADGE_LIGHT: dict[str, tuple[tuple[int, int, int, int], tuple[int, int, int, int], str]] = {
    "Crítica": ((183, 28, 28, 34), (183, 28, 28, 82), "#a51818"),
    "Explorada": ((183, 28, 28, 34), (183, 28, 28, 82), "#a51818"),
    "Explorada (produto)": ((183, 28, 28, 34), (183, 28, 28, 82), "#a51818"),
    "Alta": ((230, 81, 0, 34), (230, 81, 0, 82), "#bf4300"),
    "Média": ((212, 167, 58, 48), (196, 144, 34, 96), "#8a6100"),
    "Suspeita": ((106, 27, 154, 34), (106, 27, 154, 82), "#6a1b9a"),
    "Baixa": ((21, 101, 192, 34), (21, 101, 192, 82), "#1565c0"),
    "Info": ((97, 97, 97, 30), (97, 97, 97, 70), "#4e5550"),
}
_BADGE_DARK: dict[str, tuple[tuple[int, int, int, int], tuple[int, int, int, int], str]] = {
    "Crítica": ((239, 83, 80, 52), (239, 83, 80, 112), "#ff8a80"),
    "Explorada": ((239, 83, 80, 52), (239, 83, 80, 112), "#ff8a80"),
    "Explorada (produto)": ((239, 83, 80, 52), (239, 83, 80, 112), "#ff8a80"),
    "Alta": ((255, 167, 38, 52), (255, 167, 38, 112), "#ffb74d"),
    "Média": ((255, 213, 79, 46), (255, 213, 79, 104), "#ffd54f"),
    "Suspeita": ((186, 104, 200, 52), (186, 104, 200, 112), "#ce93d8"),
    "Baixa": ((66, 165, 245, 52), (66, 165, 245, 112), "#90caf9"),
    "Info": ((189, 189, 189, 40), (189, 189, 189, 86), "#cfd6d1"),
}


class BadgeDelegate(QStyledItemDelegate):
    """Renderiza severidades/riscos como pílulas suaves sem criar widgets extras por linha."""

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index) -> None:
        text = str(index.data(Qt.ItemDataRole.DisplayRole) or "").strip()
        if not text:
            super().paint(painter, option, index)
            return

        # Mantém destaque nativo de seleção da linha sem sobrescrever com texto duplicado.
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        opt.text = ""
        style = opt.widget.style() if opt.widget else None
        if style is not None:
            style.drawControl(QStyle.ControlElement.CE_ItemViewItem, opt, painter, opt.widget)

        dark = option.palette.color(QPalette.ColorRole.Base).lightness() < 128
        table = _BADGE_DARK if dark else _BADGE_LIGHT
        bg_rgba, bd_rgba, fg_hex = table.get(text, table["Info"])

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        font = painter.font()
        font.setPointSize(max(font.pointSize() - 1, 8))
        font.setBold(True)
        painter.setFont(font)

        fm = painter.fontMetrics()
        pill_w = min(fm.horizontalAdvance(text) + 18, max(option.rect.width() - 8, 24))
        pill_h = min(fm.height() + 6, max(option.rect.height() - 4, 16))
        x = option.rect.x() + 4
        y = option.rect.y() + (option.rect.height() - pill_h) / 2.0
        pill = QRectF(x, y, pill_w, pill_h)
        radius = pill_h / 2.0

        painter.setPen(QPen(QColor(*bd_rgba), 1.0))
        painter.setBrush(QColor(*bg_rgba))
        painter.drawRoundedRect(pill, radius, radius)

        painter.setPen(QColor(fg_hex))
        elided = fm.elidedText(text, Qt.TextElideMode.ElideRight, int(pill_w) - 10)
        painter.drawText(pill, Qt.AlignmentFlag.AlignCenter, elided)
        painter.restore()

    def sizeHint(self, option: QStyleOptionViewItem, index) -> QSize:
        base = super().sizeHint(option, index)
        text = str(index.data(Qt.ItemDataRole.DisplayRole) or "").strip()
        if not text:
            return base
        font = option.font
        font.setBold(True)
        w = option.fontMetrics.horizontalAdvance(text) + 28
        return QSize(max(base.width(), w), max(base.height(), 26))
