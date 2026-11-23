"""Componentes visuais leves do Mandacaru (PySide6).

Mantém a mesma interface dos widgets padrão do Qt, sem timers ativos em repouso
para não impactar a velocidade de varredura nem o consumo de CPU.
"""
from __future__ import annotations

import math

from PySide6.QtCore import QRectF, QSize, Qt, QTimer
from PySide6.QtGui import QColor, QLinearGradient, QPainter, QPainterPath, QPalette, QPen
from PySide6.QtWidgets import QProgressBar, QStyle, QStyledItemDelegate, QStyleOptionViewItem

# Paleta alinhada à identidade do Mandacaru (mandacaru.svg):
# - normal: verde do cacto (#2c6b2c -> #4ca647)
# - shred: terracota/vermelho (destruição definitiva)
# - warning: dourado dos óculos (interrompido / atenção)
# - error: vermelho escuro (falha)
_TONES: dict[str, tuple[str, str]] = {
    "normal": ("#2c6b2c", "#52b34c"),
    "shred": ("#b71c1c", "#e65100"),
    "warning": ("#c49022", "#e8b948"),
    "error": ("#9a1b1b", "#d32f2f"),
}


class MandacaruProgressBar(QProgressBar):
    """Barra de progresso personalizada em pílula com animação leve no modo indeterminado."""

    def __init__(self, parent=None, *, height: int = 18, show_text: bool = True):
        super().__init__(parent)
        self._tone = "normal"
        self._show_text = show_text
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

        c1, c2 = _TONES.get(self._tone, _TONES["normal"])
        ratio = 0.0

        if self.is_indeterminate():
            seg_w = max(inner.width() * 0.28, 36.0)
            # Movimento suave vai-e-volta com seno (sem salto brusco nas bordas)
            pos = 0.5 - 0.5 * math.cos(self._phase * math.pi)
            x0 = inner.left() + pos * (inner.width() - seg_w)
            seg = QRectF(x0, inner.top(), seg_w, inner.height())
            grad = QLinearGradient(seg.topLeft(), seg.topRight())
            grad.setColorAt(0.0, QColor(c1))
            grad.setColorAt(0.5, QColor(c2))
            grad.setColorAt(1.0, QColor(c1))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(grad)
            painter.drawRoundedRect(seg, inner.height() / 2.0, inner.height() / 2.0)
        else:
            span = self.maximum() - self.minimum()
            if span > 0 and self.value() > self.minimum():
                ratio = max(0.0, min(1.0, (self.value() - self.minimum()) / span))
                fill_w = max(inner.width() * ratio, inner.height())
                fill = QRectF(inner.left(), inner.top(), min(fill_w, inner.width()), inner.height())
                grad = QLinearGradient(fill.topLeft(), fill.topRight())
                grad.setColorAt(0.0, QColor(c1))
                grad.setColorAt(1.0, QColor(c2))
                painter.setPen(Qt.PenStyle.NoPen)
                painter.setBrush(grad)
                painter.drawRoundedRect(fill, inner.height() / 2.0, inner.height() / 2.0)

        painter.setClipping(False)

        if self._show_text and not self.is_indeterminate():
            pct = int(round(ratio * 100))
            if pct > 0:
                font = painter.font()
                font.setPointSize(max(font.pointSize() - 1, 8))
                font.setBold(True)
                painter.setFont(font)
                # Texto claro quando a barra já passou do centro; cor do tema antes disso
                text_color = QColor("#ffffff") if ratio >= 0.52 else (
                    QColor("#e0e6e1") if dark else QColor("#243326")
                )
                painter.setPen(text_color)
                painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, f"{pct}%")

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
