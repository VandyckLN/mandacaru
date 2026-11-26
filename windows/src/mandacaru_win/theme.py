"""Estilos e paleta visual do Mandacaru (adapta-se ao tema claro/escuro do Windows)."""
from __future__ import annotations

from PySide6.QtGui import QPalette
from PySide6.QtWidgets import QPushButton, QWidget


def is_dark_palette(widget: QWidget) -> bool:
    """Detecta modo escuro pela luminosidade da cor de fundo da janela."""
    return widget.palette().color(QPalette.ColorRole.Window).lightness() < 128


def style_button(btn: QPushButton, role: str = "neutral", *, compact: bool = False) -> QPushButton:
    """Marca o papel visual do botão (`scan`, `analyze`, `quarantine`, `danger`, `neutral`)."""
    btn.setProperty("role", role)
    if compact:
        btn.setProperty("compact", "true")
    return btn


def build_stylesheet(dark: bool) -> str:
    """Gera QSS enxuto para botões por função, abas, tabelas e faixa de atualização."""
    if dark:
        neutral_bg, neutral_border, neutral_text, neutral_hover = "#2c332e", "#434f47", "#e6ece7", "#364039"
        dis_bg, dis_border, dis_text = "#242826", "#313733", "#6f7872"
        tab_bg, tab_sel_bg, tab_text, tab_sel_text = "#232825", "#2d342f", "#adb8b0", "#f1f5f2"
        border = "#38413b"
        hdr_bg, hdr_text = "#252b27", "#c7d1ca"
        upd_bg, upd_border, upd_text = "#1c3322", "#3b7a44", "#c8e6c9"
        proj_bg, proj_border, proj_text = "#361b1b", "#8c3232", "#ffcdd2"
        card_bg, muted_text = "#242a26", "#9fb0a3"
        input_bg, input_text = "#1b201d", "#edf2ee"
        chip_bg, chip_hover = "#2b322d", "#353f38"
    else:
        neutral_bg, neutral_border, neutral_text, neutral_hover = "#eef3ef", "#ccd6ce", "#1f2a22", "#e1eae3"
        dis_bg, dis_border, dis_text = "#e7ebe8", "#d5dcd7", "#949f97"
        tab_bg, tab_sel_bg, tab_text, tab_sel_text = "#eef2ef", "#ffffff", "#4a574d", "#1b2a1e"
        border = "#d0dad2"
        hdr_bg, hdr_text = "#f3f6f4", "#334236"
        upd_bg, upd_border, upd_text = "#e8f5e9", "#81c784", "#1b5e20"
        proj_bg, proj_border, proj_text = "#fdecea", "#e57373", "#7f1d1d"
        card_bg, muted_text = "#f7faf7", "#536357"
        input_bg, input_text = "#ffffff", "#1b261d"
        chip_bg, chip_hover = "#ebf0ec", "#dde7df"

    return f"""
QPushButton {{
    background: {neutral_bg};
    color: {neutral_text};
    border: 1px solid {neutral_border};
    border-radius: 7px;
    padding: 6px 14px;
    font-weight: 600;
}}
QPushButton:hover {{ background: {neutral_hover}; }}
QPushButton:pressed {{ padding-top: 7px; padding-bottom: 5px; }}

QPushButton[compact="true"] {{
    border-radius: 6px;
    padding: 3px 9px;
    font-size: 12px;
    font-weight: 600;
}}

QPushButton[role="scan"] {{
    background: #2e7d32;
    color: #ffffff;
    border: 1px solid #256628;
}}
QPushButton[role="scan"]:hover {{ background: #266b2a; }}
QPushButton[role="scan"]:pressed {{ background: #1e5621; }}

QPushButton[role="analyze"] {{
    background: #1565c0;
    color: #ffffff;
    border: 1px solid #10529e;
}}
QPushButton[role="analyze"]:hover {{ background: #1156a6; }}
QPushButton[role="analyze"]:pressed {{ background: #0d478a; }}

QPushButton[role="quarantine"] {{
    background: #e65100;
    color: #ffffff;
    border: 1px solid #c94600;
}}
QPushButton[role="quarantine"]:hover {{ background: #cf4800; }}
QPushButton[role="quarantine"]:pressed {{ background: #b33e00; }}

QPushButton[role="danger"] {{
    background: #c62828;
    color: #ffffff;
    border: 1px solid #a81f1f;
}}
QPushButton[role="danger"]:hover {{ background: #b02222; }}
QPushButton[role="danger"]:pressed {{ background: #8e1818; }}

QPushButton:disabled {{
    background: {dis_bg};
    color: {dis_text};
    border: 1px solid {dis_border};
}}

QTabWidget::pane {{
    border: 1px solid {border};
    border-radius: 6px;
    top: -1px;
}}
QTabBar::tab {{
    background: {tab_bg};
    color: {tab_text};
    border: 1px solid {border};
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    padding: 7px 14px;
    margin-right: 3px;
    font-weight: 600;
}}
QTabBar::tab:selected {{
    background: {tab_sel_bg};
    color: {tab_sel_text};
    border-bottom: 2px solid #3f8f3a;
}}

QHeaderView::section {{
    background: {hdr_bg};
    color: {hdr_text};
    border: none;
    border-bottom: 1px solid {border};
    padding: 6px 8px;
    font-weight: 600;
}}

QTreeWidget, QTableWidget {{
    border: 1px solid {border};
    border-radius: 6px;
}}
QTreeWidget::item, QTableWidget::item {{
    padding: 3px 4px;
}}

#faixaAtualizacao {{
    background: {upd_bg};
    border: 1px solid {upd_border};
    border-radius: 6px;
}}
#faixaAtualizacao QLabel {{
    color: {upd_text};
    font-weight: 600;
}}

#faixaProjetoAlerta {{
    background: {proj_bg};
    border: 1px solid {proj_border};
    border-radius: 6px;
}}
#faixaProjetoAlerta QLabel {{
    color: {proj_text};
    font-weight: 600;
}}

QFrame#settingsCard {{
    background: {card_bg};
    border: 1px solid {border};
    border-radius: 10px;
}}
QLabel#cardTitle {{
    font-size: 14px;
    font-weight: 700;
}}
QLabel#mutedLabel {{
    color: {muted_text};
    font-size: 12px;
}}
QLabel#cronBadge {{
    background: {chip_bg};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 3px 8px;
    font-family: Consolas, "Cascadia Mono", monospace;
    font-size: 12px;
    font-weight: 600;
}}
QPushButton[role="chip"] {{
    background: {chip_bg};
    color: {neutral_text};
    border: 1px solid {border};
    border-radius: 14px;
    padding: 5px 12px;
    font-size: 12px;
    font-weight: 600;
}}
QPushButton[role="chip"]:hover {{
    background: {chip_hover};
}}
QPushButton[role="chip"]:checked {{
    background: #2e7d32;
    color: #ffffff;
    border: 1px solid #256628;
}}
QLineEdit, QTimeEdit {{
    background: {input_bg};
    color: {input_text};
    border: 1px solid {border};
    border-radius: 6px;
    padding: 5px 9px;
}}
QLineEdit:focus, QTimeEdit:focus {{
    border: 1px solid #3f8f3a;
}}
QCheckBox {{
    spacing: 8px;
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border-radius: 4px;
    border: 1px solid {border};
    background: {input_bg};
}}
QCheckBox::indicator:checked {{
    background: #2e7d32;
    border: 1px solid #256628;
}}
QScrollArea#settingsScroll {{
    border: none;
    background: transparent;
}}
"""
