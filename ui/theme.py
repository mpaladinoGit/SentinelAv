"""
SentinelAV - Tema Visual Cybersecurity Dark (Windows 11 Security Style)
"""

SECURITY_DARK_STYLE = """
QMainWindow, QDialog {
    background-color: #0b1120;
    color: #f1f5f9;
    font-family: "Segoe UI", sans-serif;
    font-size: 13px;
}
QWidget {
    color: #f1f5f9;
    font-family: "Segoe UI", sans-serif;
}
QTabWidget::pane {
    border: 1px solid #1e293b;
    background-color: #0f172a;
    border-radius: 8px;
}
QTabBar::tab {
    background-color: #1e293b;
    color: #94a3b8;
    padding: 9px 18px;
    margin-right: 4px;
    border-top-left-radius: 7px;
    border-top-right-radius: 7px;
    font-weight: 600;
    font-size: 13px;
}
QTabBar::tab:selected {
    background-color: #059669;
    color: #ffffff;
}
QTabBar::tab:hover:!selected {
    background-color: #334155;
    color: #f8fafc;
}
QPushButton {
    background-color: #059669;
    color: #ffffff;
    border: none;
    border-radius: 7px;
    padding: 9px 16px;
    font-weight: 600;
    font-size: 13px;
}
QPushButton:hover {
    background-color: #047857;
}
QPushButton:disabled {
    background-color: #1e293b;
    color: #64748b;
}
QPushButton#actionCardBtn {
    background-color: #1e293b;
    border: 1px solid #334155;
    color: #f8fafc;
    padding: 12px 16px;
    font-size: 13.5px;
    font-weight: 700;
    text-align: left;
}
QPushButton#actionCardBtn:hover {
    background-color: #334155;
    border: 1px solid #10b981;
}
QPushButton#dangerBtn {
    background-color: #dc2626;
    color: #ffffff;
}
QPushButton#dangerBtn:hover {
    background-color: #b91c1c;
}
QPushButton#secondaryBtn {
    background-color: #334155;
    color: #e2e8f0;
}
QPushButton#secondaryBtn:hover {
    background-color: #475569;
}
QPushButton#blueBtn {
    background-color: #2563eb;
    color: #ffffff;
}
QPushButton#blueBtn:hover {
    background-color: #1d4ed8;
}
QTableWidget {
    background-color: #0f172a;
    alternate-background-color: #1e293b;
    color: #f1f5f9;
    border: 1px solid #334155;
    border-radius: 7px;
    gridline-color: #1e293b;
    selection-background-color: #2563eb;
    selection-color: #ffffff;
}
QHeaderView::section {
    background-color: #1e293b;
    color: #93c5fd;
    font-weight: 700;
    padding: 7px 10px;
    border: none;
    border-bottom: 1px solid #334155;
}
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox {
    background-color: #1e293b;
    color: #f8fafc;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 6px 10px;
}
QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
    border: 1px solid #10b981;
}
QProgressBar {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 6px;
    text-align: center;
    color: #ffffff;
    font-weight: 700;
    min-height: 22px;
}
QProgressBar::chunk {
    background-color: #10b981;
    border-radius: 5px;
}
QStatusBar {
    background-color: #0f172a;
    color: #94a3b8;
    border-top: 1px solid #1e293b;
}
QCheckBox {
    spacing: 8px;
    color: #e2e8f0;
    font-weight: 500;
}
"""
