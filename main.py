"""
SentinelAV Security Suite - Ponto de Entrada Principal para Windows
Suporta:
- Interface gráfica de detecção de ameaças, quarentena e atualização online (sem argumentos)
- Verificação direta pelo menu de contexto do botão direito do Windows Explorer (--scan "<caminho>")
- Inicialização minimizada na bandeja do sistema (--minimized)
- Registro automático de integração com o Windows (--register-windows)
"""

from __future__ import annotations
import os
import sys
import ctypes


def _set_windows_app_id():
    """Garante que a barra de tarefas do Windows 10/11 exiba o ícone oficial do escudo do SentinelAV."""
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SentinelAV.SecuritySuite.1.0")
    except Exception:
        pass


def main():
    _set_windows_app_id()
    args = sys.argv[1:]

    if "--silent-update" in args:
        from core.database import ThreatDatabase
        from core.updater import ThreatUpdater

        db = ThreatDatabase()
        updater = ThreatUpdater(db)
        updater.run_silent_background_update()
        return

    if "--register-windows" in args:
        from core.win_integration import (
            register_explorer_context_menu,
            register_windows_startup,
            register_weekly_update_task,
            create_windows_shortcuts,
            get_app_executable_and_icon,
        )

        register_explorer_context_menu()
        register_windows_startup(enable=True)
        register_weekly_update_task(enable=True)
        base_dir = os.path.dirname(os.path.abspath(__file__))
        _, ico_path = get_app_executable_and_icon()
        target_bin = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)
        create_windows_shortcuts(target_bin, ico_path, base_dir)
        return

    scan_target = None
    if "--scan" in args:
        idx = args.index("--scan")
        if idx + 1 < len(args):
            scan_target = args[idx + 1]

    start_minimized = "--minimized" in args

    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtGui import QIcon
    from ui.main_window import SentinelMainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("SentinelAV")
    app.setOrganizationName("SentinelAV Security")

    base_dir = os.path.dirname(os.path.abspath(__file__))
    ico_path = os.path.join(base_dir, "assets", "shield.ico")
    if os.path.exists(ico_path):
        app.setWindowIcon(QIcon(ico_path))

    win = SentinelMainWindow(initial_scan_path=scan_target, start_minimized=start_minimized)
    if not start_minimized:
        win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
