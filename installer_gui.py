"""
SentinelAV - Assistente Gráfico de Instalação para Windows (Setup Wizard)
Instala o SentinelAV em %LOCALAPPDATA%\\Programs\\SentinelAV,
cria atalhos na Área de Trabalho e no Menu Iniciar,
adiciona "Verificar ameaças com SentinelAV" no botão direito do Windows Explorer,
e registra inicialização opcional com o Windows.
"""

from __future__ import annotations
import os
import sys
import shutil
import subprocess
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QCheckBox,
    QPushButton,
    QLineEdit,
    QFileDialog,
    QMessageBox,
    QFrame,
    QProgressBar,
)

from core.win_integration import (
    register_explorer_context_menu,
    register_windows_startup,
    register_weekly_update_task,
    register_uninstall_entry,
    create_windows_shortcuts,
    notify_windows_shell_refresh,
)
from ui.theme import SECURITY_DARK_STYLE


class SentinelInstallerWizard(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Instalador — SentinelAV Security Suite v1.0")
        self.setFixedSize(600, 460)
        self.setStyleSheet(SECURITY_DARK_STYLE)

        self.project_dir = os.path.dirname(os.path.abspath(__file__))
        self.logo_png = os.path.join(self.project_dir, "assets", "shield.png")
        self.logo_ico = os.path.join(self.project_dir, "assets", "shield.ico")
        if os.path.exists(self.logo_ico):
            self.setWindowIcon(QIcon(self.logo_ico))

        default_install_dir = os.path.join(
            os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
            "Programs",
            "SentinelAV",
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(14)

        # Cabeçalho
        header = QFrame()
        header.setStyleSheet(
            "background-color: #064e3b; border: 1px solid #10b981; border-radius: 10px; padding: 12px;"
        )
        h_layout = QHBoxLayout(header)
        if os.path.exists(self.logo_png):
            icon_lbl = QLabel()
            icon_lbl.setPixmap(
                QPixmap(self.logo_png).scaled(
                    68, 68, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
                )
            )
            icon_lbl.setStyleSheet("border: none; background: transparent;")
            h_layout.addWidget(icon_lbl)

        title_v = QVBoxLayout()
        t1 = QLabel("Instalar o SentinelAV Security no Windows")
        t1.setStyleSheet("font-size: 19px; font-weight: 800; color: #ecfdf5; border: none; background: transparent;")
        t2 = QLabel(
            "Motor Antivírus Multicamada (SHA-256 + YARA + Heurística PE + Authenticode), "
            "Escudo em Tempo Real, Quarentena Criptografada e Atualizador Online"
        )
        t2.setWordWrap(True)
        t2.setStyleSheet("font-size: 12px; color: #a7f3d0; border: none; background: transparent;")
        title_v.addWidget(t1)
        title_v.addWidget(t2)
        h_layout.addLayout(title_v, 1)
        layout.addWidget(header)

        # Pasta de destino
        layout.addWidget(QLabel("Pasta de instalação no Windows:"))
        dir_row = QHBoxLayout()
        self.dir_edit = QLineEdit(default_install_dir)
        browse_btn = QPushButton("Alterar...")
        browse_btn.setObjectName("secondaryBtn")
        browse_btn.clicked.connect(self._browse_dir)
        dir_row.addWidget(self.dir_edit)
        dir_row.addWidget(browse_btn)
        layout.addLayout(dir_row)

        # Opções de integração com o Windows
        self.chk_context_menu = QCheckBox(
            "Adicionar 'Verificar ameaças com SentinelAV' no botão direito do Windows Explorer"
        )
        self.chk_context_menu.setChecked(True)
        layout.addWidget(self.chk_context_menu)

        self.chk_shortcuts = QCheckBox(
            "Criar atalhos na Área de Trabalho e no Menu Iniciar com o ícone oficial"
        )
        self.chk_shortcuts.setChecked(True)
        layout.addWidget(self.chk_shortcuts)

        self.chk_startup = QCheckBox(
            "Iniciar proteção em segundo plano automaticamente junto com o Windows"
        )
        self.chk_startup.setChecked(True)
        layout.addWidget(self.chk_startup)

        self.chk_launch_after = QCheckBox("Abrir o SentinelAV ao concluir a instalação")
        self.chk_launch_after.setChecked(True)
        layout.addWidget(self.chk_launch_after)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        self.status_lbl = QLabel("Clique em 'Instalar Agora' para configurar o antivírus no Windows.")
        self.status_lbl.setStyleSheet("color: #6ee7b7;")
        layout.addWidget(self.status_lbl)

        layout.addStretch()

        btns = QHBoxLayout()
        btns.addStretch()
        cancel_btn = QPushButton("Cancelar")
        cancel_btn.setObjectName("secondaryBtn")
        cancel_btn.clicked.connect(self.reject)

        self.install_btn = QPushButton("🛡️ Instalar Agora")
        self.install_btn.setStyleSheet(
            "background-color: #059669; color: white; font-size: 14px; font-weight: bold; padding: 9px 24px; border-radius: 6px;"
        )
        self.install_btn.clicked.connect(self._run_install)
        btns.addWidget(cancel_btn)
        btns.addWidget(self.install_btn)
        layout.addLayout(btns)

    def _browse_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Escolher Pasta de Instalação", self.dir_edit.text())
        if d:
            self.dir_edit.setText(d)

    def _run_install(self):
        target_dir = os.path.abspath(self.dir_edit.text().strip())
        self.install_btn.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setValue(15)
        self.status_lbl.setText("Copiando motores de detecção e recursos gráficos...")
        QApplication.processEvents()

        try:
            os.makedirs(target_dir, exist_ok=True)
            if os.path.normcase(target_dir) != os.path.normcase(self.project_dir):
                for folder in ("assets", "core", "ui", "samples"):
                    src_f = os.path.join(self.project_dir, folder)
                    dst_f = os.path.join(target_dir, folder)
                    if os.path.exists(src_f):
                        if os.path.exists(dst_f):
                            shutil.rmtree(dst_f)
                        shutil.copytree(src_f, dst_f)
                for file_name in ("main.py", "installer_gui.py"):
                    src_file = os.path.join(self.project_dir, file_name)
                    if os.path.exists(src_file):
                        shutil.copy2(src_file, os.path.join(target_dir, file_name))

                # Se houver executável empacotado (.exe) em dist, copia também
                dist_exe = os.path.join(self.project_dir, "dist", "SentinelAV.exe")
                if os.path.exists(dist_exe):
                    shutil.copy2(dist_exe, os.path.join(target_dir, "SentinelAV.exe"))

            self.progress.setValue(55)
            self.status_lbl.setText("Inicializando banco de dados SQLite de vacinas e quarentena...")
            QApplication.processEvents()

            from core.database import ThreatDatabase
            ThreatDatabase()

            target_exe = os.path.join(target_dir, "SentinelAV.exe")
            target_script = target_exe if os.path.exists(target_exe) else os.path.join(target_dir, "main.py")
            target_ico = os.path.join(target_dir, "assets", "shield.ico")

            if self.chk_context_menu.isChecked():
                self.status_lbl.setText("Registrando menu do botão direito no Windows Explorer...")
                QApplication.processEvents()
                register_explorer_context_menu()

            register_windows_startup(self.chk_startup.isChecked())
            register_weekly_update_task(True)
            register_uninstall_entry(target_dir, target_ico)

            self.progress.setValue(85)
            if self.chk_shortcuts.isChecked():
                self.status_lbl.setText("Criando atalhos na Área de Trabalho e no Menu Iniciar...")
                QApplication.processEvents()
                create_windows_shortcuts(target_script, target_ico, target_dir)

            notify_windows_shell_refresh()
            self.progress.setValue(100)
            self.status_lbl.setText("Instalação concluída com sucesso!")

            QMessageBox.information(
                self,
                "Instalação Concluída — SentinelAV",
                f"O SentinelAV Security Suite foi instalado com sucesso em:\n{target_dir}\n\n"
                "• Atalhos criados na Área de Trabalho e no Menu Iniciar\n"
                "• Opção 'Verificar ameaças com SentinelAV' adicionada ao botão direito do Explorer\n"
                "• Base de vacinas SHA-256 + YARA e Cofre de Quarentena prontos",
            )

            if self.chk_launch_after.isChecked():
                if target_script.lower().endswith(".exe"):
                    subprocess.Popen([target_script], cwd=target_dir)
                else:
                    pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
                    runner = pythonw if os.path.exists(pythonw) else sys.executable
                    subprocess.Popen([runner, target_script], cwd=target_dir)

            self.accept()
        except Exception as e:
            self.install_btn.setEnabled(True)
            QMessageBox.critical(self, "Erro na Instalação", str(e))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    wiz = SentinelInstallerWizard()
    wiz.show()
    sys.exit(app.exec())
