"""
SentinelAV - Janela Principal de Segurança (Detecção de Ameaças, Quarentena e Atualizações Online)
"""

from __future__ import annotations
import os
import time
from datetime import datetime
from typing import List, Optional

from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QIcon, QPixmap, QColor, QAction
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QProgressBar,
    QFileDialog,
    QMessageBox,
    QFrame,
    QCheckBox,
    QLineEdit,
    QPlainTextEdit,
    QSystemTrayIcon,
    QMenu,
    QAbstractItemView,
)

from core import get_app_base_dir, APP_NAME, APP_VERSION
from core.database import ThreatDatabase
from core.scanner import SentinelScanner, ThreatDetection, create_safe_test_samples
from core.quarantine import QuarantineManager
from core.updater import ThreatUpdater
from core.realtime import RealTimeShield
from core.web_shield import WebProtectionShield, WebThreatAlert
from core.win_integration import (
    is_windows_startup_enabled,
    register_windows_startup,
    is_weekly_update_task_registered,
    register_weekly_update_task,
)
from ui.theme import SECURITY_DARK_STYLE


class ScanWorker(QThread):
    progress_updated = pyqtSignal(int, int, str)  # (atual, total, item_atual)
    threat_found = pyqtSignal(object)  # ThreatDetection
    scan_finished = pyqtSignal(int, int, float, str)  # (arquivos_lidos, ameacas, segundos, tipo_scan)

    def __init__(
        self,
        scanner: SentinelScanner,
        scan_type: str,
        target_paths: Optional[List[str]] = None,
        scan_processes: bool = False,
    ):
        super().__init__()
        self.scanner = scanner
        self.scan_type = scan_type
        self.target_paths = target_paths or []
        self.scan_processes = scan_processes
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def is_cancelled(self) -> bool:
        return self._cancelled

    def run(self):
        t0 = time.perf_counter()
        total_inspected = 0
        threats_count = 0

        # 1. Opcionalmente escaneia processos na memória RAM primeiro
        if self.scan_processes and not self._cancelled:
            def _proc_cb(cur: int, tot: int, label: str):
                self.progress_updated.emit(cur, max(tot, 1), label)

            proc_count, proc_threats = self.scanner.scan_running_processes(
                progress_cb=_proc_cb,
                cancel_check=self.is_cancelled,
            )
            total_inspected += proc_count
            for hit in proc_threats:
                threats_count += 1
                self.threat_found.emit(hit)

        # 2. Escaneia arquivos/pastas selecionadas
        if self.target_paths and not self._cancelled:
            self.progress_updated.emit(0, 100, "Mapeando arquivos para inspeção...")
            files = self.scanner.collect_files(self.target_paths, cancel_check=self.is_cancelled)
            total_files = len(files)

            for idx, fpath in enumerate(files, start=1):
                if self._cancelled:
                    break
                if idx == 1 or idx % 5 == 0 or idx == total_files:
                    self.progress_updated.emit(idx, max(total_files, 1), fpath)
                hit = self.scanner.scan_file(fpath)
                total_inspected += 1
                if hit:
                    threats_count += 1
                    self.threat_found.emit(hit)

        elapsed = time.perf_counter() - t0
        self.scanner.db.record_scan(self.scan_type, total_inspected, threats_count, elapsed)
        self.scan_finished.emit(total_inspected, threats_count, elapsed, self.scan_type)


class UpdateWorker(QThread):
    progress_changed = pyqtSignal(int, str)
    update_completed = pyqtSignal(bool, str, int)

    def __init__(self, updater: ThreatUpdater):
        super().__init__()
        self.updater = updater

    def run(self):
        ok, msg, added = self.updater.update_from_online_feeds(
            status_cb=lambda pct, txt: self.progress_changed.emit(pct, txt)
        )
        self.update_completed.emit(ok, msg, added)


class SentinelMainWindow(QMainWindow):
    def __init__(self, initial_scan_path: Optional[str] = None, start_minimized: bool = False):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} Security — Proteção Antivírus & Heurística para Windows v{APP_VERSION}")
        self.resize(1150, 700)
        self.setMinimumSize(980, 600)
        self.setStyleSheet(SECURITY_DARK_STYLE)

        self.base_dir = get_app_base_dir()
        self.ico_path = os.path.join(self.base_dir, "assets", "shield.ico")
        self.png_path = os.path.join(self.base_dir, "assets", "shield.png")
        if os.path.exists(self.ico_path):
            self.setWindowIcon(QIcon(self.ico_path))

        # Inicializa Motores Core
        self.db = ThreatDatabase()
        self.scanner = SentinelScanner(self.db)
        self.quarantine = QuarantineManager()
        self.updater = ThreatUpdater(self.db)
        self.realtime = RealTimeShield(self.scanner, self)
        self.web_shield = WebProtectionShield(self.db.db_path)

        self.active_threats: List[ThreatDetection] = []
        self.scan_worker: Optional[ScanWorker] = None
        self.update_worker: Optional[UpdateWorker] = None
        self._is_silent_auto_update = False

        self._build_ui()
        self._setup_system_tray()

        # Conecta sinais do Escudo em Tempo Real
        self.realtime.threat_detected.connect(self._on_realtime_threat)
        self.realtime.activity_logged.connect(self._append_log)

        self._refresh_stats_ui()
        self._refresh_quarantine_table()
        self._append_log("SentinelAV iniciado. Motores SHA-256, YARA, Heurística PE e Escudo Web prontos.")

        # Timer de verificação de auto-atualização semanal (verifica ao iniciar e a cada 2h se venceu o ciclo de 7 dias)
        self._weekly_timer = QTimer(self)
        self._weekly_timer.setInterval(2 * 3600 * 1000)
        self._weekly_timer.timeout.connect(self._check_weekly_auto_update_due)
        self._weekly_timer.start()
        QTimer.singleShot(8000, self._check_weekly_auto_update_due)

        if initial_scan_path and os.path.exists(initial_scan_path):
            self._start_custom_paths_scan([os.path.abspath(initial_scan_path)], "Verificação pelo Explorer")
        elif start_minimized:
            self.hide()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(18, 16, 18, 14)
        main_layout.setSpacing(12)

        # 1. Banner Superior de Status de Proteção
        self.banner_frame = QFrame()
        self.banner_frame.setObjectName("bannerFrame")
        self.banner_frame.setStyleSheet(
            "QFrame#bannerFrame { background-color: #064e3b; border: 1px solid #10b981; border-radius: 10px; }"
            "QFrame#bannerFrame QLabel, QFrame#bannerFrame QCheckBox { border: none; background: transparent; padding: 0px; }"
        )
        banner_layout = QHBoxLayout(self.banner_frame)
        banner_layout.setContentsMargins(16, 12, 16, 12)
        banner_layout.setSpacing(16)

        if os.path.exists(self.png_path):
            logo_lbl = QLabel()
            logo_lbl.setPixmap(
                QPixmap(self.png_path).scaled(
                    60, 60, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
                )
            )
            logo_lbl.setStyleSheet("border: none; background: transparent; padding: 0px;")
            banner_layout.addWidget(logo_lbl)

        status_col = QVBoxLayout()
        status_col.setSpacing(5)
        self.status_title_lbl = QLabel("🛡️ SISTEMA PROTEGIDO — Escudo Ativo")
        self.status_title_lbl.setStyleSheet(
            "font-size: 19px; font-weight: 800; color: #ecfdf5; border: none; background: transparent; padding: 0px;"
        )
        self.status_sub_lbl = QLabel(
            "Motores de Assinatura SHA-256, Regras YARA, Heurística PE (IAT/Entropia) e Verificação Authenticode ativos."
        )
        self.status_sub_lbl.setWordWrap(True)
        self.status_sub_lbl.setStyleSheet(
            "font-size: 12.5px; color: #a7f3d0; border: none; background: transparent; padding: 0px;"
        )

        # Linha em destaque no Banner Principal com Data da Última Atualização + Botão de Atualização Manual
        upd_banner_row = QHBoxLayout()
        upd_banner_row.setSpacing(14)
        self.last_update_banner_lbl = QLabel("📅 Última Atualização: --")
        self.last_update_banner_lbl.setStyleSheet(
            "font-size: 13px; color: #fef08a; font-weight: 700; border: none; background: transparent; padding-right: 8px;"
        )
        self.defs_badge_lbl = QLabel("🛡️ Vacinas Ativas: --")
        self.defs_badge_lbl.setStyleSheet(
            "font-size: 12.5px; color: #6ee7b7; font-weight: 600; border: none; background: transparent; padding-right: 8px;"
        )
        self.btn_banner_update = QPushButton("🔄 Atualizar Ameaças Agora")
        self.btn_banner_update.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_banner_update.setStyleSheet(
            "background-color: #2563eb; color: #ffffff; font-size: 12px; font-weight: 700; "
            "padding: 5px 14px; border-radius: 6px; border: 1px solid #60a5fa;"
        )
        self.btn_banner_update.setToolTip(
            "Executa imediatamente a atualização manual online buscando novas ameaças (Hashes SHA-256, Regras YARA, Phishing e IPs C2)"
        )
        self.btn_banner_update.clicked.connect(lambda: self.run_online_update(silent=False))

        upd_banner_row.addWidget(self.last_update_banner_lbl)
        upd_banner_row.addWidget(self.defs_badge_lbl)
        upd_banner_row.addWidget(self.btn_banner_update)
        upd_banner_row.addStretch()

        status_col.addWidget(self.status_title_lbl)
        status_col.addWidget(self.status_sub_lbl)
        status_col.addLayout(upd_banner_row)
        banner_layout.addLayout(status_col, 1)

        # Controles Rápidos do Escudo em Tempo Real no Banner
        right_col = QVBoxLayout()
        right_col.setSpacing(4)
        self.chk_realtime = QCheckBox("Escudo em Tempo Real Ativo")
        self.chk_realtime.setChecked(True)
        self.chk_realtime.setStyleSheet("color: #ffffff; font-weight: 700; border: none; background: transparent; padding: 0px;")
        self.chk_realtime.toggled.connect(self._toggle_realtime)

        self.chk_auto_quarantine = QCheckBox("Quarentena Automática ao Detectar")
        self.chk_auto_quarantine.setChecked(False)
        self.chk_auto_quarantine.setStyleSheet("color: #d1fae5; border: none; background: transparent; padding: 0px;")

        self.chk_win_startup = QCheckBox("Iniciar junto com o Windows (Bandeja)")
        self.chk_win_startup.setChecked(is_windows_startup_enabled())
        self.chk_win_startup.setStyleSheet("color: #d1fae5; border: none; background: transparent; padding: 0px;")
        self.chk_win_startup.toggled.connect(self._toggle_windows_startup)

        right_col.addWidget(self.chk_realtime)
        right_col.addWidget(self.chk_auto_quarantine)
        right_col.addWidget(self.chk_win_startup)
        banner_layout.addLayout(right_col)

        main_layout.addWidget(self.banner_frame)

        # 2. Abas Principais
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs, 1)

        self._build_scan_tab()
        self._build_web_tab()
        self._build_quarantine_tab()
        self._build_update_tab()

        # Barra de Status Inferior
        self.statusBar().showMessage("Pronto. Monitorando pastas críticas e integridade do sistema.")

    def _build_scan_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        # Botões de Verificação Direta
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        self.btn_quick_scan = QPushButton("⚡ Verificação Rápida\n(Memória, Downloads, Inicialização)")
        self.btn_quick_scan.setObjectName("actionCardBtn")
        self.btn_quick_scan.clicked.connect(self.run_quick_scan)

        self.btn_folder_scan = QPushButton("📁 Verificar Pasta...\n(Escolher Diretório no Windows)")
        self.btn_folder_scan.setObjectName("actionCardBtn")
        self.btn_folder_scan.clicked.connect(self.run_folder_scan)

        self.btn_file_scan = QPushButton("📄 Verificar Arquivo...\n(Inspecionar .EXE, .DLL, .PDF, Script)")
        self.btn_file_scan.setObjectName("actionCardBtn")
        self.btn_file_scan.clicked.connect(self.run_file_scan)

        self.btn_proc_scan = QPushButton("🖥️ Verificar Memória RAM\n(Processos em Execução Agora)")
        self.btn_proc_scan.setObjectName("actionCardBtn")
        self.btn_proc_scan.clicked.connect(self.run_process_scan)

        btn_row.addWidget(self.btn_quick_scan)
        btn_row.addWidget(self.btn_folder_scan)
        btn_row.addWidget(self.btn_file_scan)
        btn_row.addWidget(self.btn_proc_scan)
        layout.addLayout(btn_row)

        # Barra de Progresso + Botão de Teste / Parar
        prog_row = QHBoxLayout()
        self.scan_progress = QProgressBar()
        self.scan_progress.setRange(0, 100)
        self.scan_progress.setValue(0)
        prog_row.addWidget(self.scan_progress, 1)

        self.btn_stop_scan = QPushButton("⏹ Parar")
        self.btn_stop_scan.setObjectName("dangerBtn")
        self.btn_stop_scan.setEnabled(False)
        self.btn_stop_scan.clicked.connect(self.stop_current_scan)
        prog_row.addWidget(self.btn_stop_scan)

        self.btn_create_test = QPushButton("🧪 Criar Amostra de Teste (EICAR/Simulado)")
        self.btn_create_test.setObjectName("secondaryBtn")
        self.btn_create_test.setToolTip(
            "Gera arquivos de teste 100% inofensivos na pasta 'samples' e inicia a detecção para você testar o antivírus."
        )
        self.btn_create_test.clicked.connect(self.generate_and_scan_test_samples)
        prog_row.addWidget(self.btn_create_test)

        layout.addLayout(prog_row)

        self.scan_current_lbl = QLabel("Nenhuma verificação em andamento. Escolha um modo de verificação acima.")
        self.scan_current_lbl.setStyleSheet("color: #93c5fd; font-size: 12px;")
        layout.addWidget(self.scan_current_lbl)

        # Tabela de Ameaças Detectadas
        hdr_row = QHBoxLayout()
        lbl_t = QLabel("🚨 Ameaças Detectadas:")
        lbl_t.setStyleSheet("font-size: 14px; font-weight: 700; color: #f8fafc;")
        hdr_row.addWidget(lbl_t)
        hdr_row.addStretch()

        self.btn_quarantine_all = QPushButton("🛡️ Neutralizar Todas (Mover para Quarentena)")
        self.btn_quarantine_all.setObjectName("dangerBtn")
        self.btn_quarantine_all.setEnabled(False)
        self.btn_quarantine_all.clicked.connect(self.quarantine_all_detected)

        self.btn_quarantine_sel = QPushButton("🔒 Quarentena na Selecionada")
        self.btn_quarantine_sel.setObjectName("secondaryBtn")
        self.btn_quarantine_sel.setEnabled(False)
        self.btn_quarantine_sel.clicked.connect(self.quarantine_selected_threat)

        self.btn_trust_sel = QPushButton("✅ Confiar / Whitelist")
        self.btn_trust_sel.setObjectName("secondaryBtn")
        self.btn_trust_sel.setEnabled(False)
        self.btn_trust_sel.clicked.connect(self.whitelist_selected_threat)

        hdr_row.addWidget(self.btn_quarantine_sel)
        hdr_row.addWidget(self.btn_trust_sel)
        hdr_row.addWidget(self.btn_quarantine_all)
        layout.addLayout(hdr_row)

        self.threats_table = QTableWidget(0, 5)
        self.threats_table.setHorizontalHeaderLabels(
            ["Ameaça Detectada", "Severidade", "Motor Detector", "Arquivo / Processo", "Detalhes Técnicos"]
        )
        self.threats_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.threats_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.threats_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.threats_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.threats_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.threats_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.threats_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.threats_table.setAlternatingRowColors(True)
        layout.addWidget(self.threats_table, 1)

        self.tabs.addTab(tab, "🔍 Detecção de Ameaças")

    def _build_web_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        # 1. Card de Inspeção de Links / Anti-Phishing
        url_card = QFrame()
        url_card.setObjectName("urlCard")
        url_card.setStyleSheet(
            "QFrame#urlCard { background-color: #1e293b; border: 1px solid #334155; border-radius: 10px; }"
            "QFrame#urlCard QLabel { border: none; background: transparent; padding: 0px; }"
        )
        u_layout = QVBoxLayout(url_card)
        u_layout.setContentsMargins(14, 12, 14, 12)

        u_title = QLabel("🛡️ Verificador de Links, Sites & Anti-Phishing (OpenPhish + Heurística Bancária)")
        u_title.setStyleSheet("font-size: 14px; font-weight: 700; color: #f8fafc; border: none;")
        u_layout.addWidget(u_title)

        u_desc = QLabel(
            "Verifique qualquer link suspeito recebido por e-mail/WhatsApp ou navegador antes de acessar. "
            "Nota: Todo download concluído pelos navegadores (Chrome, Edge, Brave, Firefox) na pasta Downloads "
            "já é escaneado automaticamente pelo Escudo em Tempo Real."
        )
        u_desc.setWordWrap(True)
        u_desc.setStyleSheet("color: #94a3b8; font-size: 12px; border: none;")
        u_layout.addWidget(u_desc)

        url_row = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Cole aqui uma URL ou domínio para verificar (ex: https://site-suspeito.xyz/login)...")
        btn_check_url = QPushButton("🔍 Verificar Link / Site")
        btn_check_url.clicked.connect(self.check_url_now)

        btn_test_phish = QPushButton("🧪 Testar Link Phishing Simulado")
        btn_test_phish.setObjectName("secondaryBtn")
        btn_test_phish.clicked.connect(self.test_phishing_url)

        url_row.addWidget(self.url_input, 1)
        url_row.addWidget(btn_check_url)
        url_row.addWidget(btn_test_phish)
        u_layout.addLayout(url_row)
        layout.addWidget(url_card)

        # 2. Botões de Varredura de Rede C2 e Auditoria de Navegadores
        net_row = QHBoxLayout()
        net_row.setSpacing(10)

        btn_scan_net = QPushButton(
            "🌐 Inspecionar Conexões de Rede Ativas\n(Detectar IPs de Botnet/C2, Portas de RAT/Mineração e LOLBins)"
        )
        btn_scan_net.setObjectName("actionCardBtn")
        btn_scan_net.clicked.connect(self.scan_web_network_now)

        btn_audit_browsers = QPushButton(
            "🧭 Auditar Navegadores (Chrome, Edge, Brave) & DNS\n(Verificar Extensões Maliciosas e Arquivo Hosts do Windows)"
        )
        btn_audit_browsers.setObjectName("actionCardBtn")
        btn_audit_browsers.clicked.connect(self.audit_browsers_now)

        net_row.addWidget(btn_scan_net)
        net_row.addWidget(btn_audit_browsers)
        layout.addLayout(net_row)

        self.web_status_lbl = QLabel("Escudo Web pronto. Proteção de Downloads em Tempo Real ativa.")
        self.web_status_lbl.setStyleSheet("color: #6ee7b7; font-size: 12.5px; font-weight: 600;")
        layout.addWidget(self.web_status_lbl)

        # 3. Tabela de Alertas Web / Navegadores / Rede
        self.web_table = QTableWidget(0, 5)
        self.web_table.setHorizontalHeaderLabels(
            ["Camada Web", "Ameaça Detectada", "Severidade", "URL / IP / Extensão", "Diagnóstico"]
        )
        self.web_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.web_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.web_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.web_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.web_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.web_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.web_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.web_table.setAlternatingRowColors(True)
        layout.addWidget(self.web_table, 1)

        self.tabs.addTab(tab, "🌐 Proteção Web & Navegadores")

    def _build_quarantine_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        info_lbl = QLabel(
            "Os arquivos na Quarentena estão isolados e criptografados com cifra XOR-256 no cofre seguro "
            "(%LOCALAPPDATA%\\SentinelAV\\quarantine), impedindo qualquer execução."
        )
        info_lbl.setWordWrap(True)
        info_lbl.setStyleSheet("color: #94a3b8; font-size: 12.5px;")
        layout.addWidget(info_lbl)

        q_btns = QHBoxLayout()
        btn_restore = QPushButton("♻️ Restaurar Selecionado (Adicionar à Whitelist)")
        btn_restore.setObjectName("blueBtn")
        btn_restore.clicked.connect(self.restore_quarantined_item)

        btn_delete = QPushButton("🔥 Excluir Permanentemente")
        btn_delete.setObjectName("dangerBtn")
        btn_delete.clicked.connect(self.delete_quarantined_item)

        btn_refresh = QPushButton("🔄 Atualizar Lista")
        btn_refresh.setObjectName("secondaryBtn")
        btn_refresh.clicked.connect(self._refresh_quarantine_table)

        q_btns.addWidget(btn_restore)
        q_btns.addWidget(btn_delete)
        q_btns.addWidget(btn_refresh)
        q_btns.addStretch()
        layout.addLayout(q_btns)

        self.quarantine_table = QTableWidget(0, 6)
        self.quarantine_table.setHorizontalHeaderLabels(
            ["ID", "Data / Hora", "Ameaça", "Severidade", "Arquivo Original", "SHA-256"]
        )
        self.quarantine_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.quarantine_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.quarantine_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.quarantine_table.setAlternatingRowColors(True)
        layout.addWidget(self.quarantine_table, 1)

        self.tabs.addTab(tab, "🔒 Cofre de Quarentena (0)")

    def _build_update_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(14)

        # Card de Atualização Online
        upd_card = QFrame()
        upd_card.setObjectName("updCard")
        upd_card.setStyleSheet(
            "QFrame#updCard { background-color: #1e293b; border: 1px solid #334155; border-radius: 10px; }"
            "QFrame#updCard QLabel, QFrame#updCard QCheckBox { border: none; background: transparent; padding: 0px; }"
        )
        u_layout = QVBoxLayout(upd_card)
        u_layout.setContentsMargins(16, 14, 16, 14)

        self.upd_stats_lbl = QLabel("Carregando estatísticas da base de ameaças...")
        self.upd_stats_lbl.setStyleSheet("font-size: 14px; font-weight: 700; color: #f8fafc; border: none; padding: 0px;")
        u_layout.addWidget(self.upd_stats_lbl)

        self.last_update_detail_lbl = QLabel("📅 Data da Última Atualização: --")
        self.last_update_detail_lbl.setStyleSheet("font-size: 13.5px; font-weight: 700; color: #fef08a; border: none; padding: 0px;")
        u_layout.addWidget(self.last_update_detail_lbl)

        sched_row = QHBoxLayout()
        self.chk_weekly_auto = QCheckBox(
            "📅 Auto-Atualização Semanal Ativa (Agendador do Windows + Verificação Automática de 7 Dias)"
        )
        self.chk_weekly_auto.setChecked(is_weekly_update_task_registered() or True)
        self.chk_weekly_auto.setStyleSheet("color: #6ee7b7; font-weight: 700; border: none; padding: 0px;")
        self.chk_weekly_auto.toggled.connect(self._toggle_weekly_auto_update)
        sched_row.addWidget(self.chk_weekly_auto)
        sched_row.addStretch()

        self.weekly_next_lbl = QLabel("Próxima atualização semanal: calculando...")
        self.weekly_next_lbl.setStyleSheet("color: #93c5fd; font-size: 12px; font-weight: 600; border: none; padding: 0px;")
        sched_row.addWidget(self.weekly_next_lbl)
        u_layout.addLayout(sched_row)

        desc_u = QLabel(
            "Você pode atualizar manualmente a qualquer momento clicando no botão abaixo (ou no botão azul do topo), "
            "além da sincronização automática semanal em segundo plano."
        )
        desc_u.setWordWrap(True)
        desc_u.setStyleSheet("color: #94a3b8; font-size: 12.5px; border: none; padding: 0px;")
        u_layout.addWidget(desc_u)

        self.upd_progress = QProgressBar()
        self.upd_progress.setRange(0, 100)
        self.upd_progress.setValue(0)
        u_layout.addWidget(self.upd_progress)

        self.btn_update_now = QPushButton("🔄 Executar Atualização Manual Agora (Buscar Novas Ameaças Online)")
        self.btn_update_now.setStyleSheet(
            "background-color: #2563eb; color: #ffffff; font-size: 14px; font-weight: 700; padding: 11px 18px; border-radius: 7px;"
        )
        self.btn_update_now.clicked.connect(lambda: self.run_online_update(silent=False))
        u_layout.addWidget(self.btn_update_now)

        layout.addWidget(upd_card)

        # Card para adicionar Hash SHA-256 ou Assinatura customizada
        custom_card = QFrame()
        custom_card.setObjectName("customCard")
        custom_card.setStyleSheet(
            "QFrame#customCard { background-color: #1e293b; border: 1px solid #334155; border-radius: 10px; }"
            "QFrame#customCard QLabel { border: none; background: transparent; padding: 0px; }"
        )
        c_layout = QVBoxLayout(custom_card)
        c_layout.setContentsMargins(16, 12, 16, 12)
        c_title = QLabel("➕ Cadastrar Nova Assinatura SHA-256 Manualmente")
        c_title.setStyleSheet("font-size: 13.5px; font-weight: 700; color: #93c5fd; border: none; padding: 0px;")
        c_layout.addWidget(c_title)

        form_row = QHBoxLayout()
        self.custom_hash_edit = QLineEdit()
        self.custom_hash_edit.setPlaceholderText("Hash SHA-256 (64 caracteres hexadecimais)...")
        self.custom_name_edit = QLineEdit()
        self.custom_name_edit.setPlaceholderText("Nome da Ameaça (ex: Trojan.Custom.Block)")
        btn_add_hash = QPushButton("Adicionar Vacina")
        btn_add_hash.setObjectName("blueBtn")
        btn_add_hash.clicked.connect(self.add_custom_hash_signature)
        form_row.addWidget(self.custom_hash_edit, 2)
        form_row.addWidget(self.custom_name_edit, 1)
        form_row.addWidget(btn_add_hash)
        c_layout.addLayout(form_row)
        layout.addWidget(custom_card)

        # Log de Eventos em Tempo Real
        layout.addWidget(QLabel("📋 Registro de Atividades & Eventos de Segurança:"))
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        layout.addWidget(self.log_view, 1)

        self.tabs.addTab(tab, "🔄 Atualizações & Inteligência")

    def _setup_system_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray = QSystemTrayIcon(self)
        if os.path.exists(self.ico_path):
            self.tray.setIcon(QIcon(self.ico_path))
        self.tray.setToolTip(f"{APP_NAME} — Escudo em Tempo Real Ativo")

        menu = QMenu()
        act_open = QAction("Abrir Painel do SentinelAV", self)
        act_open.triggered.connect(self.showNormal)
        act_quick = QAction("⚡ Executar Verificação Rápida", self)
        act_quick.triggered.connect(self.run_quick_scan)
        act_update = QAction("🔄 Atualizar Base de Ameaças Agora (Manual)", self)
        act_update.triggered.connect(lambda: self.run_online_update(silent=False))
        act_quit = QAction("Sair do SentinelAV", self)
        act_quit.triggered.connect(QApplication.instance().quit)

        menu.addAction(act_open)
        menu.addAction(act_quick)
        menu.addAction(act_update)
        menu.addSeparator()
        menu.addAction(act_quit)

        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._on_tray_activated)
        self.tray.show()

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.showNormal()
            self.activateWindow()

    def _append_log(self, message: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_view.appendPlainText(f"[{ts}] {message}")

    def _refresh_stats_ui(self):
        stats = self.db.get_stats()
        self.web_shield.reload_cache()
        web_stats = self.web_shield.get_web_stats()
        total_all = stats["total_definitions"] + web_stats["total_web_indicators"]

        raw_last = stats.get("last_update", "Nunca")
        try:
            dt_last = datetime.strptime(raw_last, "%Y-%m-%d %H:%M:%S")
            br_last = dt_last.strftime("%d/%m/%Y às %H:%M:%S")
        except Exception:
            br_last = raw_last

        if hasattr(self, "last_update_banner_lbl"):
            upd_txt = f"📅 Última Atualização: {br_last}  "
            self.last_update_banner_lbl.setText(upd_txt)
            self.last_update_banner_lbl.setMinimumWidth(
                self.last_update_banner_lbl.fontMetrics().horizontalAdvance(upd_txt) + 18
            )

        defs_txt = f"🛡️ Vacinas Ativas: {total_all:,}  "
        self.defs_badge_lbl.setText(defs_txt)
        self.defs_badge_lbl.setMinimumWidth(
            self.defs_badge_lbl.fontMetrics().horizontalAdvance(defs_txt) + 18
        )
        self.upd_stats_lbl.setText(
            f"📦 Versão da Base: {stats['db_version']}   |   "
            f"Hashes SHA-256: {stats['hash_count']:,}   |   "
            f"Regras YARA: {stats['rule_count']}   |   "
            f"Domínios/IPs Web: {web_stats['total_web_indicators']:,}"
        )
        if hasattr(self, "last_update_detail_lbl"):
            self.last_update_detail_lbl.setText(
                f"📅 Última Atualização Executada: {br_last}   |   Total de Vacinas Ativas: {total_all:,}"
            )
        _, next_date_str, rem_days = self.updater.get_weekly_schedule_status(7)
        if hasattr(self, "weekly_next_lbl"):
            self.weekly_next_lbl.setText(
                f"🗓️ Próxima Atualização Semanal: {next_date_str} (em {rem_days} dia(s))"
            )
        self._update_banner_state()

    def _update_banner_state(self):
        count = len(self.active_threats)
        child_reset = "QFrame#bannerFrame QLabel, QFrame#bannerFrame QCheckBox { border: none; background: transparent; padding: 0px; }"
        if count > 0:
            self.banner_frame.setStyleSheet(
                "QFrame#bannerFrame { background-color: #7f1d1d; border: 1px solid #ef4444; border-radius: 10px; } "
                + child_reset
            )
            self.status_title_lbl.setText(f"🚨 {count} AMEAÇA(S) DETECTADA(S) — Ação Necessária!")
            self.status_sub_lbl.setText(
                "Clique em 'Neutralizar Todas (Mover para Quarentena)' abaixo para isolar os arquivos maliciosos."
            )
            self.btn_quarantine_all.setEnabled(True)
            self.btn_quarantine_sel.setEnabled(True)
            self.btn_trust_sel.setEnabled(True)
        else:
            if self.chk_realtime.isChecked():
                self.banner_frame.setStyleSheet(
                    "QFrame#bannerFrame { background-color: #064e3b; border: 1px solid #10b981; border-radius: 10px; } "
                    + child_reset
                )
                self.status_title_lbl.setText("🛡️ SISTEMA PROTEGIDO — Escudo Ativo")
                self.status_sub_lbl.setText(
                    "Motores de Assinatura SHA-256, Regras YARA, Heurística PE (IAT/Entropia) e Authenticode ativos."
                )
            else:
                self.banner_frame.setStyleSheet(
                    "QFrame#bannerFrame { background-color: #78350f; border: 1px solid #f59e0b; border-radius: 10px; } "
                    + child_reset
                )
                self.status_title_lbl.setText("⚠️ ESCUDO EM TEMPO REAL PAUSADO")
                self.status_sub_lbl.setText("Reative o Escudo em Tempo Real para monitorar Downloads e Inicialização.")
            self.btn_quarantine_all.setEnabled(False)
            self.btn_quarantine_sel.setEnabled(False)
            self.btn_trust_sel.setEnabled(False)

    def _toggle_realtime(self, checked: bool):
        self.realtime.set_enabled(checked)
        self._update_banner_state()

    def _toggle_windows_startup(self, checked: bool):
        register_windows_startup(checked)
        estado = "ATIVADA" if checked else "DESATIVADA"
        self._append_log(f"Inicialização automática com o Windows {estado}.")

    def closeEvent(self, event):
        """Mantém o antivírus rodando em segundo plano na Bandeja do Sistema ao fechar a janela."""
        if hasattr(self, "tray") and self.tray.isVisible():
            self.hide()
            self.tray.showMessage(
                "SentinelAV Continua Protegendo",
                "O Escudo em Tempo Real permanece ativo na bandeja do sistema (perto do relógio).",
                QSystemTrayIcon.MessageIcon.Information,
                3500,
            )
            event.ignore()
        else:
            event.accept()

    def _on_realtime_threat(self, hit: ThreatDetection):
        self._append_log(f"🚨 [BLOQUEIO EM TEMPO REAL] {hit.threat_name} em {hit.filepath}")
        if self.chk_auto_quarantine.isChecked():
            ok, msg = self.quarantine.quarantine_threat(hit)
            self._append_log(f"🔒 [Auto-Quarentena] {msg}")
            self._refresh_quarantine_table()
            if hasattr(self, "tray"):
                self.tray.showMessage(
                    "SentinelAV — Ameaça Neutralizada!",
                    f"{hit.threat_name}\nMovida automaticamente para a Quarentena.",
                    QSystemTrayIcon.MessageIcon.Warning,
                    5000,
                )
        else:
            self._add_threat_to_table(hit)
            self._update_banner_state()
            if hasattr(self, "tray"):
                self.tray.showMessage(
                    "🚨 SentinelAV — Ameaça Detectada em Tempo Real!",
                    f"{hit.threat_name}\nArquivo: {os.path.basename(hit.filepath)}",
                    QSystemTrayIcon.MessageIcon.Critical,
                    5000,
                )

    # ================= AÇÕES DE VERIFICAÇÃO =================

    def _set_scan_buttons_enabled(self, enabled: bool):
        self.btn_quick_scan.setEnabled(enabled)
        self.btn_folder_scan.setEnabled(enabled)
        self.btn_file_scan.setEnabled(enabled)
        self.btn_proc_scan.setEnabled(enabled)
        self.btn_create_test.setEnabled(enabled)
        self.btn_stop_scan.setEnabled(not enabled)

    def _clear_active_threats(self):
        self.active_threats.clear()
        self.threats_table.setRowCount(0)
        self._update_banner_state()

    def run_quick_scan(self):
        dirs = self.scanner.get_quick_scan_directories()
        self._start_scan_worker(
            scan_type="Verificação Rápida",
            target_paths=dirs,
            scan_processes=True,
        )

    def run_folder_scan(self):
        folder = QFileDialog.getExistingDirectory(
            self, "Selecionar Pasta para Verificar Ameaças", os.path.expanduser("~")
        )
        if folder:
            self._start_custom_paths_scan([folder], f"Pasta: {os.path.basename(folder)}")

    def run_file_scan(self):
        fpath, _ = QFileDialog.getOpenFileName(
            self, "Selecionar Arquivo para Inspeção Profunda", os.path.expanduser("~"), "Todos os Arquivos (*.*)"
        )
        if fpath:
            self._start_custom_paths_scan([fpath], f"Arquivo: {os.path.basename(fpath)}")

    def run_process_scan(self):
        self._start_scan_worker(
            scan_type="Memória RAM (Processos Ativos)",
            target_paths=[],
            scan_processes=True,
        )

    def generate_and_scan_test_samples(self):
        """Gera amostras de teste seguras na pasta 'samples' e executa a verificação nelas."""
        samples = create_safe_test_samples()
        self._append_log(f"Criadas {len(samples)} amostras de teste inofensivas na pasta 'samples/'.")
        samples_dir = os.path.dirname(samples[0])
        self._start_custom_paths_scan([samples_dir], "Teste de Detecção (Amostras Simuladas)")

    def _start_custom_paths_scan(self, paths: List[str], label: str):
        self._start_scan_worker(scan_type=label, target_paths=paths, scan_processes=False)

    def _start_scan_worker(self, scan_type: str, target_paths: List[str], scan_processes: bool):
        if self.scan_worker and self.scan_worker.isRunning():
            return
        self.tabs.setCurrentIndex(0)
        self._clear_active_threats()
        self._set_scan_buttons_enabled(False)
        self.scan_progress.setValue(0)
        self.scan_current_lbl.setText(f"Iniciando {scan_type}...")
        self._append_log(f"Iniciando {scan_type}...")

        self.scan_worker = ScanWorker(
            scanner=self.scanner,
            scan_type=scan_type,
            target_paths=target_paths,
            scan_processes=scan_processes,
        )
        self.scan_worker.progress_updated.connect(self._on_scan_progress)
        self.scan_worker.threat_found.connect(self._on_scan_threat_found)
        self.scan_worker.scan_finished.connect(self._on_scan_finished)
        self.scan_worker.start()

    def stop_current_scan(self):
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.cancel()
            self.scan_current_lbl.setText("Interrompendo verificação...")

    def _on_scan_progress(self, current: int, total: int, current_item: str):
        pct = int((current / max(total, 1)) * 100)
        self.scan_progress.setValue(min(pct, 99))
        short_item = current_item if len(current_item) < 85 else "..." + current_item[-82:]
        self.scan_current_lbl.setText(f"[{current}/{total}] Inspecionando: {short_item}")

    def _on_scan_threat_found(self, hit: ThreatDetection):
        self._append_log(f"🚨 Detectado: {hit.threat_name} ({hit.engine}) -> {hit.filepath}")
        if self.chk_auto_quarantine.isChecked():
            ok, msg = self.quarantine.quarantine_threat(hit)
            self._append_log(f"🔒 [Auto-Quarentena] {msg}")
            self._refresh_quarantine_table()
        else:
            self._add_threat_to_table(hit)
            self._update_banner_state()

    def _add_threat_to_table(self, hit: ThreatDetection):
        # Evita duplicar o mesmo caminho na tabela
        if any(os.path.normcase(x.filepath) == os.path.normcase(hit.filepath) for x in self.active_threats):
            return
        self.active_threats.append(hit)
        row = self.threats_table.rowCount()
        self.threats_table.insertRow(row)

        t_item = QTableWidgetItem(f"🚨 {hit.threat_name}")
        t_item.setForeground(QColor("#fca5a5"))

        sev_item = QTableWidgetItem(hit.severity)
        sev_item.setForeground(QColor("#ef4444") if hit.severity == "Crítica" else QColor("#fbbf24"))

        eng_item = QTableWidgetItem(hit.engine)
        target_label = f"[PID {hit.pid}] {hit.filepath}" if hit.pid else hit.filepath
        path_item = QTableWidgetItem(target_label)
        det_item = QTableWidgetItem("; ".join(hit.details))

        self.threats_table.setItem(row, 0, t_item)
        self.threats_table.setItem(row, 1, sev_item)
        self.threats_table.setItem(row, 2, eng_item)
        self.threats_table.setItem(row, 3, path_item)
        self.threats_table.setItem(row, 4, det_item)

    def _on_scan_finished(self, total_inspected: int, threats_count: int, elapsed: float, scan_type: str):
        self._set_scan_buttons_enabled(True)
        self.scan_progress.setValue(100)
        summary = (
            f"✅ {scan_type} concluída em {elapsed:.2f}s — "
            f"{total_inspected:,} itens verificados | {threats_count} ameaça(s) encontrada(s)."
        )
        self.scan_current_lbl.setText(summary)
        self.statusBar().showMessage(summary)
        self._append_log(summary)
        self._update_banner_state()

    # ================= RESPOSTA A INCIDENTES & QUARENTENA =================

    def quarantine_all_detected(self):
        if not self.active_threats:
            return
        moved = 0
        errors = []
        for hit in list(self.active_threats):
            ok, msg = self.quarantine.quarantine_threat(hit)
            if ok:
                moved += 1
                self._append_log(f"🔒 Quarentena: {msg}")
            else:
                errors.append(msg)

        self._clear_active_threats()
        self._refresh_quarantine_table()

        QMessageBox.information(
            self,
            "Neutralização Concluída — SentinelAV",
            f"🛡️ {moved} ameaça(s) foram criptografadas com XOR-256 e isoladas no Cofre de Quarentena!"
            + (f"\n\nAvisos:\n" + "\n".join(errors) if errors else ""),
        )

    def quarantine_selected_threat(self):
        row = self.threats_table.currentRow()
        if row < 0 or row >= len(self.active_threats):
            QMessageBox.warning(self, "Selecione uma Ameaça", "Selecione uma linha na tabela de ameaças primeiro.")
            return
        hit = self.active_threats[row]
        ok, msg = self.quarantine.quarantine_threat(hit)
        if ok:
            self._append_log(f"🔒 {msg}")
            self.active_threats.pop(row)
            self.threats_table.removeRow(row)
            self._update_banner_state()
            self._refresh_quarantine_table()
        else:
            QMessageBox.warning(self, "Erro na Quarentena", msg)

    def whitelist_selected_threat(self):
        row = self.threats_table.currentRow()
        if row < 0 or row >= len(self.active_threats):
            QMessageBox.warning(self, "Selecione um Item", "Selecione uma linha na tabela de ameaças primeiro.")
            return
        hit = self.active_threats[row]
        self.db.add_to_whitelist(hit.sha256, hit.filepath)
        self._append_log(f"✅ Adicionado à Whitelist: {hit.filepath} ({hit.sha256[:12]}...)")
        self.active_threats.pop(row)
        self.threats_table.removeRow(row)
        self._update_banner_state()

    def _refresh_quarantine_table(self):
        items = self.quarantine.list_items()
        self.quarantine_table.setRowCount(0)
        for row_idx, item in enumerate(items):
            self.quarantine_table.insertRow(row_idx)
            self.quarantine_table.setItem(row_idx, 0, QTableWidgetItem(item.get("id", "")))
            self.quarantine_table.setItem(row_idx, 1, QTableWidgetItem(item.get("quarantined_at", "")))
            self.quarantine_table.setItem(row_idx, 2, QTableWidgetItem(item.get("threat_name", "")))
            self.quarantine_table.setItem(row_idx, 3, QTableWidgetItem(item.get("severity", "")))
            self.quarantine_table.setItem(row_idx, 4, QTableWidgetItem(item.get("original_path", "")))
            self.quarantine_table.setItem(row_idx, 5, QTableWidgetItem(item.get("sha256", "")[:20] + "..."))

        self.tabs.setTabText(2, f"🔒 Cofre de Quarentena ({len(items)})")

    # ================= ESCUDO WEB, NAVEGADORES & ANTI-PHISHING =================

    def _add_web_alert_row(self, alert: WebThreatAlert):
        row = self.web_table.rowCount()
        self.web_table.insertRow(row)

        type_item = QTableWidgetItem(alert.alert_type)
        threat_item = QTableWidgetItem(f"🚨 {alert.threat_name}")
        threat_item.setForeground(QColor("#fca5a5"))

        sev_item = QTableWidgetItem(alert.severity)
        sev_item.setForeground(QColor("#ef4444") if alert.severity == "Crítica" else QColor("#fbbf24"))

        target_item = QTableWidgetItem(alert.target)
        details_item = QTableWidgetItem(alert.details)

        self.web_table.setItem(row, 0, type_item)
        self.web_table.setItem(row, 1, threat_item)
        self.web_table.setItem(row, 2, sev_item)
        self.web_table.setItem(row, 3, target_item)
        self.web_table.setItem(row, 4, details_item)

    def check_url_now(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.information(self, "Verificar Link", "Digite ou cole uma URL ou domínio para analisar.")
            return
        alert = self.web_shield.analyze_url(url)
        if alert:
            self._add_web_alert_row(alert)
            self.web_status_lbl.setText(f"🚨 BLOQUEADO: '{url}' identificado como {alert.threat_name}!")
            self.web_status_lbl.setStyleSheet("color: #f87171; font-size: 12.5px; font-weight: 700;")
            self._append_log(f"🚨 [Escudo Web] URL perigosa detectada: {url} ({alert.threat_name})")
            QMessageBox.critical(
                self,
                "🚨 Alerta de Phishing / Ameaça Web!",
                f"O link analisado é PERIGOSO!\n\n"
                f"• URL: {url}\n"
                f"• Ameaça: {alert.threat_name}\n"
                f"• Camada: {alert.alert_type}\n"
                f"• Diagnóstico: {alert.details}",
            )
        else:
            self.web_status_lbl.setText(f"✅ Link seguro: '{url}' não apresenta indicadores de Phishing ou C2.")
            self.web_status_lbl.setStyleSheet("color: #6ee7b7; font-size: 12.5px; font-weight: 600;")
            QMessageBox.information(
                self,
                "✅ Link Verificado — Seguro",
                f"Nenhum indicador de Phishing, falsificação bancária ou malware foi encontrado em:\n{url}",
            )

    def test_phishing_url(self):
        self.url_input.setText("https://acesso-itau-seguranca-token.xyz/login.php")
        self.check_url_now()

    def scan_web_network_now(self):
        self.web_table.setRowCount(0)
        inspected, alerts = self.web_shield.scan_active_network_connections()
        for a in alerts:
            self._add_web_alert_row(a)
        msg = (
            f"🌐 Varredura de Rede concluída: {inspected} conexões externas ativas inspecionadas | "
            f"{len(alerts)} ameaça(s) de C2/Rede detectada(s)."
        )
        self.web_status_lbl.setText(msg)
        self._append_log(msg)

    def audit_browsers_now(self):
        self.web_table.setRowCount(0)
        audited, alerts = self.web_shield.audit_browsers_and_dns()
        for a in alerts:
            self._add_web_alert_row(a)
        msg = (
            f"🧭 Auditoria de Navegadores (Chrome, Edge, Brave) & DNS Hosts concluída: "
            f"{audited} extensões/configurações verificadas | {len(alerts)} alerta(s) encontrado(s)."
        )
        self.web_status_lbl.setText(msg)
        self._append_log(msg)

    def restore_quarantined_item(self):
        row = self.quarantine_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Quarentena", "Selecione um item na tabela da Quarentena para restaurar.")
            return
        item_id = self.quarantine_table.item(row, 0).text()
        ok, msg, sha256 = self.quarantine.restore_item(item_id)
        if ok:
            if sha256:
                self.db.add_to_whitelist(sha256, "Restaurado da Quarentena")
            self._append_log(f"♻️ Restaurado da Quarentena (ID {item_id}).")
            self._refresh_quarantine_table()
            QMessageBox.information(self, "Arquivo Restaurado", msg)
        else:
            QMessageBox.warning(self, "Erro ao Restaurar", msg)

    def delete_quarantined_item(self):
        row = self.quarantine_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Quarentena", "Selecione um item na tabela da Quarentena para excluir.")
            return
        item_id = self.quarantine_table.item(row, 0).text()
        ok, msg = self.quarantine.delete_permanently(item_id)
        if ok:
            self._append_log(f"🔥 {msg}")
            self._refresh_quarantine_table()
        else:
            QMessageBox.warning(self, "Erro ao Excluir", msg)

    # ================= ATUALIZAÇÃO ONLINE DE AMEAÇAS & AGENDAMENTO SEMANAL =================

    def _toggle_weekly_auto_update(self, checked: bool):
        ok, msg = register_weekly_update_task(checked)
        self._append_log(f"📅 {msg}")

    def _check_weekly_auto_update_due(self):
        """
        Verifica se já se passaram 7 dias desde a última atualização.
        Se sim (por exemplo, se o PC estava desligado no horário agendado), inicia a atualização silenciosa.
        """
        if not self.chk_weekly_auto.isChecked():
            return
        is_due, _, _ = self.updater.get_weekly_schedule_status(interval_days=7)
        if is_due:
            self._append_log("📅 Ciclo semanal de 7 dias atingido! Iniciando auto-atualização em segundo plano...")
            self.run_online_update(silent=True)

    def run_online_update(self, silent: bool = False):
        if self.update_worker and self.update_worker.isRunning():
            return
        self._is_silent_auto_update = silent
        self.btn_update_now.setEnabled(False)
        self.btn_update_now.setText("⏳ Atualizando Base de Ameaças Online...")
        if hasattr(self, "btn_banner_update"):
            self.btn_banner_update.setEnabled(False)
            self.btn_banner_update.setText("⏳ Atualizando...")
        self.upd_progress.setValue(5)
        self._append_log("Iniciando atualização online da base de vacinas (MalwareBazaar / OpenPhish / C2)...")

        self.update_worker = UpdateWorker(self.updater)
        self.update_worker.progress_changed.connect(self._on_update_progress)
        self.update_worker.update_completed.connect(self._on_update_completed)
        self.update_worker.start()

    def _on_update_progress(self, pct: int, status_txt: str):
        self.upd_progress.setValue(pct)
        self.statusBar().showMessage(status_txt)

    def _on_update_completed(self, ok: bool, msg: str, added_count: int):
        self.btn_update_now.setEnabled(True)
        self.btn_update_now.setText("🔄 Executar Atualização Manual Agora (Buscar Novas Ameaças Online)")
        if hasattr(self, "btn_banner_update"):
            self.btn_banner_update.setEnabled(True)
            self.btn_banner_update.setText("🔄 Atualizar Ameaças Agora")
        self._refresh_stats_ui()
        self._append_log(f"Atualização concluída (+{added_count} novas vacinas/indicadores).")
        if self._is_silent_auto_update:
            if hasattr(self, "tray"):
                self.tray.showMessage(
                    "🔄 SentinelAV — Auto-Atualização Semanal Concluída",
                    f"+{added_count} novas assinaturas de malware, phishing e C2 adicionadas.",
                    QSystemTrayIcon.MessageIcon.Information,
                    4000,
                )
        else:
            QMessageBox.information(self, "Atualização de Vacinas — SentinelAV", msg)

    def add_custom_hash_signature(self):
        h = self.custom_hash_edit.text().strip().lower()
        name = self.custom_name_edit.text().strip() or "Malware.Custom.UserDefined"
        if len(h) != 64 or not all(c in "0123456789abcdef" for c in h):
            QMessageBox.warning(
                self,
                "Hash Inválido",
                "Informe um hash SHA-256 válido contendo exatamente 64 caracteres hexadecimais.",
            )
            return
        self.db.add_bulk_hashes([(h, name, "CustomRule", "Crítica", "Manual/User")])
        self.custom_hash_edit.clear()
        self.custom_name_edit.clear()
        self._refresh_stats_ui()
        self._append_log(f"➕ Nova vacina SHA-256 cadastrada manualmente: {name} ({h[:16]}...)")
        QMessageBox.information(self, "Vacina Adicionada", f"Assinatura '{name}' adicionada ao banco de dados!")
