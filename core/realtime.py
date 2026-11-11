"""
SentinelAV - Escudo de Proteção em Tempo Real (On-Access Directory Watcher & Anti-Ransomware Canary)
Vigiar em segundo plano as pastas críticas do usuário (Downloads, Área de Trabalho, Inicialização, Amostras)
usando notificações nativas do sistema operacional (QFileSystemWatcher) e monitora arquivos-isca (Canary)
contra criptografia em massa por Ransomware.
"""

from __future__ import annotations
import os
import hashlib
from typing import Dict, List, Set
from PyQt6.QtCore import QObject, QFileSystemWatcher, QTimer, pyqtSignal

from core import get_data_dir, get_app_base_dir
from core.scanner import SentinelScanner, ThreatDetection


CANARY_CONTENT = (
    b"SENTINELAV-ANTI-RANSOMWARE-HONEYPOT-CANARY-DO-NOT-MODIFY-2026\n"
    b"Qualquer alteracao nao autorizada neste arquivo-isca dispara bloqueio anti-ransomware."
)
CANARY_SHA256 = hashlib.sha256(CANARY_CONTENT).hexdigest().lower()


class RealTimeShield(QObject):
    threat_detected = pyqtSignal(object)  # Emite ThreatDetection
    activity_logged = pyqtSignal(str)

    def __init__(self, scanner: SentinelScanner, parent=None):
        super().__init__(parent)
        self.scanner = scanner
        self.enabled = True
        self.auto_quarantine = False

        self.watcher = QFileSystemWatcher(self)
        self.watcher.directoryChanged.connect(self._on_directory_changed)
        self.watcher.fileChanged.connect(self._on_file_changed)

        self._known_files_mtime: Dict[str, int] = {}
        self._watched_dirs: List[str] = []
        self._canary_path = os.path.join(get_data_dir(), "!_Sentinel_Canary_Honeypot.dat")

        self._setup_canary()
        self._setup_watched_directories()

        # Timer leve para verificar integridade do Canary Anti-Ransomware
        self._canary_timer = QTimer(self)
        self._canary_timer.setInterval(8000)
        self._canary_timer.timeout.connect(self._check_canary_integrity)
        self._canary_timer.start()

    def _setup_canary(self):
        """Planta o arquivo-isca (Honeypot) usado para detecção de criptografia de Ransomware."""
        try:
            with open(self._canary_path, "wb") as f:
                f.write(CANARY_CONTENT)
            self.watcher.addPath(self._canary_path)
        except Exception:
            pass

    def _setup_watched_directories(self):
        user_home = os.path.expanduser("~")
        appdata = os.environ.get("APPDATA", "")
        samples_dir = os.path.join(get_app_base_dir(), "samples")
        os.makedirs(samples_dir, exist_ok=True)

        dirs = [
            samples_dir,
            os.path.join(user_home, "Downloads"),
            os.path.join(user_home, "Desktop"),
            os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        ]
        for d in dirs:
            if d and os.path.isdir(d):
                abs_d = os.path.abspath(d)
                self._watched_dirs.append(abs_d)
                self.watcher.addPath(abs_d)
                self._snapshot_directory(abs_d)

    def _snapshot_directory(self, dir_path: str):
        try:
            for entry in os.scandir(dir_path):
                if entry.is_file(follow_symlinks=False):
                    try:
                        self._known_files_mtime[entry.path] = entry.stat().st_mtime_ns
                    except Exception:
                        pass
        except Exception:
            pass

    def set_enabled(self, active: bool):
        self.enabled = active
        state_txt = "ATIVADO" if active else "PAUSADO"
        self.activity_logged.emit(f"Escudo em Tempo Real {state_txt}.")

    def _on_directory_changed(self, dir_path: str):
        if not self.enabled or not os.path.isdir(dir_path):
            return
        try:
            for entry in os.scandir(dir_path):
                if not entry.is_file(follow_symlinks=False):
                    continue
                fpath = entry.path
                try:
                    mtime = entry.stat().st_mtime_ns
                except Exception:
                    continue

                prev_mtime = self._known_files_mtime.get(fpath)
                if prev_mtime != mtime:
                    self._known_files_mtime[fpath] = mtime
                    # Ignora arquivos temporários de download incompleto do navegador
                    if fpath.lower().endswith((".crdownload", ".part", ".tmp")):
                        continue
                    self.activity_logged.emit(f"[Tempo Real] Inspecionando novo arquivo: {os.path.basename(fpath)}")
                    hit = self.scanner.scan_file(fpath)
                    if hit:
                        self.threat_detected.emit(hit)
        except Exception:
            pass

    def _on_file_changed(self, filepath: str):
        if not self.enabled:
            return
        if os.path.normcase(filepath) == os.path.normcase(self._canary_path):
            self._check_canary_integrity()

    def _check_canary_integrity(self):
        if not self.enabled:
            return
        try:
            if not os.path.exists(self._canary_path):
                self._setup_canary()
                return
            with open(self._canary_path, "rb") as f:
                data = f.read()
            if hashlib.sha256(data).hexdigest().lower() != CANARY_SHA256:
                # Restaura canary e emite alerta de alteração em arquivo-isca
                self._setup_canary()
                self.activity_logged.emit("⚠️ Alerta Anti-Ransomware: Arquivo-isca (Canary) sofreu modificação!")
        except Exception:
            pass
