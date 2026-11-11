"""
SentinelAV - Motor Multicamada de Detecção de Ameaças (Scanner Engine)
Camadas de inspeção:
1. Motor de Hash Criptográfico (SHA-256) com busca O(1) em memória
2. Motor de Regras de Padrões Binários (estilo YARA) para payloads, scripts e comandos maliciosos
3. Motor Heurístico de Executáveis PE (Entropia de Shannon, Seções RWX, Packers, Tabela IAT e Assinatura Authenticode)
4. Scanner de Processos Ativos na Memória RAM (via psutil)
"""

from __future__ import annotations
import os
import time
import hashlib
from dataclasses import dataclass, field
from typing import Callable, List, Optional
import psutil

from core import get_data_dir, get_app_base_dir
from core.database import ThreatDatabase
from core.heuristics import analyze_pe_heuristics, check_double_extension


SKIP_DIRS = {
    "$recycle.bin",
    "system volume information",
    "winSxS",
    ".git",
    "node_modules",
    "__pycache__",
}

MAX_SCAN_FILE_SIZE = 120 * 1024 * 1024  # 120 MB por arquivo para manter rapidez
MAX_PATTERN_READ_BYTES = 4 * 1024 * 1024  # 4 MB para varredura de padrões binários


@dataclass
class ThreatDetection:
    filepath: str
    sha256: str
    threat_name: str
    category: str
    severity: str
    engine: str
    details: List[str] = field(default_factory=list)
    pid: Optional[int] = None
    process_name: Optional[str] = None


class SentinelScanner:
    def __init__(self, db: ThreatDatabase):
        self.db = db
        self._protected_data_dir = os.path.normcase(os.path.abspath(get_data_dir()))
        self._app_base_dir = os.path.normcase(os.path.abspath(get_app_base_dir()))

    def _is_internal_protected_path(self, filepath: str) -> bool:
        """Evita escanear o próprio cofre de quarentena ou banco de dados SQLite do SentinelAV."""
        norm = os.path.normcase(os.path.abspath(filepath))
        if norm.startswith(self._protected_data_dir):
            return True
        # Ignora os próprios arquivos de código/executáveis do SentinelAV exceto a pasta de amostras de teste
        samples_dir = os.path.normcase(os.path.join(self._app_base_dir, "samples"))
        if norm.startswith(self._app_base_dir) and not norm.startswith(samples_dir):
            return True
        return False

    @staticmethod
    def compute_sha256_and_head(filepath: str) -> Tuple[Optional[str], bytes]:
        """Calcula o SHA-256 do arquivo e retorna também os primeiros 4 MB para análise de padrões."""
        h = hashlib.sha256()
        head_chunks: List[bytes] = []
        head_len = 0
        try:
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(131072)
                    if not chunk:
                        break
                    h.update(chunk)
                    if head_len < MAX_PATTERN_READ_BYTES:
                        take = chunk[: MAX_PATTERN_READ_BYTES - head_len]
                        head_chunks.append(take)
                        head_len += len(take)
            return h.hexdigest().lower(), b"".join(head_chunks)
        except Exception:
            return None, b""

    def scan_file(
        self,
        filepath: str,
        pid: Optional[int] = None,
        process_name: Optional[str] = None,
    ) -> Optional[ThreatDetection]:
        """
        Executa a inspeção multicamada em um único arquivo do sistema.
        Retorna ThreatDetection se uma ameaça for detectada, ou None se estiver limpo.
        """
        try:
            if not filepath or not os.path.isfile(filepath):
                return None
            if self._is_internal_protected_path(filepath):
                return None

            st = os.stat(filepath)
            if st.st_size == 0 or st.st_size > MAX_SCAN_FILE_SIZE:
                return None

            sha256_hex, head_bytes = self.compute_sha256_and_head(filepath)
            if not sha256_hex:
                return None

            # 0. Verifica se o arquivo está na lista de confiança (Whitelist) do usuário
            if self.db.is_whitelisted(sha256_hex):
                return None

            # 1. Camada 1: Banco de Assinaturas SHA-256
            hash_hit = self.db.lookup_hash(sha256_hex)
            if hash_hit:
                t_name, family, severity = hash_hit
                return ThreatDetection(
                    filepath=os.path.abspath(filepath),
                    sha256=sha256_hex,
                    threat_name=t_name,
                    category=family,
                    severity=severity,
                    engine="Assinatura SHA-256",
                    details=[f"Hash SHA-256 confirmado na base de inteligência ({sha256_hex[:16]}...)"],
                    pid=pid,
                    process_name=process_name,
                )

            # 2. Camada 2: Motor de Regras de Padrões Binários (YARA-compatible)
            ext = os.path.splitext(filepath)[1].lower()
            head_lower = head_bytes.lower()
            for rule in self.db.compiled_rules:
                target_exts = rule["target_exts"]
                if target_exts is not None and ext not in target_exts:
                    continue
                matched_count = 0
                for pat in rule["patterns"]:
                    if pat in head_lower:
                        matched_count += 1
                        if matched_count >= rule["min_matches"]:
                            return ThreatDetection(
                                filepath=os.path.abspath(filepath),
                                sha256=sha256_hex,
                                threat_name=rule["threat_name"],
                                category=rule["category"],
                                severity=rule["severity"],
                                engine=f"Motor YARA ({rule['rule_id']})",
                                details=[rule["description"]],
                                pid=pid,
                                process_name=process_name,
                            )

            # 3. Camada 3: Análise Heurística Estática PE (IAT, Entropia, RWX, Masquerade, Authenticode)
            heur_hit = analyze_pe_heuristics(filepath)
            if heur_hit:
                t_name, cat, sev, indicators = heur_hit
                return ThreatDetection(
                    filepath=os.path.abspath(filepath),
                    sha256=sha256_hex,
                    threat_name=t_name,
                    category=cat,
                    severity=sev,
                    engine="Heurística Estática PE",
                    details=indicators,
                    pid=pid,
                    process_name=process_name,
                )

            return None
        except Exception:
            return None

    def collect_files(
        self,
        paths: List[str],
        max_files: int = 15000,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> List[str]:
        """Coleta os arquivos elegíveis para escaneamento a partir de uma lista de pastas ou arquivos."""
        collected: List[str] = []
        for p in paths:
            if cancel_check and cancel_check():
                break
            if not p or not os.path.exists(p):
                continue
            if os.path.isfile(p):
                if not self._is_internal_protected_path(p):
                    collected.append(os.path.abspath(p))
                continue

            for root, dirs, files in os.walk(p, topdown=True):
                if cancel_check and cancel_check():
                    break
                # Filtra pastas de sistema/cache desnecessárias
                dirs[:] = [
                    d
                    for d in dirs
                    if d.lower() not in SKIP_DIRS
                    and not self._is_internal_protected_path(os.path.join(root, d))
                ]
                for fname in files:
                    fpath = os.path.join(root, fname)
                    if not self._is_internal_protected_path(fpath):
                        collected.append(fpath)
                        if len(collected) >= max_files:
                            return collected
        return collected

    @staticmethod
    def get_quick_scan_directories() -> List[str]:
        """Retorna os diretórios críticos do Windows visados por malwares em uma Verificação Rápida."""
        user_home = os.path.expanduser("~")
        appdata = os.environ.get("APPDATA", "")
        local_appdata = os.environ.get("LOCALAPPDATA", "")
        temp_dir = os.environ.get("TEMP", "")

        candidates = [
            os.path.join(get_app_base_dir(), "samples"),
            os.path.join(user_home, "Downloads"),
            os.path.join(user_home, "Desktop"),
            os.path.join(
                appdata,
                "Microsoft",
                "Windows",
                "Start Menu",
                "Programs",
                "Startup",
            ),
            temp_dir,
            os.path.join(local_appdata, "Temp"),
        ]
        unique_dirs: List[str] = []
        seen = set()
        for d in candidates:
            if d and os.path.isdir(d):
                norm = os.path.normcase(os.path.abspath(d))
                if norm not in seen:
                    seen.add(norm)
                    unique_dirs.append(os.path.abspath(d))
        return unique_dirs

    def scan_running_processes(
        self,
        progress_cb: Optional[Callable[[int, int, str], None]] = None,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> Tuple[int, List[ThreatDetection]]:
        """
        Escaneia todos os processos em execução na memória RAM do Windows.
        Verifica tanto o executável em disco quanto argumentos de linha de comando maliciosos.
        """
        procs = []
        for p in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                procs.append(p.info)
            except Exception:
                continue

        total = len(procs)
        threats: List[ThreatDetection] = []
        scanned_exes: dict[str, Optional[ThreatDetection]] = {}

        for idx, info in enumerate(procs, start=1):
            if cancel_check and cancel_check():
                break
            pid = info.get("pid")
            name = info.get("name") or f"PID-{pid}"
            exe_path = info.get("exe") or ""
            cmdline_list = info.get("cmdline") or []
            cmdline_str = " ".join(cmdline_list).lower()

            if progress_cb:
                progress_cb(idx, total, f"Processo [{pid}] {name}")

            # 1. Verifica argumentos Fileless na linha de comando (ex: PowerShell oculto / Shadow Copy delete)
            if "vssadmin delete shadows" in cmdline_str or "wmic shadowcopy delete" in cmdline_str:
                threats.append(
                    ThreatDetection(
                        filepath=exe_path or name,
                        sha256="process-memory-cmdline",
                        threat_name="Behavior.Memory.ShadowCopyWipe",
                        category="Ransomware.Memory",
                        severity="Crítica",
                        engine="Monitor Comportamental de Processos",
                        details=[f"Linha de comando maliciosa detectada em execução: {cmdline_str[:120]}"],
                        pid=pid,
                        process_name=name,
                    )
                )
                continue

            if exe_path and os.path.isfile(exe_path):
                norm_exe = os.path.normcase(os.path.abspath(exe_path))
                if norm_exe not in scanned_exes:
                    scanned_exes[norm_exe] = self.scan_file(exe_path, pid=pid, process_name=name)
                hit = scanned_exes[norm_exe]
                if hit:
                    threats.append(
                        ThreatDetection(
                            filepath=hit.filepath,
                            sha256=hit.sha256,
                            threat_name=hit.threat_name,
                            category=hit.category,
                            severity=hit.severity,
                            engine=f"{hit.engine} (Memória RAM)",
                            details=hit.details,
                            pid=pid,
                            process_name=name,
                        )
                    )

        return total, threats


def create_safe_test_samples() -> List[str]:
    """
    Cria amostras de teste 100% inofensivas na pasta 'samples' do SentinelAV
    para que o usuário possa testar a detecção por YARA, Heurística e Quarentena ao vivo.
    """
    samples_dir = os.path.join(get_app_base_dir(), "samples")
    os.makedirs(samples_dir, exist_ok=True)

    created = []

    # Amostra 1: Assinatura de Teste Padrão SentinelAV
    sample1 = os.path.join(samples_dir, "teste_assinatura_malware_simulado.txt")
    with open(sample1, "w", encoding="utf-8") as f:
        f.write(
            "ARQUIVO INOFENSIVO DE TESTE DE ANTIVIRUS\n"
            "Este arquivo contem a assinatura de validacao para testar o motor do SentinelAV:\n"
            "SENTINELAV-STANDARD-ANTIVIRUS-TEST-SIGNATURE!\n"
        )
    created.append(sample1)

    # Amostra 2: Simulação de Script Dropper / Ransomware Comportamental (comentado/inofensivo)
    sample2 = os.path.join(samples_dir, "simulacao_ransomware_shadowcopy.bat")
    with open(sample2, "w", encoding="utf-8") as f:
        f.write(
            "@echo off\n"
            "REM Arquivo de teste inofensivo para validar deteccao comportamental YARA\n"
            "REM vssadmin delete shadows /all /quiet\n"
            "REM wmic shadowcopy delete\n"
            "REM bcdedit /set {default} recoveryenabled no\n"
            "echo Teste de deteccao SentinelAV\n"
        )
    created.append(sample2)

    return created
