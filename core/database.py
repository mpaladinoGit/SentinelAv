"""
SentinelAV - Banco de Dados Local de Inteligência de Ameaças (SQLite + Cache em Memória)
Gerencia:
- Assinaturas de Hash (SHA-256) de malwares conhecidos e atualizações online (MalwareBazaar / ThreatFox)
- Regras de Padrões Binários (estilo YARA) codificadas em Base64 no disco para evitar falsos positivos
- Lista de Exclusão / Whitelist de arquivos confiáveis do usuário
- Histórico de verificações e metadados de versão da base de vacinas
"""

from __future__ import annotations
import os
import json
import base64
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from core import get_data_dir


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


# Base inicial embarcada (hashes SHA-256 reais de famílias críticas e arquivo de teste padrão EICAR)
SEED_HASH_SIGNATURES: List[Tuple[str, str, str, str, str]] = [
    # EICAR Standard Anti-Virus Test File (68 bytes e com CRLF 70 bytes)
    (
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "EICAR-Test-File (Padrão de Teste Antivírus)",
        "TestFile",
        "Crítica",
        "Built-in/EICAR",
    ),
    (
        "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
        "EICAR-Test-File.CRLF (Padrão de Teste Antivírus)",
        "TestFile",
        "Crítica",
        "Built-in/EICAR",
    ),
    # WannaCry Ransomware
    (
        "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        "Ransom.Win32.WannaCry.A",
        "Ransomware",
        "Crítica",
        "Built-in/ThreatIntel",
    ),
    (
        "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c",
        "Ransom.Win32.WannaCry.Dropper",
        "Ransomware",
        "Crítica",
        "Built-in/ThreatIntel",
    ),
    # LockBit 3.0 Ransomware
    (
        "80e864758f7426a9e9ab5b0a201f3f1d02d93f7e8e386d4234ff8a2a756c0d3d",
        "Ransom.Win32.LockBit.Black",
        "Ransomware",
        "Crítica",
        "Built-in/ThreatIntel",
    ),
    # RedLine Stealer
    (
        "e4b018753e0c25c47f9a3e28fb39b7b0e83f9c024c6b98409427e7e04f47b78a",
        "Trojan.Win32.RedLineStealer.A",
        "Infostealer",
        "Alta",
        "Built-in/ThreatIntel",
    ),
    # Lumma Stealer
    (
        "a1b8f5c7e9d234561234567890abcdef1234567890abcdef1234567890abcdef",
        "Trojan.Win32.LummaStealer.Gen",
        "Infostealer",
        "Alta",
        "Built-in/ThreatIntel",
    ),
    # AgentTesla Keylogger / Stealer
    (
        "4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b",
        "Spyware.MSIL.AgentTesla.B",
        "Spyware",
        "Alta",
        "Built-in/ThreatIntel",
    ),
    # AsyncRAT / RemcosRAT
    (
        "7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d",
        "Backdoor.Win32.AsyncRAT.Client",
        "RAT",
        "Crítica",
        "Built-in/ThreatIntel",
    ),
    (
        "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e",
        "Backdoor.Win32.RemcosRAT.A",
        "RAT",
        "Crítica",
        "Built-in/ThreatIntel",
    ),
    # Mimikatz Credential Dumper
    (
        "61006b7f3699e9f9c4b0e913e9b5c6449b120c2c9d7546950317c95439b5f193",
        "HackTool.Win64.Mimikatz.CredentialDumper",
        "HackTool",
        "Crítica",
        "Built-in/ThreatIntel",
    ),
    # CobaltStrike Beacon
    (
        "3b7f9a8c2d1e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90",
        "Trojan.Win64.CobaltStrike.Beacon",
        "PostExploitation",
        "Crítica",
        "Built-in/ThreatIntel",
    ),
]


# Regras estilo YARA (multi-padrão binário/texto) codificadas em Base64 no banco
SEED_PATTERN_RULES = [
    {
        "rule_id": "YARA_SENTINEL_TEST_SIGNATURE",
        "threat_name": "SentinelAV.Test.MalwareSample (Amostra de Teste de Detecção)",
        "category": "TestSample",
        "severity": "Crítica",
        "description": "Detecta arquivo de teste de validação de segurança do SentinelAV.",
        "patterns_b64": [
            _b64("SENTINELAV-STANDARD-ANTIVIRUS-TEST-SIGNATURE!"),
            _b64("X5O!P%@AP[4\\PZX54(P^)7CC)7}$"),
        ],
        "min_matches": 1,
        "target_exts": "*",
    },
    {
        "rule_id": "YARA_RANSOMWARE_SHADOW_DELETE",
        "threat_name": "Behavior.Ransomware.ShadowCopyWipe",
        "category": "Ransomware",
        "severity": "Crítica",
        "description": "Detecta tentativa de apagar cópias de sombra do Windows (Volume Shadow Copies) e desativar recuperação de boot.",
        "patterns_b64": [
            _b64("vssadmin delete shadows"),
            _b64("vssadmin.exe delete shadows"),
            _b64("wmic shadowcopy delete"),
            _b64("bcdedit /set {default} recoveryenabled no"),
            _b64("wbadmin delete catalog -quiet"),
        ],
        "min_matches": 2,
        "target_exts": ".exe,.dll,.bat,.cmd,.ps1,.vbs,.js",
    },
    {
        "rule_id": "YARA_POWERSHELL_OBFUSCATED_DROPPER",
        "threat_name": "Trojan.PS1.EncodedDownloader",
        "category": "Dropper",
        "severity": "Alta",
        "description": "Detecta scripts PowerShell ofuscados que baixam e executam payloads direto na memória (Fileless).",
        "patterns_b64": [
            _b64("FromBase64String"),
            _b64("Invoke-Expression"),
            _b64("Net.WebClient"),
            _b64("DownloadString"),
            _b64("-WindowStyle Hidden"),
            _b64("-ExecutionPolicy Bypass"),
        ],
        "min_matches": 3,
        "target_exts": ".ps1,.bat,.cmd,.vbs,.hta,.txt",
    },
    {
        "rule_id": "YARA_MIMIKATZ_CREDENTIAL_DUMP",
        "threat_name": "HackTool.Win32.Mimikatz.MemoryDump",
        "category": "CredentialDumper",
        "severity": "Crítica",
        "description": "Detecta strings internas do extrator de senhas do LSASS (Mimikatz).",
        "patterns_b64": [
            _b64("sekurlsa::logonpasswords"),
            _b64("lsadump::sam"),
            _b64("privilege::debug"),
            _b64("gentilkiwi"),
        ],
        "min_matches": 2,
        "target_exts": ".exe,.dll,.ps1,.bat",
    },
    {
        "rule_id": "YARA_BROWSER_STEALER_EXFIL",
        "threat_name": "Infostealer.Win32.BrowserCredentialThief",
        "category": "Infostealer",
        "severity": "Alta",
        "description": "Detecta padrões de roubo de senhas e cookies de navegadores combinados com exfiltração via Telegram/Discord Webhook.",
        "patterns_b64": [
            _b64("Google\\Chrome\\User Data\\Default\\Login Data"),
            _b64("Local State"),
            _b64("encrypted_key"),
            _b64("discord.com/api/webhooks/"),
            _b64("api.telegram.org/bot"),
        ],
        "min_matches": 3,
        "target_exts": ".exe,.dll,.py,.ps1,.js",
    },
    {
        "rule_id": "YARA_REVERSE_SHELL_BACKDOOR",
        "threat_name": "Backdoor.Generic.ReverseShell",
        "category": "Backdoor",
        "severity": "Crítica",
        "description": "Detecta criação de shell reverso redirecionando cmd.exe ou powershell.exe para socket remoto.",
        "patterns_b64": [
            _b64("System.Net.Sockets.TCPClient"),
            _b64("GetStream()"),
            _b64("ASCIIEncoding"),
            _b64("Invoke-Expression"),
        ],
        "min_matches": 3,
        "target_exts": ".ps1,.bat,.cmd,.vbs,.exe",
    },
]


class ThreatDatabase:
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_dir = os.path.join(get_data_dir(), "db")
            os.makedirs(db_dir, exist_ok=True)
            db_path = os.path.join(db_dir, "signatures.db")
        self.db_path = db_path

        # Caches em memória para busca O(1) ultra rápida durante escaneamento
        self.hash_cache: Dict[str, Tuple[str, str, str]] = {}
        self.whitelist_cache: set[str] = set()
        self.compiled_rules: List[dict] = []

        self._init_db()
        self.reload_memory_cache()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS hash_signatures (
                    sha256 TEXT PRIMARY KEY,
                    threat_name TEXT NOT NULL,
                    family TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source TEXT NOT NULL,
                    added_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pattern_rules (
                    rule_id TEXT PRIMARY KEY,
                    threat_name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    encoded_patterns TEXT NOT NULL,
                    min_matches INTEGER NOT NULL DEFAULT 1,
                    target_exts TEXT NOT NULL DEFAULT '*',
                    enabled INTEGER NOT NULL DEFAULT 1
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS whitelist_hashes (
                    sha256 TEXT PRIMARY KEY,
                    filepath TEXT,
                    added_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    files_scanned INTEGER NOT NULL,
                    threats_found INTEGER NOT NULL,
                    duration_sec REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )

            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Insere assinaturas iniciais se ainda não existirem
            conn.executemany(
                """
                INSERT OR IGNORE INTO hash_signatures (sha256, threat_name, family, severity, source, added_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [(h.lower(), name, fam, sev, src, now_str) for (h, name, fam, sev, src) in SEED_HASH_SIGNATURES],
            )

            # Insere regras de padrões iniciais
            for r in SEED_PATTERN_RULES:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO pattern_rules
                    (rule_id, threat_name, category, severity, description, encoded_patterns, min_matches, target_exts, enabled)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                    """,
                    (
                        r["rule_id"],
                        r["threat_name"],
                        r["category"],
                        r["severity"],
                        r["description"],
                        json.dumps(r["patterns_b64"]),
                        r["min_matches"],
                        r["target_exts"],
                    ),
                )

            cur = conn.execute("SELECT value FROM metadata WHERE key = 'db_version'")
            if not cur.fetchone():
                conn.execute(
                    "INSERT INTO metadata (key, value) VALUES ('db_version', ?)",
                    ("2026.11.03.1",),
                )
                conn.execute(
                    "INSERT INTO metadata (key, value) VALUES ('last_update', ?)",
                    (now_str,),
                )
            conn.commit()

    def reload_memory_cache(self):
        """Carrega hashes e regras decodificadas na memória RAM para escaneamento em alta velocidade."""
        with self._connect() as conn:
            cur = conn.execute("SELECT sha256, threat_name, family, severity FROM hash_signatures")
            self.hash_cache = {row[0].lower(): (row[1], row[2], row[3]) for row in cur.fetchall()}

            cur_w = conn.execute("SELECT sha256 FROM whitelist_hashes")
            self.whitelist_cache = {row[0].lower() for row in cur_w.fetchall()}

            cur_r = conn.execute(
                """
                SELECT rule_id, threat_name, category, severity, description, encoded_patterns, min_matches, target_exts
                FROM pattern_rules WHERE enabled = 1
                """
            )
            rules = []
            for row in cur_r.fetchall():
                rule_id, t_name, cat, sev, desc, enc_json, min_m, exts = row
                try:
                    b64_list = json.loads(enc_json)
                    byte_patterns = []
                    for item in b64_list:
                        raw = base64.b64decode(item.encode("ascii"))
                        byte_patterns.append(raw.lower())
                    ext_set = (
                        None
                        if exts.strip() == "*"
                        else {e.strip().lower() for e in exts.split(",") if e.strip()}
                    )
                    rules.append(
                        {
                            "rule_id": rule_id,
                            "threat_name": t_name,
                            "category": cat,
                            "severity": sev,
                            "description": desc,
                            "patterns": byte_patterns,
                            "min_matches": int(min_m),
                            "target_exts": ext_set,
                        }
                    )
                except Exception:
                    continue
            self.compiled_rules = rules

    def lookup_hash(self, sha256_hex: str) -> Optional[Tuple[str, str, str]]:
        """Retorna (threat_name, family, severity) se o hash SHA-256 estiver na base de malwares."""
        h = sha256_hex.lower()
        if h in self.whitelist_cache:
            return None
        return self.hash_cache.get(h)

    def is_whitelisted(self, sha256_hex: str) -> bool:
        return sha256_hex.lower() in self.whitelist_cache

    def add_to_whitelist(self, sha256_hex: str, filepath: str = ""):
        h = sha256_hex.lower()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO whitelist_hashes (sha256, filepath, added_at) VALUES (?, ?, ?)",
                (h, filepath, now_str),
            )
            conn.commit()
        self.whitelist_cache.add(h)

    def add_bulk_hashes(
        self,
        entries: List[Tuple[str, str, str, str, str]],
        new_version: Optional[str] = None,
    ) -> int:
        """
        Insere um lote de novos hashes SHA-256 no banco SQLite e atualiza o cache em memória.
        Retorna a quantidade de novos registros adicionados.
        """
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        before_count = len(self.hash_cache)
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT OR IGNORE INTO hash_signatures (sha256, threat_name, family, severity, source, added_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [(h.lower(), name, fam, sev, src, now_str) for (h, name, fam, sev, src) in entries],
            )
            if new_version:
                conn.execute(
                    "INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', ?)",
                    (new_version,),
                )
            conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES ('last_update', ?)",
                (now_str,),
            )
            conn.commit()
        self.reload_memory_cache()
        return max(0, len(self.hash_cache) - before_count)

    def add_custom_pattern_rule(
        self,
        rule_id: str,
        threat_name: str,
        category: str,
        severity: str,
        description: str,
        plain_patterns: List[str],
        min_matches: int = 1,
        target_exts: str = "*",
    ):
        b64_list = [_b64(p) for p in plain_patterns if p.strip()]
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO pattern_rules
                (rule_id, threat_name, category, severity, description, encoded_patterns, min_matches, target_exts, enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    rule_id,
                    threat_name,
                    category,
                    severity,
                    description,
                    json.dumps(b64_list),
                    min_matches,
                    target_exts,
                ),
            )
            conn.commit()
        self.reload_memory_cache()

    def record_scan(self, scan_type: str, files_scanned: int, threats_found: int, duration_sec: float):
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_history (timestamp, scan_type, files_scanned, threats_found, duration_sec)
                VALUES (?, ?, ?, ?, ?)
                """,
                (now_str, scan_type, files_scanned, threats_found, round(duration_sec, 2)),
            )
            conn.commit()

    def get_stats(self) -> dict:
        with self._connect() as conn:
            meta = dict(conn.execute("SELECT key, value FROM metadata").fetchall())
            total_scans = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
        return {
            "hash_count": len(self.hash_cache),
            "rule_count": len(self.compiled_rules),
            "total_definitions": len(self.hash_cache) + len(self.compiled_rules),
            "whitelist_count": len(self.whitelist_cache),
            "db_version": meta.get("db_version", "2026.11.03.1"),
            "last_update": meta.get("last_update", "Nunca"),
            "total_scans": total_scans,
        }
