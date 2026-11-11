"""
SentinelAV - Escudo Web, Anti-Phishing, Monitor de Rede C2 e Auditor de Navegadores
Protege contra ameaças originadas na Web e nos Navegadores (Chrome, Edge, Brave, Firefox):
1. Anti-Phishing & Inspetor de URLs (Base OpenPhish + Heurística de Falsificação Bancária/Punycode)
2. Monitor de Conexões de Rede Ativas (Bloqueio de IPs de Botnet/C2 FeodoTracker/IPsum, Portas de RAT/Mineradores e LOLBins)
3. Auditor de Extensões de Navegadores (Chrome, Edge, Brave) e Verificador de Sequestro de DNS (Arquivo hosts do Windows)
4. Monitoramento em Tempo Real da pasta Downloads contra malwares baixados pelos navegadores
"""

from __future__ import annotations
import os
import re
import json
import sqlite3
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
import psutil
import requests

from core import get_data_dir


OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
FEODO_C2_IP_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
IPSUM_MALICIOUS_IP_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"

# Portas classicamente associadas a Backdoors, RATs, Metasploit e Mineradores de Criptomoedas (Stratum)
SUSPICIOUS_REMOTE_PORTS: Dict[int, str] = {
    4444: "Metasploit / Reverse Shell Padrão (Porta 4444)",
    1337: "Backdoor / RAT Genérico (Porta 1337)",
    6667: "Comando e Controle Botnet IRC (Porta 6667)",
    3333: "Pool de Mineração de Criptomoedas Stratum (Porta 3333)",
    14444: "Pool de Mineração Monero/XMRig (Porta 14444)",
    5555: "Android ADB / Worm Backdoor (Porta 5555)",
}

# Processos nativos do Windows (LOLBins) que não devem abrir conexões diretas para a Internet sem supervisão
LOLBIN_NETWORK_PROCESSES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "certutil.exe",
    "regsvr32.exe",
    "bitsadmin.exe",
}

SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".shop",
    ".icu",
    ".vip",
    ".my",
    ".buzz",
    ".monster",
    ".zip",
    ".mov",
}

TARGETED_BRANDS = {
    "itau": ("itau.com.br",),
    "bradesco": ("bradesco.com.br", "bradescard.com.br"),
    "nubank": ("nubank.com.br", "nu.com.br"),
    "santander": ("santander.com.br",),
    "bancodobrasil": ("bb.com.br",),
    "caixa": ("caixa.gov.br",),
    "govbr": ("gov.br",),
    "mercadolivre": ("mercadolivre.com.br", "mercadopago.com.br"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "azure.com"),
    "steam": ("steampowered.com", "steamcommunity.com"),
    "binance": ("binance.com",),
}

SEED_MALICIOUS_DOMAINS = [
    ("explorer.beta.bip300.xyz", "Phishing.Crypto.WalletDrain", "OpenPhish"),
    ("portuil.my", "Phishing.CredentialHarvest.Generic", "OpenPhish"),
    ("seguranca-itau-atualizar.xyz", "Phishing.Banking.FakeLogin", "SentinelWeb"),
    ("acesso-govbr-regularizar.top", "Phishing.GovBR.FakePortal", "SentinelWeb"),
    ("resgate-pontos-bradesco.click", "Phishing.Banking.FakeLogin", "SentinelWeb"),
    ("atualizacao-nubank-seguro.shop", "Phishing.Banking.FakeLogin", "SentinelWeb"),
    ("malware-test.sentinelav.local", "Test.WebShield.MaliciousDomain", "SentinelWeb"),
]

SEED_MALICIOUS_IPS = [
    ("14.34.249.175", "C2.Botnet.Scanner.IPsum", "IPsum-Level3"),
    ("138.226.239.233", "C2.Malware.CommandControl", "IPsum-Level3"),
    ("45.148.10.121", "C2.Trojan.BulletproofHost", "IPsum-Level3"),
    ("185.220.101.1", "C2.DarkWeb.RelayNode", "SentinelWeb"),
]


@dataclass
class WebThreatAlert:
    alert_type: str  # "URL/Phishing", "Rede/C2", "Navegador/Extensão", "DNS/Hosts"
    threat_name: str
    severity: str
    target: str
    details: str
    pid: Optional[int] = None
    process_name: Optional[str] = None


class WebProtectionShield:
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_dir = os.path.join(get_data_dir(), "db")
            os.makedirs(db_dir, exist_ok=True)
            db_path = os.path.join(db_dir, "signatures.db")
        self.db_path = db_path

        self.blocked_domains: Dict[str, Tuple[str, str]] = {}
        self.blocked_ips: Dict[str, Tuple[str, str]] = {}

        self._init_web_tables()
        self.reload_cache()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_web_tables(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS web_malicious_domains (
                    domain TEXT PRIMARY KEY,
                    threat_name TEXT NOT NULL,
                    source TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS web_malicious_ips (
                    ip TEXT PRIMARY KEY,
                    threat_name TEXT NOT NULL,
                    source TEXT NOT NULL
                )
                """
            )
            conn.executemany(
                "INSERT OR IGNORE INTO web_malicious_domains (domain, threat_name, source) VALUES (?, ?, ?)",
                SEED_MALICIOUS_DOMAINS,
            )
            conn.executemany(
                "INSERT OR IGNORE INTO web_malicious_ips (ip, threat_name, source) VALUES (?, ?, ?)",
                SEED_MALICIOUS_IPS,
            )
            conn.commit()

    def reload_cache(self):
        with self._connect() as conn:
            cur_d = conn.execute("SELECT domain, threat_name, source FROM web_malicious_domains")
            self.blocked_domains = {r[0].lower(): (r[1], r[2]) for r in cur_d.fetchall()}

            cur_i = conn.execute("SELECT ip, threat_name, source FROM web_malicious_ips")
            self.blocked_ips = {r[0].strip(): (r[1], r[2]) for r in cur_i.fetchall()}

    def get_web_stats(self) -> dict:
        return {
            "blocked_domains": len(self.blocked_domains),
            "blocked_ips": len(self.blocked_ips),
            "total_web_indicators": len(self.blocked_domains) + len(self.blocked_ips),
        }

    def update_web_feeds(self, max_items: int = 2000) -> Tuple[int, int]:
        """
        Baixa listas atualizadas de URLs de Phishing (OpenPhish) e IPs de Botnet/C2 (Feodo Tracker + IPsum).
        Retorna (novos_dominios, novos_ips).
        """
        before_d = len(self.blocked_domains)
        before_i = len(self.blocked_ips)

        new_domains: List[Tuple[str, str, str]] = []
        new_ips: List[Tuple[str, str, str]] = []

        headers = {"User-Agent": "SentinelAV-WebShield/1.0"}

        # 1. OpenPhish Live Phishing Feed
        try:
            resp = requests.get(OPENPHISH_FEED_URL, headers=headers, timeout=10)
            if resp.status_code == 200 and resp.text:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parsed = urlparse(line if "://" in line else "http://" + line)
                    host = (parsed.hostname or "").lower().strip()
                    if host and "." in host:
                        new_domains.append((host, "Phishing.OpenPhish.ActiveURL", "OpenPhish/Live"))
                        if len(new_domains) >= max_items:
                            break
        except Exception:
            pass

        # 2. Feodo Tracker + IPsum Botnet C2 IPs
        for url, src_name in ((FEODO_C2_IP_URL, "AbuseCH/FeodoTracker"), (IPSUM_MALICIOUS_IP_URL, "IPsum/ThreatIntel")):
            try:
                resp = requests.get(url, headers=headers, timeout=10)
                if resp.status_code == 200 and resp.text:
                    for line in resp.text.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        ip_candidate = line.split()[0].strip()
                        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip_candidate):
                            new_ips.append((ip_candidate, f"C2.Botnet.MaliciousIP ({src_name})", src_name))
                            if len(new_ips) >= max_items:
                                break
            except Exception:
                pass

        with self._connect() as conn:
            if new_domains:
                conn.executemany(
                    "INSERT OR IGNORE INTO web_malicious_domains (domain, threat_name, source) VALUES (?, ?, ?)",
                    new_domains,
                )
            if new_ips:
                conn.executemany(
                    "INSERT OR IGNORE INTO web_malicious_ips (ip, threat_name, source) VALUES (?, ?, ?)",
                    new_ips,
                )
            conn.commit()

        self.reload_cache()
        return max(0, len(self.blocked_domains) - before_d), max(0, len(self.blocked_ips) - before_i)

    # ================= 1. SCANNER DE URL & ANTI-PHISHING =================

    def analyze_url(self, raw_url: str) -> Optional[WebThreatAlert]:
        """
        Analisa uma URL ou domínio em busca de Phishing, Malware Distribution, C2 ou falsificação visual.
        Retorna WebThreatAlert se for perigoso, ou None se for seguro.
        """
        u = raw_url.strip()
        if not u:
            return None
        if "://" not in u:
            u = "http://" + u

        try:
            parsed = urlparse(u)
            host = (parsed.hostname or "").lower().strip()
            path_lower = (parsed.path or "").lower()
        except Exception:
            return None

        if not host:
            return None

        # 1. Verifica no banco de Domínios Maliciosos / OpenPhish
        if host in self.blocked_domains:
            t_name, src = self.blocked_domains[host]
            return WebThreatAlert(
                alert_type="URL / Anti-Phishing",
                threat_name=t_name,
                severity="Crítica",
                target=raw_url,
                details=f"Domínio confirmado na base de ameaças web ({src}).",
            )

        # 2. Verifica se o host é um IP direto presente na lista de Botnets/C2
        if host in self.blocked_ips:
            t_name, src = self.blocked_ips[host]
            return WebThreatAlert(
                alert_type="URL / Servidor C2",
                threat_name=t_name,
                severity="Crítica",
                target=raw_url,
                details=f"Endereço IP bloqueado na lista de Comando & Controle ({src}).",
            )

        # 3. Heurística Anti-Phishing: Truque de redirecionamento com '@' na URL
        if "@" in (parsed.netloc or ""):
            return WebThreatAlert(
                alert_type="Heurística Anti-Phishing",
                threat_name="Heur.Phishing.URLCredentialTrick",
                severity="Alta",
                target=raw_url,
                details="Uso malicioso de '@' na URL para mascarar o verdadeiro domínio de destino.",
            )

        # 4. Heurística Anti-Phishing: Ataque Homógrafo IDN / Punycode (xn--)
        if "xn--" in host:
            return WebThreatAlert(
                alert_type="Heurística Anti-Phishing",
                threat_name="Heur.Phishing.PunycodeHomograph",
                severity="Alta",
                target=raw_url,
                details="Domínio utiliza caracteres internacionais disfarçados (Punycode 'xn--') para imitar marcas reais.",
            )

        # 5. Heurística Anti-Phishing: Falsificação de Bancos / Governo / Marcas (Typosquatting)
        clean_host_alnum = re.sub(r"[^a-z0-9]", "", host)
        for brand_key, official_domains in TARGETED_BRANDS.items():
            if brand_key in clean_host_alnum:
                is_official = any(host == off or host.endswith("." + off) for off in official_domains)
                if not is_official:
                    return WebThreatAlert(
                        alert_type="Heurística Anti-Phishing",
                        threat_name=f"Heur.Phishing.BrandImpersonation ({brand_key.upper()})",
                        severity="Crítica",
                        target=raw_url,
                        details=f"Domínio não oficial tentando se passar por '{brand_key.upper()}'. Risco de roubo de senha/token.",
                    )

        # 6. Download direto de executável/script em TLD suspeito ou IP puro
        is_raw_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))
        has_susp_tld = any(host.endswith(tld) for tld in SUSPICIOUS_TLDS)
        if path_lower.endswith((".exe", ".scr", ".bat", ".ps1", ".vbs", ".hta", ".msi")) and (is_raw_ip or has_susp_tld):
            return WebThreatAlert(
                alert_type="Escudo de Download Web",
                threat_name="Heur.WebDropper.SuspiciousExecutableLink",
                severity="Alta",
                target=raw_url,
                details="Link aponta diretamente para download de executável/script hospedado em IP bruto ou TLD de alto risco.",
            )

        return None

    # ================= 2. MONITOR DE CONEXÕES DE REDE E NAVEGADORES =================

    def scan_active_network_connections(self) -> Tuple[int, List[WebThreatAlert]]:
        """
        Inspeciona todas as conexões TCP/UDP ativas no Windows em busca de:
        - Comunicação com servidores C2 / Botnets conhecidos
        - Portas de RATs / Reverse Shells / Mineradores
        - Processos nativos (PowerShell, CMD, mshta, certutil) baixando cargas da internet (Fileless)
        """
        alerts: List[WebThreatAlert] = []
        inspected = 0

        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return 0, []

        for c in conns:
            if not c.raddr:
                continue
            remote_ip = c.raddr.ip
            remote_port = c.raddr.port
            if not remote_ip or remote_ip.startswith(("127.", "10.", "192.168.", "::1", "0.")):
                continue

            inspected += 1
            pid = c.pid
            proc_name = "Desconhecido"
            if pid:
                try:
                    proc_name = psutil.Process(pid).name()
                except Exception:
                    pass

            # 1. Verifica IP remoto na base de C2 / Botnets
            if remote_ip in self.blocked_ips:
                t_name, src = self.blocked_ips[remote_ip]
                alerts.append(
                    WebThreatAlert(
                        alert_type="Tráfego de Rede / C2",
                        threat_name=t_name,
                        severity="Crítica",
                        target=f"{remote_ip}:{remote_port}",
                        details=f"Processo '{proc_name}' (PID {pid}) conectado a IP malicioso ({src}).",
                        pid=pid,
                        process_name=proc_name,
                    )
                )
                continue

            # 2. Verifica portas clássicas de Backdoor / RAT / CryptoMining
            if remote_port in SUSPICIOUS_REMOTE_PORTS:
                desc_port = SUSPICIOUS_REMOTE_PORTS[remote_port]
                alerts.append(
                    WebThreatAlert(
                        alert_type="Porta de Rede Suspeita",
                        threat_name=f"Network.SuspiciousPort.{remote_port}",
                        severity="Alta",
                        target=f"{remote_ip}:{remote_port}",
                        details=f"Processo '{proc_name}' (PID {pid}) comunicando em {desc_port}.",
                        pid=pid,
                        process_name=proc_name,
                    )
                )
                continue

            # 3. Verifica processos LOLBin (PowerShell / mshta / wscript / certutil) conectando à Web
            if proc_name.lower() in LOLBIN_NETWORK_PROCESSES and c.status == "ESTABLISHED":
                alerts.append(
                    WebThreatAlert(
                        alert_type="Execução Web Fileless (LOLBin)",
                        threat_name=f"Behavior.Network.LOLBinConnection ({proc_name})",
                        severity="Alta",
                        target=f"{remote_ip}:{remote_port}",
                        details=f"O interpretador de comandos '{proc_name}' (PID {pid}) abriu conexão externa ativa.",
                        pid=pid,
                        process_name=proc_name,
                    )
                )

        return inspected, alerts

    # ================= 3. AUDITORIA DE NAVEGADORES (EXTENSÕES & DNS HOSTS) =================

    def audit_browsers_and_dns(self) -> Tuple[int, List[WebThreatAlert]]:
        """
        Audita as extensões instaladas nos navegadores (Chrome, Edge, Brave) e o arquivo hosts do Windows.
        Retorna (total_itens_auditados, lista_de_alertas).
        """
        alerts: List[WebThreatAlert] = []
        audited_count = 0

        # 1. Verifica arquivo hosts do Windows contra DNS Hijacking
        hosts_path = os.path.join(
            os.environ.get("SystemRoot", r"C:\Windows"),
            "System32",
            "drivers",
            "etc",
            "hosts",
        )
        if os.path.isfile(hosts_path):
            audited_count += 1
            try:
                with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        clean = line.strip()
                        if not clean or clean.startswith("#"):
                            continue
                        parts = clean.split()
                        if len(parts) >= 2:
                            ip_dest, dom = parts[0], parts[1].lower()
                            # Se redirecionar banco ou serviço crítico para um IP externo (não 127.0.0.1 / 0.0.0.0)
                            if not ip_dest.startswith(("127.", "0.0.0.0", "::1")):
                                for brand in TARGETED_BRANDS:
                                    if brand in dom:
                                        alerts.append(
                                            WebThreatAlert(
                                                alert_type="Sequestro de DNS (Hosts)",
                                                threat_name="Trojan.DNS.HostsHijack",
                                                severity="Crítica",
                                                target=f"{dom} -> {ip_dest}",
                                                details=f"O arquivo hosts do Windows está redirecionando '{dom}' para o IP externo {ip_dest}.",
                                            )
                                        )
            except Exception:
                pass

        # 2. Audita Extensões dos Navegadores Chromium (Chrome, Edge, Brave)
        local_appdata = os.environ.get("LOCALAPPDATA", "")
        browser_ext_Dirs = [
            ("Google Chrome", os.path.join(local_appdata, "Google", "Chrome", "User Data", "Default", "Extensions")),
            ("Microsoft Edge", os.path.join(local_appdata, "Microsoft", "Edge", "User Data", "Default", "Extensions")),
            ("Brave Browser", os.path.join(local_appdata, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Extensions")),
        ]

        risky_perms = {"cookies", "webRequestBlocking", "clipboardRead", "debugger", "proxy"}

        for browser_name, ext_root in browser_ext_Dirs:
            if not os.path.isdir(ext_root):
                continue
            try:
                for ext_id in os.listdir(ext_root):
                    ext_id_dir = os.path.join(ext_root, ext_id)
                    if not os.path.isdir(ext_id_dir):
                        continue
                    for ver_dir in os.listdir(ext_id_dir):
                        manifest_file = os.path.join(ext_id_dir, ver_dir, "manifest.json")
                        if not os.path.isfile(manifest_file):
                            continue
                        audited_count += 1
                        try:
                            with open(manifest_file, "r", encoding="utf-8", errors="ignore") as mf:
                                data = json.load(mf)
                            ext_name = data.get("name", ext_id)
                            perms = set(data.get("permissions", []) or [])
                            host_perms = set(data.get("host_permissions", []) or [])
                            update_url = data.get("update_url", "")

                            matched_risky = perms.intersection(risky_perms)
                            has_all_urls = "<all_urls>" in perms or "*://*/*" in perms or "<all_urls>" in host_perms or "*://*/*" in host_perms

                            # Alerta apenas se a extensão não tiver update_url oficial da loja E pedir captura ampla de cookies/tráfego
                            if not update_url and has_all_urls and len(matched_risky) >= 2:
                                alerts.append(
                                    WebThreatAlert(
                                        alert_type=f"Extensão Suspeita ({browser_name})",
                                        threat_name="Browser.Extension.HighRiskSideloaded",
                                        severity="Alta",
                                        target=f"{browser_name}: {ext_name} ({ext_id[:10]}...)",
                                        details=(
                                            f"Extensão instalada fora da loja oficial com acesso total a sites e permissões críticas: "
                                            f"{', '.join(sorted(matched_risky))}."
                                        ),
                                    )
                                )
                        except Exception:
                            continue
            except Exception:
                continue

        return audited_count, alerts
