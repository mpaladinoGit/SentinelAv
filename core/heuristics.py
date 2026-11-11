"""
SentinelAV - Motor de Análise Heurística Estática (PE Analyzer + Entropia de Shannon + Inspeção de IAT)
Inspeciona executáveis do Windows (.exe, .dll, .scr, .cpl, .sys) em busca de:
- Mascaramento de extensão dupla (ex: boleto.pdf.exe, comprovante.jpg.scr)
- Seções com permissão RWX (Leitura + Escrita + Execução simultâneas, típicas de shellcode/unpackers)
- Entropia de Shannon elevada (> 7.35) indicando payload criptografado (Ransomware / Crypter)
- Combinações perigosas de APIs na Tabela de Importação (IAT):
  * Process Injection / Hollowing (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)
  * Keylogging (SetWindowsHookEx + GetAsyncKeyState + GetForegroundWindow)
  * Downloader silencioso (URLDownloadToFile + WinExec/ShellExecute)
"""

from __future__ import annotations
import os
import math
from collections import Counter
from typing import List, Optional, Tuple
import pefile
from core.win_trust import is_file_digitally_signed


PE_EXTENSIONS = {".exe", ".dll", ".scr", ".cpl", ".sys", ".ocx"}
DOC_MASQUERADE_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".zip", ".mp4"}

PACKER_SECTION_NAMES = {
    "upx0",
    "upx1",
    ".vmp0",
    ".vmp1",
    ".themida",
    ".enigma1",
    ".aspack",
    ".mpress1",
    ".petite",
}

INJECTION_APIS = {
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
    "QueueUserAPC",
    "SetThreadContext",
}

KEYLOGGER_APIS = {
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "GetAsyncKeyState",
    "GetKeyState",
    "GetForegroundWindow",
}

DROPPER_APIS = {
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
}


def calculate_shannon_entropy(data: bytes) -> float:
    """Calcula a entropia de Shannon (0.0 a 8.0) de um bloco de bytes."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def check_double_extension(filepath: str) -> Optional[Tuple[str, str, str]]:
    """
    Detecta arquivos executáveis ou scripts tentando se passar por documentos/imagens
    (ex: 'Fatura_Outubro.pdf.exe', 'Foto_Festa.jpg.scr').
    """
    filename = os.path.basename(filepath).lower()
    parts = filename.rsplit(".", 2)
    if len(parts) == 3:
        _, fake_ext, real_ext = parts
        fake_ext = "." + fake_ext
        real_ext = "." + real_ext
        if real_ext in {".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".hta", ".js"} and fake_ext in DOC_MASQUERADE_EXTS:
            return (
                f"Heur.Masquerade.DoubleExt ({fake_ext}{real_ext})",
                "Trojan.Masquerade",
                "Alta",
            )
    return None


def analyze_pe_heuristics(filepath: str) -> Optional[Tuple[str, str, str, List[str]]]:
    """
    Analisa estaticamente um binário PE do Windows (.exe, .dll, .scr).
    Retorna (threat_name, category, severity, indicators) caso ultrapasse o limiar de risco,
    ou None se o arquivo parecer legítimo.
    """
    ext = os.path.splitext(filepath)[1].lower()

    # 1. Verifica extensão dupla maliciosa primeiro
    dbl = check_double_extension(filepath)
    if dbl:
        return dbl[0], dbl[1], dbl[2], ["Extensão dupla enganosa para induzir execução pelo usuário"]

    if ext not in PE_EXTENSIONS:
        return None

    # 2. Se o binário possui assinatura digital Authenticode válida no Windows, confiamos nele
    if is_file_digitally_signed(filepath):
        return None

    score = 0
    indicators: List[str] = []
    pe = None

    try:
        pe = pefile.PE(filepath, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )

        # Inspeção de Seções PE (Entropia, Packers, RWX)
        IMAGE_SCN_MEM_EXECUTE = 0x20000000
        IMAGE_SCN_MEM_WRITE = 0x80000000

        rwx_sections = 0
        high_entropy_exec_sections = 0

        for section in pe.sections:
            raw_name = section.Name.rstrip(b"\x00").decode("latin-1", errors="ignore").strip().lower()
            chars = section.Characteristics
            is_exec = bool(chars & IMAGE_SCN_MEM_EXECUTE)
            is_write = bool(chars & IMAGE_SCN_MEM_WRITE)

            if is_exec and is_write:
                rwx_sections += 1
                score += 25
                indicators.append(f"Seção '{raw_name}' com permissão RWX (Escrita + Execução)")

            if raw_name in PACKER_SECTION_NAMES:
                score += 25
                indicators.append(f"Offuscador/Packer detectado na seção '{raw_name}'")

            sec_data = section.get_data()[:65536]
            if len(sec_data) >= 2048:
                ent = calculate_shannon_entropy(sec_data)
                if ent > 7.45 and is_exec:
                    high_entropy_exec_sections += 1
                    score += 25
                    indicators.append(f"Alta entropia ({ent:.2f}/8.0) na seção executável '{raw_name}'")

        # Inspeção da Tabela de Importação (IAT)
        imported_apis: set[str] = set()
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        imported_apis.add(imp.name.decode("ascii", errors="ignore"))

        inj_matches = imported_apis.intersection(INJECTION_APIS)
        if len(inj_matches) >= 3:
            score += 55
            indicators.append(
                f"APIs de Injeção de Processo na IAT ({', '.join(sorted(list(inj_matches))[:4])})"
            )

        key_matches = imported_apis.intersection(KEYLOGGER_APIS)
        if len(key_matches) >= 3:
            score += 50
            indicators.append(
                f"APIs de Captura de Teclado/Keylogger ({', '.join(sorted(list(key_matches))[:3])})"
            )

        drop_matches = imported_apis.intersection(DROPPER_APIS)
        if ("URLDownloadToFileA" in drop_matches or "URLDownloadToFileW" in drop_matches) and len(drop_matches) >= 2:
            score += 50
            indicators.append(
                f"APIs de Download e Execução Automática ({', '.join(sorted(list(drop_matches)))})"
            )

        if score >= 75:
            if len(inj_matches) >= 3:
                t_name = "Heur.Win32.ProcessInjector.Suspicious"
                cat = "Trojan.Injector"
            elif len(key_matches) >= 3:
                t_name = "Heur.Win32.Keylogger.Generic"
                cat = "Spyware.Keylogger"
            elif high_entropy_exec_sections > 0 and rwx_sections > 0:
                t_name = "Heur.Win32.PackedPayload.Crypt"
                cat = "Suspicious.Packed"
            else:
                t_name = f"Heur.Win32.SuspiciousPE (Score {score})"
                cat = "Heuristic.PE"

            sev = "Crítica" if score >= 90 else "Alta"
            return t_name, cat, sev, indicators

        return None
    except Exception:
        return None
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass
