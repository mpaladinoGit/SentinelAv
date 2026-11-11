"""
SentinelAV - Verificador Nativo de Assinatura Digital do Windows (WinVerifyTrust / Authenticode)
Usa a API oficial wintrust.dll do Windows para validar se um executável (.exe, .dll, .sys, .msi)
possui assinatura digital autêntica e confiável, evitando falsos positivos na análise heurística.
"""

from __future__ import annotations
import os
import ctypes
from ctypes import wintypes
from functools import lru_cache


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(GUID)),
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


# WINTRUST_ACTION_GENERIC_VERIFY_V2: {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B,
    0xCD44,
    0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000


@lru_cache(maxsize=4096)
def _verify_file_cached(norm_path: str, mtime_ns: int) -> bool:
    """Chama WinVerifyTrust na wintrust.dll do Windows."""
    try:
        wintrust = ctypes.windll.wintrust

        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = norm_path
        file_info.hFile = None
        file_info.pgKnownSubject = None

        trust_data = WINTRUST_DATA()
        trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        trust_data.pPolicyCallbackData = None
        trust_data.pSIPClientData = None
        trust_data.dwUIChoice = WTD_UI_NONE
        trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
        trust_data.dwUnionChoice = WTD_CHOICE_FILE
        trust_data.pFile = ctypes.pointer(file_info)
        trust_data.dwStateAction = WTD_STATEACTION_VERIFY
        trust_data.hWVTStateData = None
        trust_data.pwszURLReference = None
        trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL
        trust_data.dwUIContext = 0
        trust_data.pSignatureSettings = None

        action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2
        status = wintrust.WinVerifyTrust(
            None,
            ctypes.byref(action_guid),
            ctypes.byref(trust_data),
        )

        # Libera o estado alocado pelo WinVerifyTrust
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE
        wintrust.WinVerifyTrust(
            None,
            ctypes.byref(action_guid),
            ctypes.byref(trust_data),
        )

        return status == 0
    except Exception:
        return False


def is_file_digitally_signed(filepath: str) -> bool:
    """
    Retorna True se o arquivo possui assinatura digital Authenticode válida no Windows.
    Usa cache baseado em caminho + mtime para máxima velocidade durante o escaneamento.
    """
    try:
        st = os.stat(filepath)
        return _verify_file_cached(os.path.normcase(os.path.abspath(filepath)), st.st_mtime_ns)
    except Exception:
        return False
