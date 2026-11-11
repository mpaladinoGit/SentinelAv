"""
SentinelAV - Pacote Core (Motor de Detecção, Heurística PE, Quarentena, Atualizador e Integração Windows)
"""

from __future__ import annotations
import os
import sys

APP_NAME = "SentinelAV"
APP_VERSION = "1.0.0"


def get_app_base_dir() -> str:
    """Retorna o diretório raiz do aplicativo (suporta execução via Python ou PyInstaller .exe)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_data_dir() -> str:
    """
    Retorna o diretório de dados persistentes (%LOCALAPPDATA%\\SentinelAV)
    para armazenar banco de vacinas/assinaturas, quarentena criptografada e logs.
    """
    local_appdata = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    data_dir = os.path.join(local_appdata, "SentinelAV")
    os.makedirs(data_dir, exist_ok=True)
    return data_dir
