"""
SentinelAV - Empacotador Automático para Windows (.EXE Standalone via PyInstaller)
Gera:
- dist\\SentinelAV.exe (Aplicativo principal com ícone oficial shield.ico e sem janela de console)
- dist\\SentinelAV_Installer.exe (Assistente gráfico de instalação standalone)
"""

from __future__ import annotations
import os
import sys
import subprocess


def build_executables():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    ico_path = os.path.join(base_dir, "assets", "shield.ico")
    assets_dir = os.path.join(base_dir, "assets")

    print("==========================================================")
    print("  Empacotando SentinelAV Security Suite (.EXE Windows)    ")
    print("==========================================================")

    # 1. Empacota SentinelAV.exe
    cmd_main = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--windowed",
        "--name",
        "SentinelAV",
        "--icon",
        ico_path,
        "--add-data",
        f"{assets_dir};assets",
        os.path.join(base_dir, "main.py"),
    ]
    print("\n[1/2] Compilando SentinelAV.exe...")
    subprocess.run(cmd_main, cwd=base_dir, check=True)

    # 2. Empacota SentinelAV_Installer.exe
    cmd_inst = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--windowed",
        "--name",
        "SentinelAV_Installer",
        "--icon",
        ico_path,
        "--add-data",
        f"{assets_dir};assets",
        os.path.join(base_dir, "installer_gui.py"),
    ]
    print("\n[2/2] Compilando SentinelAV_Installer.exe...")
    subprocess.run(cmd_inst, cwd=base_dir, check=True)

    print("\n✅ Empacotamento concluído com sucesso!")
    print(f"Executáveis disponíveis em: {os.path.join(base_dir, 'dist')}")


if __name__ == "__main__":
    build_executables()
