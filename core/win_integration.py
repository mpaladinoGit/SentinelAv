"""
SentinelAV - Integração Nativa com o Windows 10/11
Permite:
1. Adicionar "🛡️ Verificar ameaças com SentinelAV" no menu de contexto (botão direito) de qualquer arquivo ou pasta no Windows Explorer
2. Criar atalhos (.lnk) na Área de Trabalho e no Menu Iniciar com o ícone oficial shield.ico
3. Configurar inicialização automática opcional junto com o Windows (HKCU\\...\\Run)
4. Registrar o aplicativo em "Aplicativos Instalados" do Windows (Uninstall key)
"""

from __future__ import annotations
import os
import sys
import ctypes
import subprocess
import winreg
from typing import Tuple
from core import get_app_base_dir, APP_NAME, APP_VERSION

WEEKLY_TASK_NAME = "SentinelAV_WeeklyAutoUpdate"


def get_app_executable_and_icon() -> Tuple[str, str]:
    """
    Retorna (comando_base_executavel, caminho_do_icone_ico).
    Suporta tanto execução empacotada (.exe PyInstaller) quanto via pythonw.exe.
    """
    base_dir = get_app_base_dir()
    ico_path = os.path.join(base_dir, "assets", "shield.ico")

    if getattr(sys, "frozen", False):
        exe_path = os.path.abspath(sys.executable)
        if not os.path.exists(ico_path):
            ico_path = exe_path
        return f'"{exe_path}"', ico_path

    installed_main = os.path.join(
        os.environ.get("LOCALAPPDATA", ""),
        "Programs",
        "SentinelAV",
        "main.py",
    )
    installed_ico = os.path.join(
        os.environ.get("LOCALAPPDATA", ""),
        "Programs",
        "SentinelAV",
        "assets",
        "shield.ico",
    )
    python_exe = sys.executable
    pythonw = os.path.join(os.path.dirname(python_exe), "pythonw.exe")
    runner = pythonw if os.path.exists(pythonw) else python_exe

    if os.path.exists(installed_main):
        return f'"{runner}" "{os.path.abspath(installed_main)}"', (
            installed_ico if os.path.exists(installed_ico) else ico_path
        )

    main_script = os.path.join(base_dir, "main.py")
    return f'"{runner}" "{main_script}"', ico_path


def _set_reg_value(root, subkey: str, name: str, value, reg_type=winreg.REG_SZ):
    key = winreg.CreateKeyEx(root, subkey, 0, winreg.KEY_WRITE)
    winreg.SetValueEx(key, name, 0, reg_type, value)
    winreg.CloseKey(key)


def notify_windows_shell_refresh():
    try:
        SHCNE_ASSOCCHANGED = 0x08000000
        SHCNF_IDLIST = 0x0000
        ctypes.windll.shell32.SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None)
    except Exception:
        pass


def register_explorer_context_menu() -> Tuple[bool, str]:
    """
    Adiciona a opção 'Verificar ameaças com SentinelAV' no botão direito
    de qualquer arquivo (*) e qualquer pasta (Directory) no Windows Explorer.
    """
    try:
        cmd_base, ico_path = get_app_executable_and_icon()
        hkcu = winreg.HKEY_CURRENT_USER

        # 1. Qualquer Arquivo (*)
        file_key = "Software\\Classes\\*\\shell\\SentinelAV_Scan"
        _set_reg_value(hkcu, file_key, "", "Verificar ameaças com SentinelAV")
        _set_reg_value(hkcu, file_key, "Icon", f'"{ico_path}"')
        _set_reg_value(hkcu, f"{file_key}\\command", "", f'{cmd_base} --scan "%1"')

        # 2. Qualquer Pasta (Directory)
        dir_key = "Software\\Classes\\Directory\\shell\\SentinelAV_Scan"
        _set_reg_value(hkcu, dir_key, "", "Verificar pasta com SentinelAV")
        _set_reg_value(hkcu, dir_key, "Icon", f'"{ico_path}"')
        _set_reg_value(hkcu, f"{dir_key}\\command", "", f'{cmd_base} --scan "%1"')

        notify_windows_shell_refresh()
        return True, "Menu de contexto do Windows Explorer registrado com sucesso!"
    except Exception as e:
        return False, f"Erro ao registrar menu de contexto: {e}"


def is_windows_startup_enabled() -> bool:
    """Verifica se o SentinelAV está configurado para iniciar junto com o Windows."""
    try:
        run_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_key, 0, winreg.KEY_READ)
        val, _ = winreg.QueryValueEx(key, "SentinelAV")
        winreg.CloseKey(key)
        return bool(val)
    except Exception:
        return False


def register_windows_startup(enable: bool = True) -> bool:
    """Ativa ou desativa a inicialização do SentinelAV junto com o login do Windows."""
    try:
        cmd_base, _ = get_app_executable_and_icon()
        run_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, run_key, 0, winreg.KEY_WRITE)
        if enable:
            winreg.SetValueEx(key, "SentinelAV", 0, winreg.REG_SZ, f"{cmd_base} --minimized")
        else:
            try:
                winreg.DeleteValue(key, "SentinelAV")
            except FileNotFoundError:
                pass
        winreg.CloseKey(key)
        return True
    except Exception:
        return False


def is_weekly_update_task_registered() -> bool:
    """Verifica se a Tarefa Agendada Semanal do SentinelAV está ativa no Agendador do Windows."""
    try:
        res = subprocess.run(
            ["schtasks", "/Query", "/TN", WEEKLY_TASK_NAME],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return res.returncode == 0
    except Exception:
        return False


def register_weekly_update_task(enable: bool = True) -> Tuple[bool, str]:
    """
    Cria ou remove a Tarefa Agendada Semanal no Windows Task Scheduler (schtasks)
    para atualizar silenciosamente as vacinas (SHA-256, YARA, Phishing e IPs C2) toda semana.
    """
    try:
        if not enable:
            subprocess.run(
                ["schtasks", "/Delete", "/F", "/TN", WEEKLY_TASK_NAME],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return True, "Tarefa semanal de auto-atualização desativada."

        cmd_base, _ = get_app_executable_and_icon()
        task_cmd = f"{cmd_base} --silent-update"

        res = subprocess.run(
            [
                "schtasks",
                "/Create",
                "/F",
                "/SC",
                "WEEKLY",
                "/D",
                "MON",
                "/TN",
                WEEKLY_TASK_NAME,
                "/TR",
                task_cmd,
                "/ST",
                "12:00",
            ],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if res.returncode == 0:
            return True, "Tarefa de auto-atualização semanal registrada no Agendador do Windows!"
        return False, f"Aviso ao agendar tarefa: {res.stderr.strip()}"
    except Exception as e:
        return False, f"Erro ao configurar tarefa semanal: {e}"


def register_uninstall_entry(install_dir: str, ico_path: str):
    """Registra o SentinelAV em 'Aplicativos e Recursos' do Windows."""
    try:
        uninst_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SentinelAV"
        hkcu = winreg.HKEY_CURRENT_USER
        _set_reg_value(hkcu, uninst_key, "DisplayName", f"{APP_NAME} Security Suite")
        _set_reg_value(hkcu, uninst_key, "DisplayVersion", APP_VERSION)
        _set_reg_value(hkcu, uninst_key, "Publisher", "SentinelAV Security")
        _set_reg_value(hkcu, uninst_key, "InstallLocation", install_dir)
        _set_reg_value(hkcu, uninst_key, "DisplayIcon", ico_path)
        _set_reg_value(hkcu, uninst_key, "NoModify", 1, winreg.REG_DWORD)
        _set_reg_value(hkcu, uninst_key, "NoRepair", 1, winreg.REG_DWORD)
    except Exception:
        pass


def create_windows_shortcuts(target_exe_or_script: str, icon_path: str, work_dir: str) -> Tuple[bool, str]:
    """Cria atalhos (.lnk) na Área de Trabalho e no Menu Iniciar do Windows."""
    try:
        import pythoncom
        import win32com.client

        pythoncom.CoInitialize()
        shell = win32com.client.Dispatch("WScript.Shell")

        desktop_dir = shell.SpecialFolders("Desktop")
        start_menu_dir = shell.SpecialFolders("Programs")

        for folder in (desktop_dir, start_menu_dir):
            if not folder or not os.path.exists(folder):
                continue
            lnk_path = os.path.join(folder, "SentinelAV Antivírus.lnk")
            shortcut = shell.CreateShortCut(lnk_path)
            if target_exe_or_script.lower().endswith(".py"):
                pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
                shortcut.Targetpath = pythonw if os.path.exists(pythonw) else sys.executable
                shortcut.Arguments = f'"{target_exe_or_script}"'
            else:
                shortcut.Targetpath = target_exe_or_script
            shortcut.WorkingDirectory = work_dir
            if os.path.exists(icon_path):
                shortcut.IconLocation = f"{icon_path},0"
            shortcut.Description = "SentinelAV - Proteção Antivírus, Heurística PE e Quarentena para Windows"
            shortcut.save()

        return True, "Atalhos criados na Área de Trabalho e no Menu Iniciar!"
    except Exception as e:
        return False, f"Erro ao criar atalhos: {e}"
