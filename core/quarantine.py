"""
SentinelAV - Cofre de Quarentena Criptografado (Quarantine Vault)
Isola arquivos maliciosos movendo-os do local original e aplicando cifra XOR-256 nos bytes,
impedindo qualquer execução acidental e permitindo restauração segura ou exclusão definitiva.
"""

from __future__ import annotations
import os
import uuid
import json
from datetime import datetime
from typing import List, Optional
import psutil
from core import get_data_dir
from core.scanner import ThreatDetection


VAULT_KEY = b"SENTINEL_AV_QUARANTINE_KEY_2026_WIN64_SECURITY!"


def _xor_transform(data: bytes) -> bytes:
    """Aplica cifra simétrica XOR nos bytes do arquivo para neutralizar o executável no disco."""
    key_len = len(VAULT_KEY)
    ba = bytearray(data)
    for i in range(len(ba)):
        ba[i] ^= VAULT_KEY[i % key_len]
    return bytes(ba)


class QuarantineManager:
    def __init__(self):
        self.vault_dir = os.path.join(get_data_dir(), "quarantine")
        os.makedirs(self.vault_dir, exist_ok=True)
        self.manifest_path = os.path.join(self.vault_dir, "manifest.json")
        self.items: List[dict] = self._load_manifest()

    def _load_manifest(self) -> List[dict]:
        if not os.path.exists(self.manifest_path):
            return []
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception:
            return []

    def _save_manifest(self):
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(self.items, f, indent=2, ensure_ascii=False)

    def quarantine_threat(self, detection: ThreatDetection) -> Tuple[bool, str]:
        """
        Encerra o processo associado (se houver), criptografa o arquivo e o move para a Quarentena.
        """
        try:
            # 1. Se houver um processo ativo em memória associado à ameaça, encerra imediatamente
            if detection.pid:
                try:
                    proc = psutil.Process(detection.pid)
                    proc.kill()
                    proc.wait(timeout=3)
                except Exception:
                    pass

            src_path = os.path.abspath(detection.filepath)
            if not os.path.isfile(src_path):
                return False, f"Arquivo não encontrado no disco: {src_path}"

            with open(src_path, "rb") as f:
                raw_bytes = f.read()

            encrypted_bytes = _xor_transform(raw_bytes)
            item_id = uuid.uuid4().hex[:12]
            vault_filename = f"{item_id}.qvault"
            vault_filepath = os.path.join(self.vault_dir, vault_filename)

            with open(vault_filepath, "wb") as f:
                f.write(encrypted_bytes)

            # Remove o arquivo malicioso original
            os.remove(src_path)

            record = {
                "id": item_id,
                "vault_file": vault_filename,
                "original_path": src_path,
                "filename": os.path.basename(src_path),
                "sha256": detection.sha256,
                "threat_name": detection.threat_name,
                "category": detection.category,
                "severity": detection.severity,
                "engine": detection.engine,
                "size_bytes": len(raw_bytes),
                "quarantined_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            self.items.insert(0, record)
            self._save_manifest()
            return True, f"Ameaça isolada e criptografada na Quarentena ({record['filename']})."
        except Exception as e:
            return False, f"Falha ao mover para a Quarentena: {e}"

    def restore_item(self, item_id: str, custom_dest_dir: Optional[str] = None) -> Tuple[bool, str, Optional[str]]:
        """
        Descriptografa e restaura um arquivo da Quarentena para seu local de origem (ou pasta escolhida).
        Retorna (sucesso, mensagem, sha256_restaurado).
        """
        target = next((x for x in self.items if x["id"] == item_id), None)
        if not target:
            return False, "Item não encontrado na Quarentena.", None

        vault_filepath = os.path.join(self.vault_dir, target["vault_file"])
        if not os.path.exists(vault_filepath):
            self.items = [x for x in self.items if x["id"] != item_id]
            self._save_manifest()
            return False, "Arquivo de cofre ausente no disco.", None

        try:
            with open(vault_filepath, "rb") as f:
                enc_bytes = f.read()
            restored_bytes = _xor_transform(enc_bytes)

            if custom_dest_dir:
                dest_path = os.path.join(custom_dest_dir, target["filename"])
            else:
                dest_path = target["original_path"]

            os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)
            with open(dest_path, "wb") as f:
                f.write(restored_bytes)

            os.remove(vault_filepath)
            self.items = [x for x in self.items if x["id"] != item_id]
            self._save_manifest()
            return True, f"Arquivo restaurado em:\n{dest_path}", target.get("sha256")
        except Exception as e:
            return False, f"Erro ao restaurar arquivo: {e}", None

    def delete_permanently(self, item_id: str) -> Tuple[bool, str]:
        """Exclui definitivamente o arquivo criptografado da Quarentena."""
        target = next((x for x in self.items if x["id"] == item_id), None)
        if not target:
            return False, "Item não encontrado."

        vault_filepath = os.path.join(self.vault_dir, target["vault_file"])
        try:
            if os.path.exists(vault_filepath):
                os.remove(vault_filepath)
            self.items = [x for x in self.items if x["id"] != item_id]
            self._save_manifest()
            return True, f"Ameaça '{target['filename']}' excluída permanentemente."
        except Exception as e:
            return False, f"Erro ao excluir item: {e}"

    def list_items(self) -> List[dict]:
        self.items = self._load_manifest()
        return self.items
