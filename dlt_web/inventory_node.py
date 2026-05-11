# =============================================================================
# inventory_node.py
# Represents a single inventory node with its own local records and RSA keys.
# Storage simulated using JSON files (no database required).
# Nodes start EMPTY — all records are added via the web interface.
# INTE2627 Assignment 2 - DLT Inventory Management System
# =============================================================================

import json
import os
from crypto_utils import derive_rsa_keys, rsa_sign, rsa_verify, hash_message_mod

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(DATA_DIR, exist_ok=True)


class InventoryNode:
    """
    Represents one inventory node in the distributed DLT system.
    Each node has:
      - its own RSA key pair (derived from parameters in keys_config.py)
      - a local list of inventory records persisted in data/inventory_<id>.json
      - ability to sign and verify records

    Nodes start with an empty ledger on first run.
    Records are only added after a successful sign → consensus pipeline
    initiated from the web interface.
    """

    def __init__(self, node_id: str, p: int, q: int, e: int):
        self.node_id = node_id
        self.keys = derive_rsa_keys(p, q, e)
        self.records = []
        self._load_records()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _records_path(self) -> str:
        return os.path.join(DATA_DIR, f"inventory_{self.node_id}.json")

    def _load_records(self):
        """Load from JSON file, or start empty if no file exists yet."""
        path = self._records_path()
        if os.path.exists(path):
            with open(path, "r") as f:
                self.records = json.load(f)
        else:
            # No seed — node starts with an empty ledger
            self.records = []

    def _save_records(self):
        with open(self._records_path(), "w") as f:
            json.dump(self.records, f, indent=2)

    # ------------------------------------------------------------------
    # Key accessors
    # ------------------------------------------------------------------

    def public_key(self) -> dict:
        return {"e": self.keys["e"], "n": self.keys["n"]}

    def private_key(self) -> dict:
        return {"d": self.keys["d"], "n": self.keys["n"]}

    # ------------------------------------------------------------------
    # Record operations
    # ------------------------------------------------------------------

    def record_to_string(self, record: dict) -> str:
        """
        Canonical, deterministic string for signing.
        Fixed field order ensures hash consistency across all nodes.
        """
        fields = ["item_id", "qty", "price", "location"]
        return ",".join(f"{k}={record[k]}" for k in fields)

    def sign_record(self, record: dict) -> int:
        """S = H(record_string)^d mod n"""
        msg = self.record_to_string(record)
        return rsa_sign(msg, self.keys["d"], self.keys["n"])

    def verify_record(self, record: dict, signature: int,
                      signer_e: int, signer_n: int) -> bool:
        """Check: S^e mod n == H(record_string) mod n"""
        msg = self.record_to_string(record)
        return rsa_verify(msg, signature, signer_e, signer_n)

    def get_hash_of_record(self, record: dict) -> int:
        msg = self.record_to_string(record)
        return hash_message_mod(msg, self.keys["n"])

    def add_record(self, record: dict):
        """Append an accepted record and persist to disk."""
        self.records.append(record)
        self._save_records()

    def get_record(self, item_id: str) -> dict | None:
        for r in self.records:
            if r["item_id"] == item_id:
                return r
        return None

    def all_item_ids(self) -> list:
        return [r["item_id"] for r in self.records]

    def clear_all_records(self):
        """Remove all records and delete the local JSON file."""
        self.records = []
        path = self._records_path()
        if os.path.exists(path):
            os.remove(path)

    def __repr__(self):
        return f"InventoryNode(id={self.node_id}, records={len(self.records)})"
