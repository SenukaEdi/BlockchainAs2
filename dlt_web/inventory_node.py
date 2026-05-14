import json
import os
from crypto_utils import derive_rsa_keys, rsa_sign, rsa_verify, hash_message_mod


DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(DATA_DIR, exist_ok=True)


class InventoryNode:
    # Represents one inventory node with its own keys and local records
    def __init__(self, node_id: str, p: int, q: int, e: int):
        self.node_id = node_id
        self.keys = derive_rsa_keys(p, q, e)
        self.records = []
        self._load_records()

    # Builds the file path for this node's local JSON record file
    def _records_path(self) -> str:
        return os.path.join(DATA_DIR, f"inventory_{self.node_id}.json")

    # Loads records from the JSON file if it already exists
    def _load_records(self):
        path = self._records_path()
        if os.path.exists(path):
            with open(path, "r") as f:
                self.records = json.load(f)
        else:
            self.records = []

    # Saves the node's records back into its JSON file
    def _save_records(self):
        with open(self._records_path(), "w") as f:
            json.dump(self.records, f, indent=2)

    # Returns the public key values used by other nodes for verification
    def public_key(self) -> dict:
        return {"e": self.keys["e"], "n": self.keys["n"]}

    # Returns the private key values used by this node for signing
    def private_key(self) -> dict:
        return {"d": self.keys["d"], "n": self.keys["n"]}

    # Converts a record into a consistent string before hashing or signing
    def record_to_string(self, record: dict) -> str:
        fields = ["item_id", "qty", "price", "location"]
        return ",".join(f"{k}={record[k]}" for k in fields)

    # Signs the record using this node's private RSA key
    def sign_record(self, record: dict) -> int:
        msg = self.record_to_string(record)
        return rsa_sign(msg, self.keys["d"], self.keys["n"])

    # Verifies a signed record using the signing node's public key
    def verify_record(self, record: dict, signature: int,
                      signer_e: int, signer_n: int) -> bool:
        msg = self.record_to_string(record)
        return rsa_verify(msg, signature, signer_e, signer_n)

    # Gets the hash value of a record using this node's modulus
    def get_hash_of_record(self, record: dict) -> int:
        msg = self.record_to_string(record)
        return hash_message_mod(msg, self.keys["n"])

    # Adds an accepted record and saves it to this node's JSON file
    def add_record(self, record: dict):
        self.records.append(record)
        self._save_records()

    # Finds one record by item ID
    def get_record(self, item_id: str) -> dict | None:
        for r in self.records:
            if r["item_id"] == item_id:
                return r
        return None

    # Returns only the item IDs currently stored by this node
    def all_item_ids(self) -> list:
        return [r["item_id"] for r in self.records]

    # Clears all records for this node and removes the JSON file
    def clear_all_records(self):
        self.records = []
        path = self._records_path()
        if os.path.exists(path):
            os.remove(path)

    # Simple readable display for debugging in the terminal
    def __repr__(self):
        return f"InventoryNode(id={self.node_id}, records={len(self.records)})"
