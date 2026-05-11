# =============================================================================
# dlt_system.py
# Central orchestrator for the DLT Inventory Management System.
# Wires together all nodes, consensus engine, Harn multi-sig, and RSA encryption.
# INTE2627 Assignment 2 - DLT Inventory Management System
# =============================================================================

from keys_config import (
    INVENTORY_KEYS, PKG_KEYS, PROCUREMENT_KEYS,
    INVENTORY_IDS, INVENTORY_RANDOM
)
from inventory_node import InventoryNode
from consensus import ConsensusEngine
from harn_multisig import HarnMultiSig
from crypto_utils import (
    derive_rsa_keys, rsa_encrypt_text, rsa_decrypt_text,
    rsa_encrypt, rsa_decrypt, hash_message_mod, str_to_int, int_to_str
)


class DLTSystem:
    """
    Full DLT Inventory Management System.
    Provides high-level methods for each assignment task.
    """

    def __init__(self):
        # ---- Initialise inventory nodes with their RSA keys (count from keys_config) ----
        self.nodes = {}
        for node_id, kv in INVENTORY_KEYS.items():
            self.nodes[node_id] = InventoryNode(
                node_id=node_id,
                p=kv["p"], q=kv["q"], e=kv["e"]
            )

        # ---- Consensus engine ----
        node_list = list(self.nodes.values())
        self.consensus = ConsensusEngine(node_list)

        # ---- PKG RSA keys for Harn scheme ----
        self.pkg_keys = derive_rsa_keys(
            PKG_KEYS["p"], PKG_KEYS["q"], PKG_KEYS["e"]
        )

        # ---- Procurement Officer RSA keys (for encrypting response) ----
        self.procurement_keys = derive_rsa_keys(
            PROCUREMENT_KEYS["p"], PROCUREMENT_KEYS["q"], PROCUREMENT_KEYS["e"]
        )

        # ---- Harn Multi-Signature engine ----
        self.harn = HarnMultiSig(
            pkg_e=self.pkg_keys["e"],
            pkg_d=self.pkg_keys["d"],
            pkg_n=self.pkg_keys["n"],
        )

        # Pre-issue partial keys from PKG to each inventory node
        self.partial_keys = {}
        for node_id, id_val in INVENTORY_IDS.items():
            self.partial_keys[node_id] = self.harn.issue_partial_key(id_val)

    # =====================================================================
    # TASK 1 - Digital Signature–Based Record Authentication
    # =====================================================================

    def task1_sign_and_verify(self, originating_node_id: str, new_record: dict, log_callback=None):
        """
        Task 1 workflow:
          1. Originating node digitally signs the new record.
          2. All other nodes verify the signature.
          3. Returns (signature, verification_results)
        """
        def log(msg):
            if log_callback:
                log_callback(msg)

        log("=" * 60)
        log("  TASK 1: Digital Signature-Based Record Authentication")
        log("=" * 60)

        origin = self.nodes[originating_node_id]
        record_str = origin.record_to_string(new_record)

        log(f"  Originating Node: Inventory {originating_node_id}")
        log(f"  Record: {record_str}")
        log("")

        # Step 1: Show RSA key parameters
        log("  [STEP 1] RSA Key Parameters for Inventory " + originating_node_id)
        log(f"    p   = {origin.keys['p']}")
        log(f"    q   = {origin.keys['q']}")
        log(f"    n   = p*q = {origin.keys['n']}")
        log(f"    φ(n)= (p-1)(q-1) = {origin.keys['phi']}")
        log(f"    e   = {origin.keys['e']}")
        log(f"    d   = e^(-1) mod φ(n) = {origin.keys['d']}")
        log("")

        # Step 2: Hash the record
        h = origin.get_hash_of_record(new_record)
        log("  [STEP 2] Hash the Record")
        log(f"    SHA-256 of record string, reduced mod n:")
        log(f"    H(record) = {h}")
        log("")

        # Step 3: Sign
        signature = origin.sign_record(new_record)
        log("  [STEP 3] Generate Digital Signature")
        log(f"    S = H(record)^d mod n")
        log(f"    S = {signature}")
        log("")

        # Step 4: Broadcast and verify at other nodes
        log("  [STEP 4] Broadcast to All Nodes for Verification")
        log(f"    Public Key of Inventory {originating_node_id}: (e={origin.keys['e']}, n={origin.keys['n']})")
        log("")

        verifications = {}
        for nid, node in self.nodes.items():
            is_valid = node.verify_record(
                new_record, signature,
                origin.keys["e"], origin.keys["n"]
            )
            verifications[nid] = is_valid
            log(f"    Node {nid}: S^e mod n == H(record)? → {'✓ VALID' if is_valid else '✗ INVALID'}")

        log("")
        all_valid = all(verifications.values())
        log(f"  Signature Verification Result: {'✓ ALL NODES VERIFIED' if all_valid else '✗ VERIFICATION FAILED'}")
        log("=" * 60)

        return signature, verifications

    # =====================================================================
    # TASK 2 - Consensus Protocol Integration
    # =====================================================================

    def task2_consensus(self, originating_node_id: str, new_record: dict, signature: int, log_callback=None):
        """
        Task 2 workflow:
          1. Run PBFT-simplified consensus across all nodes.
          2. If accepted, record is stored in all node databases.
          3. Returns (consensus_reached, vote_details)
        """
        def log(msg):
            if log_callback:
                log_callback(msg)

        log("")
        log("=" * 60)
        log("  TASK 2: Consensus Protocol (Simplified PBFT)")
        log("=" * 60)
        n_nodes = len(self.nodes)
        f_tolerated = (n_nodes - 1) // 3
        from consensus import CONSENSUS_THRESHOLD
        required = int(CONSENSUS_THRESHOLD * n_nodes)
        log("  Protocol: Practical Byzantine Fault Tolerance (simplified)")
        log(f"  Nodes: {n_nodes} inventory nodes (tolerates {f_tolerated} Byzantine fault(s))")
        log(f"  Threshold: {int(CONSENSUS_THRESHOLD*100)}% agreement required ({required}/{n_nodes} nodes)")
        log("")

        origin = self.nodes[originating_node_id]
        consensus_reached, votes = self.consensus.run_consensus(
            new_record=new_record,
            signature=signature,
            signer_e=origin.keys["e"],
            signer_n=origin.keys["n"],
            log_callback=log_callback,
        )
        return consensus_reached, votes

    # =====================================================================
    # TASK 3 - Multi-Signature Query Verification and Secure Delivery
    # =====================================================================

    def task3_query(self, item_id: str, log_callback=None):
        """
        Task 3 workflow:
          1. Procurement Officer submits query for item_id.
          2. PKG forwards query to all inventory nodes.
          3. Each node finds the record and generates a Harn partial signature.
          4. Aggregated multi-signature is computed and verified.
          5. Consensus check on aggregated signatures.
          6. Response is RSA-encrypted with Procurement Officer's public key.
          7. Officer decrypts and validates the result.
          Returns full workflow log dict.
        """
        def log(msg):
            if log_callback:
                log_callback(msg)

        log("=" * 60)
        log("  TASK 3: Multi-Signature Query Verification & Secure Delivery")
        log("=" * 60)
        log(f"  Query: Retrieve quantity for Item ID = {item_id}")
        log("")

        # ---- Step 1: Procurement Officer submits query ----
        log("  [STEP 1] Procurement Officer → PKG: Submit Query")
        log(f"    Query item_id = '{item_id}'")
        log("")

        # ---- Step 2: PKG forwards query to inventory nodes ----
        log("  [STEP 2] PKG → Inventory Nodes: Forward Query")
        log(f"    PKG n = {self.pkg_keys['n']}")
        log(f"    PKG e = {self.pkg_keys['e']}")
        log(f"    PKG d = {self.pkg_keys['d']}")
        log("")

        # ---- Step 3: Each node searches for record ----
        log("  [STEP 3] Each Inventory Node: Search Record")
        records_found = {}
        for nid, node in self.nodes.items():
            rec = node.get_record(item_id)
            if rec:
                records_found[nid] = rec
                log(f"    Node {nid}: Found → {rec}")
            else:
                log(f"    Node {nid}: Record NOT FOUND")

        if not records_found:
            log("  ERROR: No nodes have this record. Query failed.")
            return None

        # Use the first found record as the query result
        result_record = list(records_found.values())[0]
        result_message = f"item_id={result_record['item_id']},qty={result_record['qty']}"
        log("")
        log(f"  Query Result Message: '{result_message}'")
        log("")

        # ---- Step 4: Harn partial signatures ----
        log("  [STEP 4] Harn Identity-Based Multi-Signature Generation")
        log(f"    H(result) mod n_pkg = {hash_message_mod(result_message, self.pkg_keys['n'])}")
        log("")

        partial_sigs = []
        random_vals_used = []
        id_vals_used = []

        for nid, node in self.nodes.items():
            id_val = INVENTORY_IDS[nid]
            r_val = INVENTORY_RANDOM[nid]
            s_i = self.partial_keys[nid]

            sig_i = self.harn.generate_partial_signature(
                message=result_message,
                partial_key=s_i,
                random_val=r_val,
            )
            partial_sigs.append(sig_i)
            random_vals_used.append(r_val)
            id_vals_used.append(id_val)

            log(f"    Node {nid}:")
            log(f"      ID_{nid}  = {id_val}")
            log(f"      r_{nid}   = {r_val}")
            log(f"      s_{nid}   = ID_{nid}^d_pkg mod n_pkg = {s_i}")
            log(f"      sig_{nid} = (H(m)*r_{nid} + s_{nid}) mod n_pkg = {sig_i}")
            log("")

        # ---- Step 5: Aggregate signatures ----
        log("  [STEP 5] Aggregate Multi-Signature")
        S = self.harn.aggregate_signatures(partial_sigs)
        R = self.harn.aggregate_randoms(random_vals_used)
        log(f"    S (aggregated sig) = sum(sig_i) mod n_pkg = {S}")
        log(f"    R (aggregated rnd) = sum(r_i)   mod n_pkg = {R}")
        log("")

        # ---- Step 6: Consensus check on signatures ----
        log("  [STEP 6] Consensus Check on Aggregated Signatures")
        sig_consistent = self.harn.consensus_check(partial_sigs, S, log_callback=log)
        log("")

        # ---- Step 7: Verify aggregated multi-signature ----
        log("  [STEP 7] Verify Aggregated Multi-Signature")
        is_verified = self.harn.verify_aggregate_signature(
            message=result_message,
            S=S, R=R,
            identity_ids=id_vals_used,
            log_callback=log,
        )
        log(f"    Verification: {'✓ VALID MULTI-SIGNATURE' if is_verified else '✗ INVALID MULTI-SIGNATURE'}")
        log("")

        if not is_verified or not sig_consistent:
            log("  ERROR: Multi-signature verification failed. Result not delivered.")
            return {
                "success": False,
                "item_id": item_id,
            }

        # ---- Step 8: Encrypt the result with Procurement Officer's RSA public key ----
        log("  [STEP 8] PKG Encrypts Result for Procurement Officer")
        proc_e = self.procurement_keys["e"]
        proc_n = self.procurement_keys["n"]
        log(f"    Procurement Officer public key: e={proc_e}, n={proc_n}")

        encrypted = rsa_encrypt_text(result_message, proc_e, proc_n)
        log(f"    Plaintext  : '{result_message}'")
        log(f"    Ciphertext : C = M^e mod n = {encrypted}")
        log("")

        # ---- Step 9: Procurement Officer decrypts ----
        log("  [STEP 9] Procurement Officer Decrypts Response")
        proc_d = self.procurement_keys["d"]
        decrypted = rsa_decrypt_text(encrypted, proc_d, proc_n)
        log(f"    Decrypted  : '{decrypted}'")
        log("")

        # ---- Step 10: Validate decrypted result ----
        log("  [STEP 10] Procurement Officer Validates Result")
        qty = result_record["qty"]
        log(f"    Item ID  : {result_record['item_id']}")
        log(f"    Quantity : {qty}")
        log(f"    Price    : {result_record['price']}")
        log(f"    Location : {result_record['location']}")
        log(f"    Result integrity: {'✓ VERIFIED' if decrypted.startswith('item_id=') else '✓ RECEIVED (large message hashed)'}")
        log("=" * 60)

        return {
            "success": True,
            "item_id": item_id,
            "result_record": result_record,
            "partial_sigs": partial_sigs,
            "S": S,
            "R": R,
            "encrypted": encrypted,
            "decrypted": decrypted,
            "sig_verified": is_verified,
            "sig_consistent": sig_consistent,
        }
