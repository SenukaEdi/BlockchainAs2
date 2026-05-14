import math
from typing import List, Tuple
from inventory_node import InventoryNode


# Minimum percentage of nodes that must agree before the record is accepted
CONSENSUS_THRESHOLD = 0.75


class ConsensusEngine:
    # Handles the voting process between all inventory nodes
    def __init__(self, nodes: List[InventoryNode]):
        self.nodes = nodes

    # Runs the simplified PBFT process for one new record
    def run_consensus(
        self,
        new_record: dict,
        signature: int,
        signer_e: int,
        signer_n: int,
        log_callback=None
    ) -> Tuple[bool, List[dict]]:

        # Sends log messages back to the webpage if logging is available
        def log(msg):
            if log_callback:
                log_callback(msg)

        n_nodes  = len(self.nodes)
        required = math.ceil(CONSENSUS_THRESHOLD * n_nodes)
        f_tolerated = (n_nodes - 1) // 3

        log("=" * 60)
        log("  CONSENSUS PROTOCOL: PBFT (Simplified)")
        log("=" * 60)
        log(f"  Proposed record   : {new_record}")
        log(f"  Total nodes       : {n_nodes}")
        log(f"  Byzantine faults tolerated: {f_tolerated}")
        log(f"  Required threshold: {int(CONSENSUS_THRESHOLD * 100)}%  ({required}/{n_nodes} nodes must ACCEPT)")
        log("")

        votes = []
        accept_count = 0

        # Each node checks the signature and then votes ACCEPT or REJECT
        for node in self.nodes:
            is_valid = node.verify_record(new_record, signature, signer_e, signer_n)
            vote = "ACCEPT" if is_valid else "REJECT"

            if is_valid:
                accept_count += 1

            vote_detail = {
                "node_id": node.node_id,
                "vote": vote,
                "signature_valid": is_valid,
            }
            votes.append(vote_detail)
            log(f"  Node {node.node_id}: Signature verification → {'✓ VALID' if is_valid else '✗ INVALID'} → Vote: {vote}")

        log("")
        accept_ratio = accept_count / n_nodes
        consensus_reached = accept_ratio >= CONSENSUS_THRESHOLD

        log(f"  Vote tally: {accept_count}/{n_nodes} ACCEPT ({accept_ratio*100:.1f}%)")
        log(f"  Threshold:  {CONSENSUS_THRESHOLD*100:.1f}%  (need {required}/{n_nodes})")
        log(f"  Consensus:  {'✓ REACHED' if consensus_reached else '✗ NOT REACHED'}")
        log("")

        # If enough nodes accept the record, store it across all nodes
        if consensus_reached:
            log("  [COMMIT PHASE] All nodes storing accepted record...")
            for node in self.nodes:
                node.add_record(new_record)
                log(f"    Node {node.node_id}: Record stored locally ✓")
        else:
            log("  [ABORT] Record rejected - insufficient agreement.")

        log("=" * 60)
        return consensus_reached, votes
