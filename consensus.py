# =============================================================================
# consensus.py
# Simplified PBFT-inspired consensus protocol.
#
# Chosen Protocol: Practical Byzantine Fault Tolerance (PBFT) - Simplified
#
# Justification:
#   - The inventory system is permissioned (known nodes), making PBFT appropriate.
#   - PBFT handles up to f malicious/faulty nodes when total nodes n >= 3f+1.
#   - Latency: O(n^2) messages per consensus round - acceptable for small n.
#   - Security: Nodes vote on the record hash; a supermajority is required.
#   - Fault tolerance: System still reaches consensus if minority nodes are faulty.
#   - Better than PoW (no mining needed for permissioned system) and
#     Raft (Raft handles crashes but not Byzantine behavior).
#
# Simplified implementation:
#   Each node independently verifies the record signature and casts a vote.
#   If >= threshold fraction of nodes vote ACCEPT, consensus is REACHED.
# =============================================================================

import math
from typing import List, Tuple
from inventory_node import InventoryNode


CONSENSUS_THRESHOLD = 0.75   # fraction of nodes that must agree


class ConsensusEngine:
    """
    Manages consensus across all inventory nodes for record acceptance.
    The node list is passed in at construction — no node count is hardcoded.
    """

    def __init__(self, nodes: List[InventoryNode]):
        self.nodes = nodes

    def run_consensus(
        self,
        new_record: dict,
        signature: int,
        signer_e: int,
        signer_n: int,
        log_callback=None
    ) -> Tuple[bool, List[dict]]:
        """
        Run the consensus protocol for a proposed new record.

        Phase 1 - Pre-prepare: Leader (originating node) broadcasts signed record.
        Phase 2 - Prepare:     Each node verifies the signature independently.
        Phase 3 - Commit:      Each node casts a vote (ACCEPT / REJECT).
        Phase 4 - Decision:    Count votes; if >= threshold → consensus reached.

        Returns:
            (consensus_reached: bool, vote_details: list of dicts)
        """

        def log(msg):
            if log_callback:
                log_callback(msg)

        n_nodes  = len(self.nodes)
        required = math.ceil(CONSENSUS_THRESHOLD * n_nodes)
        # Compute the Byzantine fault tolerance: how many faulty nodes are tolerated
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

        for node in self.nodes:
            # Each node independently verifies the signature
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

        if consensus_reached:
            log("  [COMMIT PHASE] All nodes storing accepted record...")
            for node in self.nodes:
                node.add_record(new_record)
                log(f"    Node {node.node_id}: Record stored locally ✓")
        else:
            log("  [ABORT] Record rejected - insufficient agreement.")

        log("=" * 60)
        return consensus_reached, votes
