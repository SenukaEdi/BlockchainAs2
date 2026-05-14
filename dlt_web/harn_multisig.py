from typing import List, Dict
from crypto_utils import mod_exp, hash_message_mod, rsa_encrypt, rsa_decrypt


class HarnMultiSig:
    # Handles the Harn identity-based multi-signature calculations
    def __init__(self, pkg_e: int, pkg_d: int, pkg_n: int):
        # Stores the PKG key values used throughout the scheme
        self.pkg_e = pkg_e
        self.pkg_d = pkg_d
        self.pkg_n = pkg_n

    # Creates a partial private key for one inventory node
    def issue_partial_key(self, identity_id: int) -> int:
        s_i = mod_exp(identity_id, self.pkg_d, self.pkg_n)
        return s_i

    # Creates one node's partial signature for the query result
    def generate_partial_signature(
        self,
        message: str,
        partial_key: int,
        random_val: int,
    ) -> int:
        h_m = hash_message_mod(message, self.pkg_n)
        sig_i = (h_m * random_val + partial_key) % self.pkg_n
        return sig_i

    # Combines all partial signatures into one final signature value
    def aggregate_signatures(self, partial_sigs: List[int]) -> int:
        S = sum(partial_sigs) % self.pkg_n
        return S

    # Combines the random values used by each node
    def aggregate_randoms(self, random_vals: List[int]) -> int:
        R = sum(random_vals) % self.pkg_n
        return R

    # Checks whether the aggregated signature is valid for the message
    def verify_aggregate_signature(
        self,
        message: str,
        S: int,
        R: int,
        identity_ids: List[int],
        log_callback=None,
    ) -> bool:
        # Sends verification steps back to the webpage log if needed
        def log(msg):
            if log_callback:
                log_callback(msg)

        h_m = hash_message_mod(message, self.pkg_n)
        log(f"    H(message) mod n_pkg = {h_m}")

        # Recreates the partial keys from the node identities for checking
        sum_partial_keys = 0
        for id_i in identity_ids:
            s_i = mod_exp(id_i, self.pkg_d, self.pkg_n)
            sum_partial_keys = (sum_partial_keys + s_i) % self.pkg_n
            log(f"    s_{id_i} = {id_i}^d_pkg mod n_pkg = {s_i}")

        expected = (h_m * R + sum_partial_keys) % self.pkg_n
        log(f"    Expected S = (H(m)*R + sum(s_i)) mod n = {expected}")
        log(f"    Received S = {S}")

        return S == expected

    # Makes sure the stored aggregate matches the partial signatures
    def consensus_check(
        self,
        partial_sigs: List[int],
        agg_sig: int,
        log_callback=None,
    ) -> bool:
        # Sends the consistency check details to the webpage log if available
        def log(msg):
            if log_callback:
                log_callback(msg)

        recomputed = self.aggregate_signatures(partial_sigs)
        consistent = recomputed == agg_sig
        log(f"    Re-aggregated S = {recomputed}")
        log(f"    Stored S        = {agg_sig}")
        log(f"    Consistency:    {'✓ CONSISTENT' if consistent else '✗ INCONSISTENT'}")
        return consistent
