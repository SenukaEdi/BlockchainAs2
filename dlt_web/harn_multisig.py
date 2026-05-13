# =============================================================================
# harn_multisig.py
# Harn Identity-Based Multi-Signature Scheme (from scratch)
#
# Based on the Harn (1994) scheme as covered in INTE2627 lectures.
#
# Scheme Overview:
#   Setup (by PKG):
#     - PKG has RSA key pair (e_pkg, d_pkg, n_pkg)
#     - Each signer i has identity ID_i and random value r_i
#     - PKG computes partial private key for each signer:
#         s_i = ID_i^d_pkg mod n_pkg   (identity-based secret)
#
#   Partial Signature (by each inventory node i):
#     - Node i computes:
#         sig_i = (H(m) * r_i + s_i) mod n_pkg
#       where H(m) is the hash of the message mod n_pkg
#       and r_i is the node's random value
#
#   Aggregation:
#     - Combined signature: S = sum(sig_i) mod n_pkg
#     - Combined random:    R = sum(r_i) mod n_pkg
#
#   Verification:
#     - Verifier checks:
#         S == (H(m) * R + sum(ID_i^d_pkg mod n_pkg)) mod n_pkg
#       Equivalently:
#         S == (H(m) * R + sum(s_i)) mod n_pkg
#
# =============================================================================

from typing import List, Dict
from crypto_utils import mod_exp, hash_message_mod, rsa_encrypt, rsa_decrypt


class HarnMultiSig:
    """
    Harn Identity-Based Multi-Signature Scheme.
    All arithmetic is manual modular arithmetic - no black-box sign/verify.
    """

    def __init__(self, pkg_e: int, pkg_d: int, pkg_n: int):
        """
        Initialise with PKG (Private Key Generator) RSA parameters.
        pkg_e, pkg_d: PKG public/private exponents
        pkg_n: PKG modulus
        """
        self.pkg_e = pkg_e
        self.pkg_d = pkg_d
        self.pkg_n = pkg_n

    # ------------------------------------------------------------------
    # Setup: PKG issues partial private keys to each signer
    # ------------------------------------------------------------------

    def issue_partial_key(self, identity_id: int) -> int:
        """
        PKG computes partial private key for a signer with given identity:
            s_i = ID_i ^ d_pkg mod n_pkg

        This is the identity-based secret key issued by the PKG.
        """
        s_i = mod_exp(identity_id, self.pkg_d, self.pkg_n)
        return s_i

    # ------------------------------------------------------------------
    # Partial Signature Generation (by each inventory node)
    # ------------------------------------------------------------------

    def generate_partial_signature(
        self,
        message: str,
        partial_key: int,
        random_val: int,
    ) -> int:
        """
        Inventory node i generates its partial signature on message m:
            sig_i = (H(m) * r_i + s_i) mod n_pkg

        Parameters:
            message:     the message/query result being signed
            partial_key: s_i = ID_i^d_pkg mod n_pkg  (from PKG)
            random_val:  r_i  (hardcoded per node from List of Keys)

        Returns:
            sig_i (partial signature integer)
        """
        h_m = hash_message_mod(message, self.pkg_n)
        sig_i = (h_m * random_val + partial_key) % self.pkg_n
        return sig_i

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------

    def aggregate_signatures(self, partial_sigs: List[int]) -> int:
        """
        Aggregate all partial signatures:
            S = sum(sig_i) mod n_pkg
        """
        S = sum(partial_sigs) % self.pkg_n
        return S

    def aggregate_randoms(self, random_vals: List[int]) -> int:
        """
        Aggregate all random values:
            R = sum(r_i) mod n_pkg
        """
        R = sum(random_vals) % self.pkg_n
        return R

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_aggregate_signature(
        self,
        message: str,
        S: int,
        R: int,
        identity_ids: List[int],
        log_callback=None,
    ) -> bool:
        """
        Verify the aggregated multi-signature.

        Verification equation:
            S == (H(m) * R + sum(ID_i^d_pkg mod n_pkg)) mod n_pkg

        This works because:
            S = sum(sig_i) = sum(H(m)*r_i + s_i)
              = H(m)*sum(r_i) + sum(s_i)
              = H(m)*R + sum(ID_i^d_pkg mod n_pkg)
        """
        def log(msg):
            if log_callback:
                log_callback(msg)

        h_m = hash_message_mod(message, self.pkg_n)
        log(f"    H(message) mod n_pkg = {h_m}")

        # Recompute sum of partial keys from identities (public verification)
        sum_partial_keys = 0
        for id_i in identity_ids:
            # Verifier uses PKG public key to recompute: ID_i^d_pkg mod n_pkg
            # In identity-based scheme the verifier recomputes s_i = ID_i^d mod n
            s_i = mod_exp(id_i, self.pkg_d, self.pkg_n)
            sum_partial_keys = (sum_partial_keys + s_i) % self.pkg_n
            log(f"    s_{id_i} = {id_i}^d_pkg mod n_pkg = {s_i}")

        expected = (h_m * R + sum_partial_keys) % self.pkg_n
        log(f"    Expected S = (H(m)*R + sum(s_i)) mod n = {expected}")
        log(f"    Received S = {S}")

        return S == expected

    # ------------------------------------------------------------------
    # Consensus check on aggregated signatures
    # ------------------------------------------------------------------

    def consensus_check(
        self,
        partial_sigs: List[int],
        agg_sig: int,
        log_callback=None,
    ) -> bool:
        """
        Verify that the aggregated signature is consistent with all partial
        signatures - i.e. re-aggregating gives the same result.
        This ensures no node tampered with its partial signature after the fact.
        """
        def log(msg):
            if log_callback:
                log_callback(msg)

        recomputed = self.aggregate_signatures(partial_sigs)
        consistent = recomputed == agg_sig
        log(f"    Re-aggregated S = {recomputed}")
        log(f"    Stored S        = {agg_sig}")
        log(f"    Consistency:    {'✓ CONSISTENT' if consistent else '✗ INCONSISTENT'}")
        return consistent
