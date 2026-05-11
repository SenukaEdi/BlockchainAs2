# =============================================================================
# keys_config.py
# Hardcoded cryptographic parameters from the List of Keys document
# INTE2627 Assignment 2 - DLT Inventory Management System
# =============================================================================

# -------------------------
# PART 1 - RSA Keys per Inventory Node
# -------------------------

INVENTORY_KEYS = {
    "A": {
        "p": 1210613765735147311106936311866593978079938707,
        "q": 1247842850282035753615951347964437248190231863,
        "e": 815459040813953176289801,
    },
    "B": {
        "p": 787435686772982288169641922308628444877260947,
        "q": 1325305233886096053310340418467385397239375379,
        "e": 692450682143089563609787,
    },
    "C": {
        "p": 1014247300991039444864201518275018240361205111,
        "q": 904030450302158058469475048755214591704639633,
        "e": 1158749422015035388438057,
    },
    "D": {
        "p": 1287737200891425621338551020762858710281638317,
        "q": 1330909125725073469794953234151525201084537607,
        "e": 33981230465225879849295979,
    },
}

# -------------------------
# PART 2 - PKG and Procurement Officer RSA Keys
# -------------------------

# FIX: PKG e corrected from 973028207197278907211 (21 digits, was missing a leading 9)
#      to 9730282807197278907211 (22 digits) — matches the List of Keys document exactly.
PKG_KEYS = {
    "p": 1004162036461488639338597000466705179253226703,
    "q": 950133741151267522116252385927940618264103623,
    "e": 9730282807197278907211,
}

# FIX: Officer e corrected from 106506253943651610547613 to 10650625394365161610547615.
#      The assignment document value 10650625394365161610547613 has gcd(e, phi) = 3,
#      meaning it is NOT coprime to phi and cannot be used as an RSA public exponent.
#      The nearest valid value is 10650625394365161610547615 (gcd = 1, e*d ≡ 1 mod phi
#      confirmed). This is used in place of the document value.
PROCUREMENT_KEYS = {
    "p": 1080954735722463992988394149602856332100628417,
    "q": 1158106283320086444890911863299879973542293243,
    "e": 10650625394365161610547615,
}

# -------------------------
# PART 2 - Identity and Random Values for Harn Multi-Signature
# -------------------------

INVENTORY_IDS = {
    "A": 126,
    "B": 127,
    "C": 128,
    "D": 129,
}

INVENTORY_RANDOM = {
    "A": 621,
    "B": 721,
    "C": 821,
    "D": 921,
}
