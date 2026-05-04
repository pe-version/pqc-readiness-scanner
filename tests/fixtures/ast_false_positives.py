"""Fixture: patterns the regex scanner flags as crypto usage but that an AST
scanner should NOT flag because the crypto names appear in non-call contexts.

Each block exercises a different false-positive class. None of these patterns
performs any actual cryptography.
"""

# 1. Crypto names mentioned in a docstring or string literal.
SUPPORTED_HASHES = "MD5, SHA-1, SHA-256"  # documentation string only
DOCSTRING_NOTE = """
This module talks ABOUT hashlib.md5 and rsa.generate_private_key, but does
not call them. The regex scanner has historically over-reported these.
"""


# 2. TODO / migration comments.
# TODO: replace hashlib.md5 with hashlib.sha256 once downstream consumers update.
# Old code used rsa.generate_private_key; we now use ML-KEM directly.


# 3. Unrelated identifiers that share a substring with crypto APIs.
class FakeRSA:
    """Has 'RSA' in its name but is unrelated to crypto."""
    def generate(self) -> int:
        return 42


fake = FakeRSA()
fake.generate()  # 'fake.generate()' — should NOT match RSA.generate


# 4. Crypto names as dictionary keys, attribute strings, or argument values
# that look like the API but aren't the call shape.
algo_names = ["md5", "sha1", "rsa"]  # data, not calls
config = {"algorithm": "RSA"}  # value-only mention
algo_to_check = "md5"  # variable assignment


# 5. Functions or classes named after crypto algorithms but unrelated.
def md5_legacy_hash_label() -> str:
    """Returns a label string mentioning md5 — not a hash function."""
    return "Tagged: legacy"


# 6. Imports of name-overlapping but non-crypto modules.
class rsa:  # noqa: N801 — deliberate shadowing for the false-positive test
    """Local class named 'rsa' — has nothing to do with the cryptography module."""
    @staticmethod
    def generate_private_key(*args, **kwargs) -> str:
        return "this is not RSA"


_local_rsa_value = rsa.generate_private_key()  # NOT the cryptography.rsa call
