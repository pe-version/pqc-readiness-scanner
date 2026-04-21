"""Fixture: deliberately uses quantum-vulnerable + classically broken crypto."""

import hashlib

from cryptography.hazmat.primitives.asymmetric import ec, rsa

rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ec_key = ec.generate_private_key(ec.SECP256R1())

old_digest = hashlib.md5(b"x").hexdigest()
also_bad = hashlib.sha1(b"y").hexdigest()
