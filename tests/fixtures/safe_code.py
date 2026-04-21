"""Fixture: only uses primitives the scanner does not flag."""

import hashlib
import os

token = os.urandom(32)
digest = hashlib.sha256(token).hexdigest()
digest384 = hashlib.sha384(token).hexdigest()
