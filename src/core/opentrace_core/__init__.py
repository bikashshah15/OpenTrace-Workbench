"""OpenTrace deterministic core (I1): evidence store, validators, context, runs, trace.

Standard library only; runs on Python 3.10+. No network, provider or credential access.
"""

CONTRACT_NAME = "opentrace.evidence"
CONTRACT_VERSION = "1.0"
SUPPORTED_MAJOR = 1
NEGOTIATED_V2 = "2.0"   # I2: pass as negotiated= to enable major 2 (contract token present)
CONTRACT_VERSION_V2 = "2.0"
NEGOTIATED_V3 = "3.0"   # I3: pass as negotiated= to enable major 3 (contract token 3.0 present)
CONTRACT_VERSION_V3 = "3.0"
