"""Configuration for live advisory lookup (I5B; ON BY DEFAULT with live scanning since LIVE-ADVISORIES-DEFAULT-01).

Live advisory lookup runs whenever live scanning is enabled, unless the operator opts out with
``OPENTRACE_LIVE_ADVISORIES=0``. Unset, empty and ``1`` mean on; ``0`` means off; any other value is
unrecognised and is treated as off (fail closed: nothing is sent to a third party on a typo). Live scanning
disabled means no advisory configuration at all (see ``live.runner.LiveConfig.from_env``). The lookup contacts
``api.osv.dev`` only and sends, for each exact registry version in the pinned commit's lockfiles, the
ecosystem, package name and version, and nothing else. The captured Demo never reaches this module's lookup.
"""
import os

from . import inventory, osv

ENABLE_VAR = "OPENTRACE_LIVE_ADVISORIES"


class AdvisoryConfig:
    """Everything live advisory lookup depends on, injected so tests never touch the network."""

    def __init__(self, *, specialist_bin=None, transport=None, sleep=None, scratch=None):
        self.specialist_bin = specialist_bin
        self.transport = transport or osv.OsvTransport()
        self.sleep = sleep
        self.scratch = scratch

    @classmethod
    def from_env(cls, environ=None):
        environ = os.environ if environ is None else environ
        if environ.get(ENABLE_VAR, "1").strip() not in ("1", ""):
            return None
        return cls(specialist_bin=inventory.specialist_binary(environ))

    def public(self):
        return {"enabled": True, "source": "OSV (api.osv.dev)", "host": osv.HOST,
                "inventory": "I3 parsers via Evidence Specialist B", "specialist_available": bool(self.specialist_bin),
                "sends": "the package ecosystem, name and exact version of each registry dependency in the pinned commit's lockfiles (no source files or credentials)"}
