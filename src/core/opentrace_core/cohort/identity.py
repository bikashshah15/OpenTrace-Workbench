"""Identity normalization and OSV query keys (I3-REQ-05).

Ecosystem names are the OSV spellings. Normalized names are used for joining only; the original spelling
and the verbatim version string are always kept by the caller. A version is never rewritten to a different
version: the only transformation is the recorded Go "v" prefix form, settled by the acquisition probe.
"""
import re

ECOSYSTEMS = ("Go", "npm", "PyPI")
MAX_NAME_BYTES = 512
MAX_VERSION_BYTES = 128
_PEP503 = re.compile(r"[-_.]+")
_GO = re.compile(r"^[A-Za-z0-9._~/+:-]+$")
_NPM = re.compile(r"^(@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+$")
_PYPI = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
GO_FORMS = ("bare", "v_prefixed")


class IdentityError(ValueError):
    pass


def pep503(name):
    return _PEP503.sub("-", name).lower()


def valid_text(text, limit):
    if not isinstance(text, str) or len(text.encode("utf-8", "surrogatepass")) > limit:
        return False
    return not any(ord(c) < 0x20 or ord(c) == 0x7F for c in text)


def valid_identity(ecosystem, name):
    """The same patterns B applies before a name can be a query component."""
    if not valid_text(name, MAX_NAME_BYTES) or not name:
        return False
    if ecosystem == "Go":
        return bool(_GO.match(name)) and all(el and not el.startswith(".") and not el.endswith(".") for el in name.split("/"))
    if ecosystem == "npm":
        return len(name) <= 214 and bool(_NPM.match(name))
    if ecosystem == "PyPI":
        return bool(_PYPI.match(name))
    return False


def normalize_name(ecosystem, name):
    """Joining identity: Go module path and npm name exactly; PyPI by PEP 503. Raises IdentityError when hostile."""
    if ecosystem not in ECOSYSTEMS:
        raise IdentityError("unsupported ecosystem")
    if not valid_identity(ecosystem, name):
        raise IdentityError("name is not valid for the ecosystem")
    return pep503(name) if ecosystem == "PyPI" else name


def valid_version(version):
    return isinstance(version, str) and bool(version) and valid_text(version, MAX_VERSION_BYTES)


def version_queried(ecosystem, version_original, go_form):
    """The exact version string sent to OSV. Only the Go leading "v" follows the recorded probe form."""
    if not valid_version(version_original):
        raise IdentityError("version cannot be sent as recorded")
    if ecosystem == "Go":
        if go_form not in GO_FORMS:
            raise IdentityError("unknown Go version form")
        if go_form == "bare" and version_original.startswith("v"):
            return version_original[1:]
        if go_form == "v_prefixed" and not version_original.startswith("v"):
            return "v" + version_original
    return version_original


def query_key(ecosystem, name_normalized, version_sent):
    return "%s|%s|%s" % (ecosystem, name_normalized, version_sent)


def query_key_from_request(query):
    """Key derived from a CAPTURED request query (I2-RUN-01 lesson), mirroring B: never reconstructed by assumption."""
    pkg = query.get("package") or {}
    name = pkg.get("name") or ("purl:%s" % pkg.get("purl", ""))
    eco = pkg.get("ecosystem", "")
    if eco == "PyPI":
        name = pep503(name)
    return query_key(eco, name, query.get("version", ""))
