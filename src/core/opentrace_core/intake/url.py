"""Strict parsing of GitHub repository and tree URLs; this module never performs I/O."""

from dataclasses import dataclass
import re
import unicodedata
from urllib.parse import unquote_to_bytes, urlsplit


class IntakeError(ValueError):
    def __init__(self, code, field="url", message=None):
        self.code = code
        self.field = field
        self.message = message or code.replace("_", " ")
        super().__init__(self.message)


@dataclass(frozen=True)
class ParsedUrl:
    input_text: str
    owner: str
    name: str
    canonical_url: str
    tree_segments: tuple | None


_OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_REPO = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_SHA = re.compile(r"^[0-9a-fA-F]{7,40}$")
_HEX40 = re.compile(r"^[0-9a-fA-F]{40}$")
_BAD_REF = re.compile(r"[ ~^:?*\[\\]|\.\.|@\{")


def _decode_segment(segment):
    if re.search(r"%(?![0-9A-Fa-f]{2})", segment):
        raise IntakeError("malformed_reference", message="Reference contains invalid percent encoding")
    try:
        raw = unquote_to_bytes(segment)
        value = raw.decode("utf-8", "strict")
    except (UnicodeDecodeError, ValueError):
        raise IntakeError("malformed_reference", message="Reference contains invalid encoded text")
    if (not value or value in (".", "..") or "\\" in value
            or len(raw) > 255 or any(unicodedata.category(c) == "Cc" for c in value)):
        raise IntakeError("malformed_reference", message="Reference contains an invalid path segment")
    return value, len(raw)


def _valid_git_ref(parts):
    ref = "/".join(parts)
    if (_BAD_REF.search(ref) or ref.endswith(".")
            or any(not p or p.startswith(".") or p.endswith(".lock") for p in parts)):
        raise IntakeError("malformed_reference", message="Reference is not a valid Git ref name")


def parse_repository_url(text: str) -> ParsedUrl:
    if not isinstance(text, str) or not text.strip():
        raise IntakeError("empty", message="Enter a GitHub repository URL")
    value = text.strip()
    if len(value) > 2048:
        raise IntakeError("too_long", message="Repository URL is too long")
    try:
        parts = urlsplit(value)
    except ValueError:
        raise IntakeError("malformed_reference", message="Repository URL is malformed")
    if parts.scheme != "https":
        raise IntakeError("not_https", message="Use an https GitHub URL")
    if parts.username is not None or parts.password is not None:
        raise IntakeError("credentials_not_allowed", message="Remove credentials from the URL")
    if parts.hostname is None or parts.hostname.lower() != "github.com":
        raise IntakeError("host_not_github", message="Use github.com")
    try:
        port = parts.port
    except ValueError:
        raise IntakeError("port_not_allowed", message="Ports are not allowed")
    if port is not None or ":" in parts.netloc:
        raise IntakeError("port_not_allowed", message="Ports are not allowed")
    if parts.query or parts.fragment or "?" in value or "#" in value:
        raise IntakeError("query_or_fragment_not_allowed", message="Remove the query or fragment")
    path = parts.path
    if not path.startswith("/"):
        raise IntakeError("malformed_owner")
    segments = path[1:].split("/")
    if len(segments) == 3 and segments[-1] == "":
        segments.pop()
    if len(segments) < 2:
        raise IntakeError("malformed_repository", message="Use /owner/repository")
    owner, repo = segments[0], segments[1]
    if not _OWNER.fullmatch(owner):
        raise IntakeError("malformed_owner", message="Repository owner is malformed")
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not _REPO.fullmatch(repo) or repo in (".", ".."):
        raise IntakeError("malformed_repository", message="Repository name is malformed")
    rest = segments[2:]
    tree = None
    if not rest:
        pass
    elif rest[0] == "tree" and len(rest) >= 2:
        raw_refs = rest[1:]
        if len(raw_refs) > 8:
            raise IntakeError("too_many_segments", message="Reference has too many path segments")
        decoded = []
        total = 0
        for seg in raw_refs:
            item, size = _decode_segment(seg)
            decoded.append(item)
            total += size
        if total > 1024:
            raise IntakeError("malformed_reference", message="Reference is too long")
        _valid_git_ref(decoded)
        tree = tuple(decoded)
    else:
        raise IntakeError("unsupported_route", message="Use a repository root or tree URL")
    return ParsedUrl(value, owner, repo, "https://github.com/{}/{}".format(owner, repo), tree)


def parse_manual_sha(text: str) -> str | None:
    if text is None or not str(text).strip():
        return None
    value = str(text).strip()
    if not _SHA.fullmatch(value):
        raise IntakeError("manual_sha_malformed", field="manual_sha", message="Enter 7 to 40 hexadecimal characters")
    return value.lower()
