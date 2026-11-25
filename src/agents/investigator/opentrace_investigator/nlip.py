"""ECMA-430 message codec used by Investigator A.

Parsing treats field names and Format values case-insensitively; output always
uses the canonical capitalization. A structured/json Content is carried as a JSON
value; a JSON string Content is also accepted and parsed on input.
"""
import json

FORMATS = ("text", "token", "structured", "binary", "location", "generic")
CORRELATION_SUBFORMAT = "conversation_opentrace-a"
# I2-REQ-02: a major 2 payload travels only with this token submessage (content "2.0").
CONTRACT_SUBFORMAT = "contract_opentrace-evidence"


class NlipError(Exception):
    pass


def _fold(obj):
    return {str(k).lower(): v for k, v in obj.items()} if isinstance(obj, dict) else None


def _part(obj, where, allow_label):
    folded = _fold(obj)
    if folded is None:
        raise NlipError("%s is not an object" % where)
    for field in ("format", "subformat", "content"):
        if field not in folded:
            raise NlipError("%s missing %s" % (where, field.capitalize()))
    fmt = folded["format"]
    if not isinstance(fmt, str) or fmt.lower() not in FORMATS:
        raise NlipError("%s has invalid Format" % where)
    if not isinstance(folded["subformat"], str):
        raise NlipError("%s has invalid Subformat" % where)
    part = {"Format": fmt.lower(), "Subformat": folded["subformat"], "Content": folded["content"]}
    if allow_label and folded.get("label") is not None:
        part["Label"] = folded["label"]
    return part, folded


def parse(obj):
    """Return a canonical message dict or raise NlipError."""
    msg, folded = _part(obj, "message", allow_label=False)
    mtype = folded.get("messagetype")
    if mtype is not None:
        if not isinstance(mtype, str):
            raise NlipError("MessageType must be a string")
        msg["MessageType"] = mtype.lower() if mtype.lower() == "control" else mtype
    subs = folded.get("submessages")
    if subs is not None:
        if not isinstance(subs, list):
            raise NlipError("Submessages must be an array")
        msg["Submessages"] = [_part(s, "submessage[%d]" % i, allow_label=True)[0] for i, s in enumerate(subs)]
    return msg


def is_control(msg):
    return msg.get("MessageType") == "control"


def structured_payload(msg):
    """The domain payload carried as structured/json, or None."""
    for part in [msg] + msg.get("Submessages", []):
        if part["Format"] == "structured" and part["Subformat"].lower() == "json":
            content = part["Content"]
            if isinstance(content, str):
                try:
                    content = json.loads(content)
                except ValueError:
                    raise NlipError("structured/json Content is not JSON")
            return content
    return None


def tokens(msg):
    return [s["Content"] for s in msg.get("Submessages", [])
            if s["Format"] == "token" and s["Subformat"] == CORRELATION_SUBFORMAT]


def correlation_token(msg):
    found = tokens(msg)
    return found[0] if len(found) == 1 else None


def text_summary(msg):
    for part in [msg] + msg.get("Submessages", []):
        if part["Format"] == "text" and part["Subformat"].lower() == "english":
            return part["Content"]
    return None


def contract_tokens(msg):
    return [s["Content"] for s in msg.get("Submessages", [])
            if s["Format"] == "token" and s["Subformat"] == CONTRACT_SUBFORMAT]


def build(payload, token=None, summary=None, control=False, contract_token=None):
    msg = {}
    if control:
        msg["MessageType"] = "control"
    msg.update({"Format": "structured", "Subformat": "json", "Content": payload})
    subs = []
    if token is not None:
        subs.append({"Format": "token", "Subformat": CORRELATION_SUBFORMAT, "Content": token})
    if contract_token is not None:
        subs.append({"Format": "token", "Subformat": CONTRACT_SUBFORMAT, "Content": contract_token})
    if summary is not None:
        subs.append({"Format": "text", "Subformat": "english", "Content": summary})
    if subs:
        msg["Submessages"] = subs
    return msg


def text_message(text):
    return {"Format": "text", "Subformat": "english", "Content": text}
