"""OSV lookup for the exact registry versions of a live analysis (I5B; I3-REQ-06 protocol).

The protocol is the one I3 captured: ``POST /v1/querybatch`` (<= 100 queries, per-query pagination, one
isolation retry for a rejected query index), then ``GET /v1/vulns/{id}`` once per returned ID. Queries come
from ``cohort.plan.osv_plan`` over the I3 occurrence rows, so identity normalization and the
``ecosystem|name|version`` key are the I3 ones. Only ``api.osv.dev:443`` is ever contacted; HTTPS only, no
credentials, no cookies, no redirects, bounded bodies and bounded request counts.

Every query ends in exactly one of: ``answered`` (zero or more advisory IDs) or ``failed`` (with a reason).
A failure is never converted into "no advisories". Raw exchanges are kept only in memory for the session; the
digests of the request and response bytes are recorded as evidence.
"""
import hashlib
import http.client
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from opentrace_core.canon import canonical_bytes
from opentrace_core.cohort import families as families_mod, plan

HOST = "api.osv.dev"
LIMITS = {"batch": 100, "max_batch_requests": 100, "max_record_requests": 600, "max_per_second": 10, "timeout_s": 20,
          "retries": 2, "retry_waits_s": (1, 3), "page_cap": 10, "wall_s": 240, "max_body_bytes": 8 << 20}
ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
INDEX_RE = re.compile(r"error in query at index (\d+)")


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes


class OsvTransport:
    """The real transport: one HTTPS connection per call to ``api.osv.dev``; never follows a redirect."""

    def __init__(self, host=HOST):
        self.host = host

    def __call__(self, method, path, body=None):
        if not path.startswith("/v1/"):
            raise OSError("path outside the OSV API")
        conn = http.client.HTTPSConnection(self.host, 443, timeout=LIMITS["timeout_s"])
        try:
            headers = {"Accept": "application/json", "User-Agent": "OpenTrace-Workbench/I5B"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read(LIMITS["max_body_bytes"] + 1)
            if len(data) > LIMITS["max_body_bytes"]:
                raise OSError("response larger than the size limit")
            return Response(resp.status, data)
        finally:
            conn.close()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0)


@dataclass
class Lookup:
    """Everything a lookup observed. ``status``: ``not_run``, ``complete``, ``partial`` or ``unavailable``."""
    status: str = "not_run"
    reason: str = ""
    queried_at: str = ""
    plan_digest: str = ""
    queries: list = field(default_factory=list)       # planned queries (I3 shape)
    answers: dict = field(default_factory=dict)       # query_key -> {"state","ids","reason","exchange","slot","truncated"}
    exchanges: list = field(default_factory=list)     # {"id","kind","method","path","status","request_sha256","response_sha256","bytes"}
    slots: dict = field(default_factory=dict)         # exchange id -> raw response body (memory only)
    records: dict = field(default_factory=dict)       # vuln id -> {"record","digest","sha256"} (parsed, fetched)
    record_failures: dict = field(default_factory=dict)
    unresolved: list = field(default_factory=list)    # occurrences that could not be queried, with reason
    links: list = field(default_factory=list)         # occurrence -> query_key links (I3 plan)
    notes: list = field(default_factory=list)

    def counts(self):
        answered = [a for a in self.answers.values() if a["state"] == "answered"]
        return {"planned_queries": len(self.queries), "answered": len(answered),
                "answered_with_advisories": sum(1 for a in answered if a["ids"]),
                "incomplete_answers": sum(1 for a in answered if a["truncated"]),
                "failed": sum(1 for a in self.answers.values() if a["state"] == "failed"),
                "records_fetched": len(self.records), "records_failed": len(self.record_failures)}


class _Stop(Exception):
    pass


class Client:
    def __init__(self, transport, *, clock=time.monotonic, sleep=time.sleep, now=_now, cancel=None):
        self.transport, self.clock, self.sleep, self.now = transport, clock, sleep, now
        self.cancel = cancel
        self.start = clock()
        self.last = 0.0
        self.batches = self.records = 0
        self.stopped = None

    def _check(self):
        if self.cancel is not None and self.cancel.is_set():
            self.stopped = "cancelled"
        elif self.clock() - self.start > LIMITS["wall_s"]:
            self.stopped = "wall_cap_reached"
        elif self.batches >= LIMITS["max_batch_requests"]:
            self.stopped = "batch_request_cap_reached"
        elif self.records >= LIMITS["max_record_requests"]:
            self.stopped = "record_request_cap_reached"
        return bool(self.stopped)

    def call(self, lookup, kind, method, path, body, counter):
        """One recorded exchange, up to two retries on 5xx/network errors. Returns (Response|None, failure_reason|None)."""
        reason = None
        for attempt in range(1, LIMITS["retries"] + 2):
            if self._check():
                return None, self.stopped
            wait = 1.0 / LIMITS["max_per_second"] - (self.clock() - self.last)
            if wait > 0:
                self.sleep(wait)
            self.last = self.clock()
            setattr(self, counter, getattr(self, counter) + 1)
            try:
                res = self.transport(method, path, body)
            except (OSError, TimeoutError, http.client.HTTPException):
                reason = "network_error"
            else:
                ex = {"id": "x%d" % (len(lookup.exchanges) + 1), "kind": kind, "method": method, "path": path, "status": res.status,
                      "request_sha256": sha256(body) if body is not None else None, "response_sha256": sha256(res.body), "bytes": len(res.body),
                      "attempt": attempt}
                lookup.exchanges.append(ex)
                lookup.slots[ex["id"]] = res.body
                if res.status < 500:
                    return res, None
                reason = "http_%d" % res.status
            if attempt <= LIMITS["retries"]:
                self.sleep(LIMITS["retry_waits_s"][attempt - 1])
        return None, reason

    def exchange_id(self, lookup):
        return lookup.exchanges[-1]["id"]


def _query_object(q, token=None):
    obj = {"package": {"name": q["name"], "ecosystem": q["ecosystem"]}, "version": q["version_queried"]}
    if token:
        obj["page_token"] = token
    return obj


def _request_bytes(queries):
    return json.dumps({"queries": queries}, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse_result(result):
    """Validate one OSV query result (first page or continuation): ``(ids, next_page_token | None)``.

    Valid: an object whose ``vulns`` is absent or a list of objects each with a valid string ``id``, and whose
    ``next_page_token`` is absent, null or a non-empty string. An absent or empty ``vulns`` is a valid "no advisory
    returned". Anything else raises ``ValueError``: a malformed result is never read as an empty one.
    """
    if not isinstance(result, dict):
        raise ValueError("result is not an object")
    vulns = result.get("vulns", [])
    if not isinstance(vulns, list):
        raise ValueError("vulns is not a list")
    ids = []
    for v in vulns:
        if not isinstance(v, dict) or not isinstance(v.get("id"), str) or not ID_RE.match(v["id"]):
            raise ValueError("advisory entry without a valid id")
        ids.append(v["id"])
    token = result.get("next_page_token")
    if token is not None and (not isinstance(token, str) or not token):
        raise ValueError("next_page_token is not a non-empty string")
    return ids, token


def _fail(lookup, q, reason, exchange=None):
    lookup.answers[q["query_key"]] = {"state": "failed", "ids": [], "reason": reason, "exchange": exchange, "slot": None, "truncated": False}


def _batch(client, lookup, batch):
    live = list(batch)
    res, why = client.call(lookup, "querybatch", "POST", "/v1/querybatch", _request_bytes([_query_object(q) for q in live]), "batches")
    if res is not None and res.status == 400:
        m = INDEX_RE.search(res.body.decode("utf-8", "replace"))
        if m and int(m.group(1)) < len(live):
            idx = int(m.group(1))
            _fail(lookup, live[idx], "query_rejected", client.exchange_id(lookup))
            live = live[:idx] + live[idx + 1:]
            res, why = (client.call(lookup, "querybatch", "POST", "/v1/querybatch", _request_bytes([_query_object(q) for q in live]), "batches")
                        if live else (None, "empty"))
        else:
            why = "http_400"
            res = None
    if not live:
        return
    if res is None or res.status != 200:
        for q in live:
            _fail(lookup, q, why or "http_%s" % (res and res.status))
        return
    exchange = client.exchange_id(lookup)
    try:
        results = json.loads(res.body)["results"]
        if not isinstance(results, list) or len(results) != len(live):
            raise ValueError("result count differs from the query count")
    except (ValueError, KeyError, TypeError):
        for q in live:
            _fail(lookup, q, "unparseable_response", exchange)
        return
    for slot, q in enumerate(live):
        try:
            ids, token = _parse_result(results[slot])
        except ValueError:
            _fail(lookup, q, "malformed_result", exchange)
            continue
        pages, truncated, failed = 1, False, None
        while token:
            if pages >= LIMITS["page_cap"]:
                truncated = True
                break
            pres, pwhy = client.call(lookup, "querybatch", "POST", "/v1/querybatch", _request_bytes([_query_object(q, token)]), "batches")
            pages += 1
            try:
                if pres is None or pres.status != 200:
                    raise ValueError(pwhy or "http_%s" % pres.status)
                body = json.loads(pres.body)["results"]
                if not isinstance(body, list) or len(body) != 1:
                    raise ValueError("continuation result count")
                more, token = _parse_result(body[0])
                ids += more
            except (ValueError, KeyError, TypeError) as exc:
                failed = "page_failed:%s" % (str(exc)[:40] or "malformed")
                break
        if failed:
            _fail(lookup, q, failed, exchange)   # an incomplete page set is never reported as a complete answer
            continue
        if truncated and not ids:
            _fail(lookup, q, "page_limit_reached", exchange)   # a token remains and nothing was seen: not an answer
            continue
        lookup.answers[q["query_key"]] = {"state": "answered", "ids": sorted(set(ids)), "reason": None, "exchange": exchange,
                                          "slot": slot, "truncated": truncated}


def _records(client, lookup):
    wanted = sorted({i for a in lookup.answers.values() if a["state"] == "answered" for i in a["ids"]}, key=lambda s: s.encode())
    for vid in wanted:
        if not ID_RE.match(vid):
            lookup.record_failures[vid] = "invalid_id"
            continue
        res, why = client.call(lookup, "vuln", "GET", "/v1/vulns/" + vid, None, "records")
        if res is None or res.status != 200:
            lookup.record_failures[vid] = why or "http_%s" % res.status
            continue
        try:
            rec = json.loads(res.body)
            if not isinstance(rec, dict) or rec.get("id") != vid:
                raise ValueError("record id differs from the requested id")
        except ValueError:
            lookup.record_failures[vid] = "unparseable_record"
            continue
        digest = sha256(res.body)
        lookup.records[vid] = {"record": rec, "digest": "sha256:" + digest, "sha256": digest}


def run(occurrences, transport, *, cancel=None, clock=time.monotonic, sleep=time.sleep, now=_now):
    """Plan from I3 occurrence rows and query OSV. Always returns a ``Lookup``; never raises for network problems."""
    lookup = Lookup(queried_at=now().isoformat().replace("+00:00", "Z"))
    doc = plan.osv_plan(occurrences, "bare")
    lookup.queries, lookup.plan_digest, lookup.unresolved, lookup.links = doc["queries"], doc["planned_query_digest"], doc["unresolved"], doc["links"]
    if not doc["queries"]:
        lookup.status = "complete"
        lookup.notes.append("no occurrence had an exact registry version, so nothing was queried")
        return lookup
    client = Client(transport, clock=clock, sleep=sleep, now=now, cancel=cancel)
    for batch in doc["batches"]:
        if client._check():
            break
        _batch(client, lookup, batch)
    for q in lookup.queries:
        if q["query_key"] not in lookup.answers:
            _fail(lookup, q, client.stopped or "not_attempted")
    if client.stopped:
        lookup.notes.append("lookup stopped: " + client.stopped)
    _records(client, lookup)
    answered = sum(1 for a in lookup.answers.values() if a["state"] == "answered")
    if answered == 0:
        lookup.status, lookup.reason = "unavailable", next((a["reason"] for a in lookup.answers.values()), "no_response")
    elif answered < len(lookup.queries) or lookup.record_failures or client.stopped or any(a["truncated"] for a in lookup.answers.values()):
        lookup.status = "partial"
    else:
        lookup.status = "complete"
    return lookup


def build_families(lookup):
    """Alias families over the fetched records (I3 ``cohort.families``)."""
    return families_mod.build_families({vid: {"record": r["record"], "digest": r["digest"]} for vid, r in lookup.records.items()})


def log_document(lookup):
    """A compact, derived record of the lookup: plan, per-query outcomes and exchange digests (no raw bodies)."""
    return canonical_bytes({
        "schema": "opentrace.advisory_lookup/1", "status": lookup.status, "reason": lookup.reason or None,
        "source": {"service": "OSV (api.osv.dev)", "endpoint": ["/v1/querybatch", "/v1/vulns/{id}"], "queried_at": lookup.queried_at},
        "plan_digest": lookup.plan_digest, "counts": lookup.counts(),
        "queries": [{"query_key": q["query_key"], **{k: lookup.answers[q["query_key"]][k] for k in ("state", "ids", "reason", "exchange", "slot", "truncated")}}
                    for q in lookup.queries],
        "unresolved": [{"path": u["path"], "locator": u["locator"], "name": u["name_original"], "reason": u["reason"]} for u in lookup.unresolved],
        "exchanges": lookup.exchanges, "records": {vid: r["digest"] for vid, r in sorted(lookup.records.items())},
        "record_failures": dict(sorted(lookup.record_failures.items())), "notes": lookup.notes})
