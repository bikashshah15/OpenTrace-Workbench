"""Live GitHub REST transport for the I4A resolver: api.github.com only, no redirects, bounded."""
import json
import urllib.error
import urllib.request

from opentrace_core.intake.resolve import Response

API_HOST = "https://api.github.com"
MAX_RESPONSE = 1024 * 1024
TIMEOUT = 10


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def transport(path, *, opener=None):
    """GET ``path`` (``/repos/...``) unauthenticated. 3xx/4xx/5xx statuses are returned, not raised."""
    if not isinstance(path, str) or not path.startswith("/repos/") or ".." in path:
        raise OSError("path not allowed")
    request = urllib.request.Request(API_HOST + path, headers={
        "Accept": "application/vnd.github+json", "User-Agent": "OpenTrace-live-intake/1",
        "X-GitHub-Api-Version": "2022-11-28"})
    opener = opener or urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=TIMEOUT) as reply:
            status, data, location = reply.status, reply.read(MAX_RESPONSE + 1), reply.headers.get("Location")
    except urllib.error.HTTPError as exc:
        status, data, location = exc.code, exc.read(MAX_RESPONSE + 1), exc.headers.get("Location")
    if len(data) > MAX_RESPONSE:
        raise OSError("response too large")
    try:
        body = json.loads(data.decode("utf-8")) if data else None
    except ValueError:
        body = None
    return Response(status, body, location)
