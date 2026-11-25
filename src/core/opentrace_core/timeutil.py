"""UTC timestamp helpers. Avoids datetime.fromisoformat('...Z'), which needs 3.11+."""
import datetime as _dt
import re

_TS = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$")


def now():
    return _dt.datetime.now(_dt.timezone.utc)


def format_ts(value):
    """Format an aware datetime as UTC with millisecond precision and a literal Z."""
    value = value.astimezone(_dt.timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (value.microsecond // 1000)


def parse_ts(text):
    match = _TS.match(text) if isinstance(text, str) else None
    if not match:
        raise ValueError("invalid UTC timestamp: %r" % (text,))
    year, month, day, hour, minute, second, frac = match.groups()
    micros = int((frac or "0").ljust(9, "0")[:6])
    return _dt.datetime(int(year), int(month), int(day), int(hour), int(minute), int(second),
                        micros, tzinfo=_dt.timezone.utc)
