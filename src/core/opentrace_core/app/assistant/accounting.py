"""Durable, prompt-free spend and dispatch reservation ledger for the assistant."""

from __future__ import annotations

import contextlib
import os
import sqlite3
import stat
import threading
import time
from dataclasses import dataclass


TOTAL_LIMIT_MICRO_USD = 5_000_000
# The allowance counts provider DISPATCHES; one question normally makes two (an input-token count, then the generation), so the default allows about 200 questions.
# An operator may raise or lower it (OPENTRACE_ASSISTANT_DISPATCH_ALLOWANCE) up to MAX_DISPATCH_ALLOWANCE. The dollar budget below stays an explicit, fixed ceiling.
DEFAULT_DISPATCH_ALLOWANCE = 400
MAX_DISPATCH_ALLOWANCE = 10_000
DISPATCH_RESERVE_LIMIT_MICRO_USD = 200_000
MAX_INPUT_TOKENS = 16_000
MAX_OUTPUT_TOKENS = 2_048


class BudgetError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Reservation:
    reservation_id: str
    reserve_micro_usd: int


@dataclass(frozen=True)
class BudgetSnapshot:
    spend_micro_usd: int
    reserved_micro_usd: int
    dispatches: int
    remaining_micro_usd: int
    remaining_dispatches: int


def worst_case_micro_usd(input_tokens: int, output_tokens: int,
                         input_micro_usd_per_million: int,
                         output_micro_usd_per_million: int) -> int:
    """Compute a ceiling-rounded upper bound, including reasoning in output_tokens."""
    values = (input_tokens, output_tokens, input_micro_usd_per_million, output_micro_usd_per_million)
    if any(not isinstance(v, int) or isinstance(v, bool) or v < 0 for v in values):
        raise ValueError("token bounds and rates must be nonnegative integers")
    return ((input_tokens * input_micro_usd_per_million + 999_999) // 1_000_000
            + (output_tokens * output_micro_usd_per_million + 999_999) // 1_000_000)


class SpendLedger:
    """SQLite ledger. Records only model label, reservation state, token-cost bounds and times."""

    def __init__(self, path: str, *, total_limit_micro_usd: int = TOTAL_LIMIT_MICRO_USD,
                 dispatch_limit: int = DEFAULT_DISPATCH_ALLOWANCE,
                 per_dispatch_limit_micro_usd: int = DISPATCH_RESERVE_LIMIT_MICRO_USD,
                 clock=time.time):
        if any(not isinstance(v, int) or isinstance(v, bool) or v <= 0
               for v in (total_limit_micro_usd, dispatch_limit, per_dispatch_limit_micro_usd)):
            raise ValueError("ledger limits must be positive")
        self.path = os.path.abspath(path)
        self.total_limit = min(total_limit_micro_usd, TOTAL_LIMIT_MICRO_USD)
        self.dispatch_limit = min(dispatch_limit, MAX_DISPATCH_ALLOWANCE)   # the allowance is not stored in the ledger: prior usage is the recorded reservations, so a larger value on restart keeps it
        self.per_dispatch_limit = min(per_dispatch_limit_micro_usd, DISPATCH_RESERVE_LIMIT_MICRO_USD)
        self.clock = clock
        self._lock = threading.RLock()
        directory = os.path.dirname(self.path)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        directory_stat = os.lstat(directory)
        owner = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        if (not stat.S_ISDIR(directory_stat.st_mode) or directory_stat.st_uid != owner
                or stat.S_IMODE(directory_stat.st_mode) & 0o077):
            raise ValueError("ledger directory must be owner-owned and private")
        # Create/open the database with private permissions without changing the
        # process-wide umask. O_NOFOLLOW rejects a symlink when supported.
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("ledger path must be a regular file")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        with self._connection() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS reservations (
                    reservation_id TEXT PRIMARY KEY,
                    model TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN
                      ('reserved','dispatched','uncertain','settled','settled_overrun','released')),
                    reserve_micro_usd INTEGER NOT NULL CHECK(reserve_micro_usd >= 0),
                    actual_micro_usd INTEGER,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )""")

    def reserve(self, reservation_id: str, model: str, *, input_tokens: int, output_tokens: int,
                input_micro_usd_per_million: int, output_micro_usd_per_million: int) -> Reservation:
        if (not isinstance(reservation_id, str) or not reservation_id or len(reservation_id) > 96
                or not isinstance(model, str) or not model or len(model) > 128):
            raise ValueError("invalid reservation identity")
        if (not isinstance(input_tokens, int) or isinstance(input_tokens, bool) or input_tokens > MAX_INPUT_TOKENS
                or not isinstance(output_tokens, int) or isinstance(output_tokens, bool)
                or output_tokens > MAX_OUTPUT_TOKENS):
            raise BudgetError("token_limit")
        amount = worst_case_micro_usd(input_tokens, output_tokens,
                                      input_micro_usd_per_million, output_micro_usd_per_million)
        if amount <= 0 or amount > self.per_dispatch_limit:
            raise BudgetError("dispatch_reserve_limit")
        now = float(self.clock())
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM reservations WHERE reservation_id=?", (reservation_id,)).fetchone():
                raise BudgetError("duplicate_reservation")
            spend, reserved, dispatches, inflight_reservations = self._totals(db)
            if dispatches + inflight_reservations >= self.dispatch_limit:
                raise BudgetError("dispatch_limit")
            if spend + reserved + amount > self.total_limit:
                raise BudgetError("total_budget_exhausted")
            db.execute("INSERT INTO reservations VALUES (?,?,?,?,?,?,?)",
                       (reservation_id, model, "reserved", amount, None, now, now))
        return Reservation(reservation_id, amount)

    def mark_dispatched(self, reservation_id: str) -> None:
        self._transition(reservation_id, {"reserved"}, "dispatched")

    def release_before_dispatch(self, reservation_id: str) -> None:
        self._transition(reservation_id, {"reserved"}, "released")

    def mark_uncertain(self, reservation_id: str) -> None:
        self._transition(reservation_id, {"dispatched"}, "uncertain")

    def settle(self, reservation_id: str, actual_micro_usd: int) -> bool:
        """Settle known usage. Returns True if provider cost exceeded the reserved bound."""
        if not isinstance(actual_micro_usd, int) or isinstance(actual_micro_usd, bool) or actual_micro_usd < 0:
            raise ValueError("actual cost must be a nonnegative integer")
        now = float(self.clock())
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state,reserve_micro_usd FROM reservations WHERE reservation_id=?",
                             (reservation_id,)).fetchone()
            if not row or row[0] != "dispatched":
                raise BudgetError("reservation_not_dispatched")
            overrun = actual_micro_usd > row[1]
            db.execute("UPDATE reservations SET state=?,actual_micro_usd=?,updated_at=? WHERE reservation_id=?",
                       ("settled_overrun" if overrun else "settled", actual_micro_usd, now, reservation_id))
            return overrun

    def snapshot(self) -> BudgetSnapshot:
        with self._lock, self._connection() as db:
            spend, reserved, dispatches, active = self._totals(db)
        return BudgetSnapshot(spend, reserved, dispatches,
                              max(0, self.total_limit - spend - reserved),
                              max(0, self.dispatch_limit - dispatches - active))

    def reservation(self, reservation_id: str) -> dict | None:
        with self._lock, self._connection() as db:
            row = db.execute("SELECT reservation_id,model,state,reserve_micro_usd,actual_micro_usd,created_at,updated_at "
                             "FROM reservations WHERE reservation_id=?", (reservation_id,)).fetchone()
        if row is None:
            return None
        return dict(zip(("reservation_id", "model", "state", "reserve_micro_usd", "actual_micro_usd",
                         "created_at", "updated_at"), row))

    def _transition(self, reservation_id: str, expected: set[str], new_state: str) -> None:
        now = float(self.clock())
        placeholders = ",".join("?" for _ in expected)
        with self._lock, self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute("UPDATE reservations SET state=?,updated_at=? WHERE reservation_id=? AND state IN (" +
                                placeholders + ")", (new_state, now, reservation_id, *sorted(expected)))
            if cursor.rowcount != 1:
                raise BudgetError("invalid_reservation_transition")

    @staticmethod
    def _totals(db: sqlite3.Connection) -> tuple[int, int, int, int]:
        spent = db.execute("SELECT COALESCE(SUM(actual_micro_usd),0) FROM reservations "
                            "WHERE state IN ('settled','settled_overrun')").fetchone()[0]
        reserved = db.execute("SELECT COALESCE(SUM(reserve_micro_usd),0) FROM reservations "
                              "WHERE state IN ('reserved','dispatched','uncertain')").fetchone()[0]
        dispatches = db.execute("SELECT COUNT(*) FROM reservations "
                                "WHERE state IN ('dispatched','uncertain','settled','settled_overrun')").fetchone()[0]
        active = db.execute("SELECT COUNT(*) FROM reservations WHERE state='reserved'").fetchone()[0]
        return int(spent), int(reserved), int(dispatches), int(active)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        db.execute("PRAGMA busy_timeout=10000")
        return db

    @contextlib.contextmanager
    def _connection(self):
        db = self._connect()
        try:
            with db:
                yield db
        finally:
            db.close()
