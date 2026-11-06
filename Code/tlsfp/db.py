"""Reference fingerprint database (SQLite) with an optional Redis/Valkey KV mirror.

fingerprints : curated reference entries  (kind, value) -> label/category
observations : every handshake seen, for historical reporting
"""
from __future__ import annotations

import csv
import json
import sqlite3
import time
from dataclasses import dataclass, field

KINDS = ("ja3", "ja3s", "ja4", "ja4s")

SCHEMA = """
CREATE TABLE IF NOT EXISTS fingerprints (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    label TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'unknown',
    source TEXT NOT NULL DEFAULT 'learned',
    raw TEXT,
    notes TEXT,
    first_seen REAL,
    last_seen REAL,
    hits INTEGER NOT NULL DEFAULT 0,
    UNIQUE(kind, value, label)
);
CREATE INDEX IF NOT EXISTS idx_fp_lookup ON fingerprints(kind, value);
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY,
    ts REAL, src TEXT, sport INTEGER, dst TEXT, dport INTEGER, sni TEXT,
    ja3 TEXT, ja4 TEXT, ja3s TEXT, ja4s TEXT,
    process TEXT, verdict TEXT, matched_on TEXT, category TEXT, status TEXT
);
CREATE INDEX IF NOT EXISTS idx_obs_ts ON observations(ts);
"""


AGREE, JA3_ONLY, JA4_ONLY = "agree", "ja3_only", "ja4_only"
CONFLICT, AMBIGUOUS, UNKNOWN = "conflict", "ambiguous", "unknown"
STATUSES = (AGREE, JA4_ONLY, JA3_ONLY, AMBIGUOUS, CONFLICT, UNKNOWN)
_REDIS_INDEX_KEY = "tlsfp:__sync_index__"


@dataclass
class Match:
    """Evidence-based verdict. `labels` are the candidate applications; the verdict is
    a single identification only when `identified` is true (agree / ja4_only / ja3_only)."""
    labels: list[str]
    categories: list[str]
    matched_on: str                      # "ja4", "ja3", "ja4+ja3", or "" when unknown
    status: str = UNKNOWN
    ja4_labels: list[str] = field(default_factory=list)   # what the JA4 lookup alone said
    ja3_labels: list[str] = field(default_factory=list)   # what the JA3 lookup alone said

    @property
    def identified(self) -> bool:
        return self.status in (AGREE, JA4_ONLY, JA3_ONLY)

    @property
    def label(self) -> str:
        if self.status == CONFLICT:
            return (f"CONFLICT ({self.matched_on.split('+')[0]}: {' | '.join(self.ja4_labels)}"
                    f" vs {self.matched_on.split('+')[-1]}: {' | '.join(self.ja3_labels)})")
        return " | ".join(self.labels) if self.labels else "UNKNOWN"

    @property
    def category(self) -> str:
        if "malware" in self.categories:
            return "malware"
        return self.categories[0] if self.categories else "unknown"

    @property
    def ambiguous(self) -> bool:
        return self.status == AMBIGUOUS


class FingerprintDB:
    def __init__(self, path: str = "tlsfp.db", redis_url: str | None = None):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.redis = None
        if redis_url:
            import redis  # optional dependency
            self.redis = redis.Redis.from_url(redis_url, decode_responses=True)

    def _migrate(self) -> None:
        """Add columns introduced after a database file was first created."""
        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(observations)")}
        if "status" not in cols:
            self.conn.execute("ALTER TABLE observations ADD COLUMN status TEXT")
            self.conn.commit()

    # ------------------------------------------------------------ reference data
    def add(self, kind: str, value: str, label: str, category: str = "unknown",
            source: str = "learned", raw: str | None = None, notes: str | None = None) -> bool:
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        now = time.time()
        cur = self.conn.execute(
            """INSERT INTO fingerprints(kind, value, label, category, source, raw, notes,
                                        first_seen, last_seen, hits)
               VALUES (?,?,?,?,?,?,?,?,?,1)
               ON CONFLICT(kind, value, label) DO UPDATE SET
                   last_seen=excluded.last_seen, hits=hits+1,
                   raw=COALESCE(fingerprints.raw, excluded.raw),
                   source=CASE WHEN instr(fingerprints.source, excluded.source) > 0
                               THEN fingerprints.source
                               ELSE fingerprints.source || '; ' || excluded.source END,
                   notes=COALESCE(fingerprints.notes, excluded.notes)""",
            (kind, value, label, category, source, raw, notes, now, now))
        self.conn.commit()
        return cur.rowcount > 0

    def remove(self, kind: str, value: str, label: str | None = None) -> int:
        q, args = "DELETE FROM fingerprints WHERE kind=? AND value=?", [kind, value]
        if label:
            q += " AND label=?"
            args.append(label)
        n = self.conn.execute(q, args).rowcount
        self.conn.commit()
        return n

    def entries(self, kind: str | None = None) -> list[sqlite3.Row]:
        if kind:
            return self.conn.execute(
                "SELECT * FROM fingerprints WHERE kind=? ORDER BY label", (kind,)).fetchall()
        return self.conn.execute("SELECT * FROM fingerprints ORDER BY label, kind").fetchall()

    def _lookup(self, kind: str, value: str) -> list[tuple[str, str]]:
        if not value:
            return []
        if self.redis is not None:
            members = self.redis.smembers(f"tlsfp:{kind}:{value}")
            return [tuple(m.split("\x1f", 1)) for m in members]  # type: ignore[misc]
        rows = self.conn.execute(
            "SELECT label, category FROM fingerprints WHERE kind=? AND value=?",
            (kind, value)).fetchall()
        return [(r["label"], r["category"]) for r in rows]

    def identify(self, ja4: str | None, ja3: str | None, client: bool = True) -> Match:
        """Look up JA4 and JA3 independently, then combine the evidence:

        both match, labels overlap   -> AGREE on the overlap (JA3 can narrow a shared JA4)
        both match, labels disjoint  -> CONFLICT (neither method is silently preferred)
        only one matches             -> JA4_ONLY / JA3_ONLY
        more than one candidate left -> AMBIGUOUS (fingerprint shared by several apps)
        nothing matches              -> UNKNOWN
        For servers the same logic runs on JA4S / JA3S."""
        k4, k3 = ("ja4", "ja3") if client else ("ja4s", "ja3s")
        m4 = dict(self._lookup(k4, ja4 or ""))
        m3 = dict(self._lookup(k3, ja3 or ""))
        cats = {**m3, **m4}
        l4, l3 = sorted(m4), sorted(m3)
        if m4 and m3:
            both = sorted(set(m4) & set(m3))
            if not both:
                union = sorted(set(m4) | set(m3))
                return Match(union, [cats[x] for x in union], f"{k4}+{k3}", CONFLICT, l4, l3)
            status = AGREE if len(both) == 1 else AMBIGUOUS
            return Match(both, [cats[x] for x in both], f"{k4}+{k3}", status, l4, l3)
        if m4 or m3:
            labels, on, single = (l4, k4, JA4_ONLY) if m4 else (l3, k3, JA3_ONLY)
            status = single if len(labels) == 1 else AMBIGUOUS
            return Match(labels, [cats[x] for x in labels], on, status, l4, l3)
        return Match([], [], "", UNKNOWN, [], [])

    # ------------------------------------------------------------ observations
    def record(self, session, verdict: Match) -> None:
        c = session.client
        s = session.server
        src, sport, dst, dport = c.flow
        self.conn.execute(
            """INSERT INTO observations(ts, src, sport, dst, dport, sni, ja3, ja4, ja3s, ja4s,
                                        process, verdict, matched_on, category, status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (c.ts, src, sport, dst, dport, c.sni, c.fp.ja3, c.fp.ja4,
             s.fp.ja3s if s else None, s.fp.ja4s if s else None,
             session.process, verdict.label, verdict.matched_on, verdict.category,
             verdict.status))
        self.conn.commit()

    # ------------------------------------------------------------ import/export
    def export_json(self, path: str) -> int:
        rows = [{k: r[k] for k in ("kind", "value", "label", "category", "source", "raw", "notes")}
                for r in self.entries()]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2)
        return len(rows)

    def import_json(self, path: str) -> int:
        with open(path, encoding="utf-8") as f:
            rows = json.load(f)
        if isinstance(rows, dict):          # data/published_references.json layout
            rows = rows["fingerprints"]
        for r in rows:
            self.add(r["kind"], r["value"], r["label"], r.get("category", "unknown"),
                     r.get("source", "imported"), r.get("raw"), r.get("notes"))
        return len(rows)

    def import_sslbl(self, path: str) -> int:
        """abuse.ch SSLBL JA3 blacklist: https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv
        Format: ja3_md5,Firstseen,Lastseen,Listingreason"""
        n = 0
        with open(path, encoding="utf-8") as f:
            for line in f:
                if not line.strip() or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 4 or len(parts[0]) != 32:
                    continue
                self.add("ja3", parts[0], parts[3], "malware", "abuse.ch SSLBL",
                         notes=f"first {parts[1]} last {parts[2]}")
                n += 1
        return n

    def import_csv(self, path: str, default_category: str = "unknown",
                   source: str = "csv") -> int:
        """Generic CSV with columns kind,value,label[,category,notes]  OR the FoxIO
        ja4plus-mapping.csv (columns Application/Library/... ja4, ja4s ...)."""
        n = 0
        with open(path, encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            cols = {c.lower().strip(): c for c in (reader.fieldnames or [])}
            for row in reader:
                if "kind" in cols and "value" in cols:
                    self.add(row[cols["kind"]].strip(), row[cols["value"]].strip(),
                             row[cols["label"]].strip(),
                             (row.get(cols.get("category", ""), "") or default_category).strip(),
                             source, notes=row.get(cols.get("notes", ""), None))
                    n += 1
                    continue
                label = " / ".join(
                    row[cols[c]].strip() for c in ("application", "library", "device", "os")
                    if c in cols and row[cols[c]] and row[cols[c]].strip())
                if not label:
                    continue
                for kind in ("ja4", "ja4s", "ja3", "ja3s"):
                    if kind in cols and row[cols[kind]] and row[cols[kind]].strip():
                        cat = "malware" if any(w in label.lower() for w in
                                               ("malware", "c2", "rat", "stealer", "cobalt",
                                                "sliver", "trojan")) else default_category
                        self.add(kind, row[cols[kind]].strip(), label, cat, source)
                        n += 1
        return n

    def sync_redis(self, redis_url: str) -> int:
        import redis
        r = redis.Redis.from_url(redis_url, decode_responses=True)
        pipe = r.pipeline()
        # Delete only keys created by the previous sync. A shared Redis instance may
        # contain other applications' tlsfp:* keys, which must not be wiped.
        old_keys = r.smembers(_REDIS_INDEX_KEY)
        if old_keys:
            pipe.delete(*old_keys)
        pipe.delete(_REDIS_INDEX_KEY)
        rows = self.entries()
        for row in rows:
            key = f"tlsfp:{row['kind']}:{row['value']}"
            pipe.sadd(key,
                      f"{row['label']}\x1f{row['category']}")
            pipe.sadd(_REDIS_INDEX_KEY, key)
        pipe.execute()
        return len(rows)

    # ------------------------------------------------------------ reporting
    def report(self, since: float | None = None) -> dict:
        where, args = ("WHERE ts >= ?", [since]) if since else ("", [])
        q = lambda sql: self.conn.execute(sql.format(where=where), args).fetchall()  # noqa: E731
        return {
            "total": q("SELECT COUNT(*) n FROM observations {where}")[0]["n"],
            "by_status": q("""SELECT COALESCE(status, 'n/a') status, COUNT(*) n FROM observations
                              {where} GROUP BY status ORDER BY n DESC"""),
            "by_verdict": q("""SELECT verdict, category, COUNT(*) n FROM observations {where}
                               GROUP BY verdict, category ORDER BY n DESC"""),
            "top_unknown": q("""SELECT ja4, ja3, COUNT(*) n, GROUP_CONCAT(DISTINCT sni) snis,
                                       GROUP_CONCAT(DISTINCT process) procs
                                FROM observations {where}
                                {and_} verdict='UNKNOWN'
                                GROUP BY ja4, ja3 ORDER BY n DESC LIMIT 10"""
                             .replace("{and_}", "AND" if where else "WHERE")),
            "malware": q("""SELECT ts, src, dst, dport, sni, verdict, ja3 FROM observations
                            {where} {and_} category='malware' ORDER BY ts DESC LIMIT 50"""
                         .replace("{and_}", "AND" if where else "WHERE")),
            "process_vs_verdict": q("""SELECT process, verdict, COUNT(*) n FROM observations
                                       {where} {and_} process IS NOT NULL
                                       GROUP BY process, verdict ORDER BY process, n DESC"""
                                    .replace("{and_}", "AND" if where else "WHERE")),
        }
