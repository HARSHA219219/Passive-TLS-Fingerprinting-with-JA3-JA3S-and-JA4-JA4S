"""Identification status for every JA3/JA4 combination (agree, ja3_only, ja4_only,
conflict, ambiguous, unknown)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tlsfp.db import FingerprintDB  # noqa: E402


@pytest.fixture
def db():
    d = FingerprintDB(":memory:")
    d.add("ja4", "J4_CHROME", "Chrome", "browser")
    d.add("ja3", "J3_CHROME", "Chrome", "browser")
    d.add("ja4", "J4_CURL", "curl", "cli")
    d.add("ja3", "J3_CURL", "curl", "cli")
    # one JA4 shared by two applications (same TLS library and config)
    d.add("ja4", "J4_SHARED", "AppA", "library")
    d.add("ja4", "J4_SHARED", "AppB", "library")
    d.add("ja3", "J3_APPA", "AppA", "library")
    d.add("ja3", "J3_BAD", "EvilBot", "malware")
    return d


def test_agree(db):
    m = db.identify("J4_CHROME", "J3_CHROME")
    assert (m.status, m.labels, m.identified) == ("agree", ["Chrome"], True)
    assert m.label == "Chrome"


def test_ja4_only(db):
    m = db.identify("J4_CHROME", "J3_RANDOMISED")          # Chrome's JA3 changes per connection
    assert (m.status, m.labels, m.identified) == ("ja4_only", ["Chrome"], True)


def test_ja3_only(db):
    m = db.identify("J4_NEW", "J3_CURL")
    assert (m.status, m.labels, m.identified) == ("ja3_only", ["curl"], True)


def test_conflict_is_not_resolved_in_favour_of_ja4(db):
    m = db.identify("J4_CHROME", "J3_CURL")
    assert m.status == "conflict"
    assert not m.identified
    assert m.ja4_labels == ["Chrome"] and m.ja3_labels == ["curl"]
    assert "Chrome" in m.label and "curl" in m.label and m.label.startswith("CONFLICT")


def test_ambiguous_shared_fingerprint(db):
    m = db.identify("J4_SHARED", None)
    assert m.status == "ambiguous" and m.labels == ["AppA", "AppB"] and not m.identified


def test_ja3_narrows_ambiguous_ja4(db):
    m = db.identify("J4_SHARED", "J3_APPA")
    assert (m.status, m.labels) == ("agree", ["AppA"])


def test_unknown(db):
    m = db.identify("J4_NEW", "J3_NEW")
    assert (m.status, m.labels, m.label, m.identified) == ("unknown", [], "UNKNOWN", False)
    assert m.category == "unknown"


def test_malware_category_survives_conflict(db):
    m = db.identify("J4_CHROME", "J3_BAD")
    assert m.status == "conflict" and m.category == "malware"


def test_server_kinds(db):
    db.add("ja4s", "S4", "nginx/OpenSSL", "server")
    m = db.identify("S4", "S3_NEW", client=False)
    assert (m.status, m.labels, m.matched_on) == ("ja4_only", ["nginx/OpenSSL"], "ja4s")
