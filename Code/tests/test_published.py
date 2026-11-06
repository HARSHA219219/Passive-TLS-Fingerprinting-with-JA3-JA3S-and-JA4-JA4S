"""Validation against published reference values (see data/published_references.json and
tests/fixtures/foxio/SOURCE.md)."""
import glob
import json
import os
import sys

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

from tlsfp.reference import check_vectors, compare_foxio  # noqa: E402

REFS = os.path.join(ROOT, "data", "published_references.json")
SNAPS = sorted(glob.glob(os.path.join(ROOT, "tests", "fixtures", "foxio", "*.snap")))


def test_published_ja3_ja3s_string_vectors():
    rows = check_vectors(REFS)
    assert rows and not [r for r in rows if r["result"] == "FAIL"], rows


@pytest.mark.parametrize("snap", SNAPS, ids=[os.path.basename(s) for s in SNAPS])
def test_foxio_reference_pcaps(snap):
    rows = compare_foxio(snap[:-len(".snap")], snap)
    assert rows, "no TCP connections compared"
    bad = [r for r in rows if r["result"] == "FAIL"]
    assert not bad, bad


def test_our_chrome_capture_matches_published_chrome_ja4():
    """The JA4 we learned from real Chrome traffic equals FoxIO's published Chrome JA4."""
    with open(REFS, encoding="utf-8") as f:
        published = {(r["kind"], r["value"]) for r in json.load(f)["fingerprints"]
                     if r["label"] == "Google Chrome"}
    with open(os.path.join(ROOT, "data", "reference_db.json"), encoding="utf-8") as f:
        learned = {(r["kind"], r["value"]) for r in json.load(f) if r["label"] == "Google Chrome"}
    assert published & learned
