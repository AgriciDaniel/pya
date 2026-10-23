"""Version comparator edge cases (PEP 440-ish and semver-ish)."""

import pytest

LESS = [
    ("1.0.0", "1.0.1"),
    ("1.9", "1.10"),
    ("1.2.3", "1.2.10"),
    ("0.35.4", "0.35.5"),
    ("2026.10.1", "2026.10.19"),
    ("2026.10.18", "2026.10.19"),
    ("1.0.0-alpha", "1.0.0"),
    ("1.0.0-alpha", "1.0.0-alpha.1"),
    ("1.0.0-alpha.1", "1.0.0-beta"),
    ("1.0.0-beta.2", "1.0.0-beta.11"),
    ("1.0.0-rc.1", "1.0.0"),
    ("16.4.1-canary.3", "16.4.1"),
    ("1.0a1", "1.0b1"),
    ("1.0b2", "1.0rc1"),
    ("1.0rc1", "1.0"),
    ("1.0.dev1", "1.0a1"),
    ("1.0", "1.0.post1"),
    ("1.0rc1.dev1", "1.0rc1"),
    ("v1.2.3", "1.2.4"),
    ("1!0.1", "1!0.2"),
    ("3.1.8.8", "3.1.8.9"),
    ("1.43.3.10860", "1.43.3.10861"),
]
EQUAL = [
    ("1.0", "1.0.0"),
    ("v1.2.3", "1.2.3"),
    ("=1.2.3", "1.2.3"),
    ("1.2.3+build.5", "1.2.3"),
    ("1.0.0", "1.0.0.0"),
]


@pytest.mark.parametrize("a,b", LESS)
def test_less(common, a, b):
    assert common.compare(a, b) == -1
    assert common.compare(b, a) == 1


@pytest.mark.parametrize("a,b", EQUAL)
def test_equal(common, a, b):
    assert common.compare(a, b) == 0


def test_epoch_beats_release(common):
    assert common.compare("1!0.1", "99.0") == 1


def test_unparseable(common):
    assert common.version_key("latest") is None
    assert common.version_key("") is None
    with pytest.raises(ValueError):
        common.compare("latest", "1.0")


def test_ranges(common):
    entry = {"ranges": [{"introduced": "0", "fixed": "6.29.1"}, {"introduced": "7.0.0", "fixed": "7.30.1"}]}
    assert common.affected("6.29.0", entry)
    assert not common.affected("6.29.1", entry)
    assert common.affected("7.0.0", entry)
    assert not common.affected("7.30.1", entry)
    assert not common.affected("8.0.0", entry)
    last = {"ranges": [{"introduced": "0", "last_affected": "3.15.3"}]}
    assert common.affected("3.15.3", last)
    assert not common.affected("3.15.4", last)
    open_ended = {"ranges": [{"introduced": "0"}]}
    assert common.affected("99.0.0", open_ended)
    exact = {"versions": ["1.107.0"]}
    assert common.affected("1.107.0", exact)
    assert common.affected("v1.107.0", exact)
    assert not common.affected("1.107.1", exact)


def test_prerelease_of_fixed_is_affected(common):
    entry = {"ranges": [{"introduced": "16.0.0", "fixed": "16.4.1"}]}
    assert common.affected("16.4.1-canary.1", entry)
    assert not common.affected("16.4.1", entry)


def test_branch_status(common):
    node = {"ranges": [{"introduced": "0", "fixed": "22.0.0"}, {"introduced": "22.0.0", "fixed": "22.23.4"},
                       {"introduced": "24.0.0", "fixed": "24.22.1"}]}
    assert common.branch_status("20", node)[0] == "all"
    assert common.branch_status("22", node)[0] == "some"
    assert common.branch_status("23", node)[0] == "none"
