# tests/test_attribution.py (reporter section)
import pytest
from src.parsers import SourceStats
from src.reporter import write_build_summary


def _make_stats(url, fetched, unique, exact_dupes, overlaps_with=None):
    s = SourceStats(url=url, fetched=fetched, unique=unique, exact_dupes=exact_dupes)
    if overlaps_with:
        s.overlaps_with = overlaps_with
    return s


def test_overlap_matrix_columns_aligned(tmp_path):
    """All shared-count values in the overlap matrix should start in the same column."""
    a_url = "https://example.com/hosts/AdguardDNS.txt"
    b_url = "https://example.com/hosts/Easylist.txt"
    c_url = "https://example.com/static/w3kbl.txt"

    stats = {
        a_url: _make_stats(a_url, fetched=158251, unique=158251, exact_dupes=0),
        b_url: _make_stats(
            b_url,
            fetched=48924,
            unique=79,
            exact_dupes=48845,
            overlaps_with={a_url: 48845},
        ),
        c_url: _make_stats(
            c_url, fetched=355, unique=316, exact_dupes=39, overlaps_with={a_url: 39}
        ),
    }

    write_build_summary(
        filepath=str(tmp_path / "build_summary.txt"),
        source_stats=stats,
        subsumption_counts={},
        self_subsumption_counts={},
        final_blocked_count=158000,
        local_record_count=5,
    )

    content = (tmp_path / "build_summary.txt").read_text()
    matrix_lines = [
        line for line in content.splitlines() if "∩" in line and "shared" in line
    ]
    assert len(matrix_lines) == 2

    # The word "shared" should appear at the same column in every matrix row.
    shared_positions = [line.index("shared") for line in matrix_lines]
    assert (
        len(set(shared_positions)) == 1
    ), f"'shared' column not aligned: positions {shared_positions}\n" + "\n".join(
        matrix_lines
    )


def test_recommendations_flags_low_contribution(tmp_path):
    a_url = "https://example.com/hosts/AdguardDNS.txt"
    b_url = "https://example.com/hosts/Easylist.txt"

    stats = {
        a_url: _make_stats(a_url, fetched=158251, unique=158251, exact_dupes=0),
        b_url: _make_stats(
            b_url,
            fetched=48924,
            unique=79,
            exact_dupes=48845,
            overlaps_with={a_url: 48845},
        ),
    }

    write_build_summary(
        filepath=str(tmp_path / "build_summary.txt"),
        source_stats=stats,
        subsumption_counts={b_url: 36},
        self_subsumption_counts={},
        final_blocked_count=158200,
        local_record_count=5,
    )

    content = (tmp_path / "build_summary.txt").read_text()
    assert "REMOVE?" in content
    assert "Easylist.txt" in content
    assert "AdguardDNS.txt" not in content.split("REMOVE?")[1]


def test_recommendations_clean_when_all_lists_healthy(tmp_path):
    a_url = "https://example.com/hosts/AdguardDNS.txt"
    b_url = "https://example.com/master/hosts"

    stats = {
        a_url: _make_stats(a_url, fetched=158251, unique=158251, exact_dupes=0),
        b_url: _make_stats(
            b_url,
            fetched=83812,
            unique=78870,
            exact_dupes=4942,
            overlaps_with={a_url: 4942},
        ),
    }

    write_build_summary(
        filepath=str(tmp_path / "build_summary.txt"),
        source_stats=stats,
        subsumption_counts={b_url: 37720},
        self_subsumption_counts={b_url: 2475},
        final_blocked_count=196000,
        local_record_count=5,
    )

    content = (tmp_path / "build_summary.txt").read_text()
    assert "No changes recommended" in content
    assert "REMOVE?" not in content


def test_zero_fetched_list_flagged(tmp_path):
    """A list that returned nothing should be flagged."""
    a_url = "https://example.com/hosts/AdguardDNS.txt"
    b_url = "https://example.com/UncheckyAds/hosts"

    stats = {
        a_url: _make_stats(a_url, fetched=158251, unique=158251, exact_dupes=0),
        b_url: _make_stats(
            b_url, fetched=9, unique=0, exact_dupes=9, overlaps_with={a_url: 9}
        ),
    }

    write_build_summary(
        filepath=str(tmp_path / "build_summary.txt"),
        source_stats=stats,
        subsumption_counts={},
        self_subsumption_counts={},
        final_blocked_count=158251,
        local_record_count=0,
    )

    content = (tmp_path / "build_summary.txt").read_text()
    assert "REMOVE?" in content
    assert "UncheckyAds" in content
