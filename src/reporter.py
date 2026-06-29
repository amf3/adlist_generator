# src/reporter.py
import sys
from datetime import datetime, timezone
from .parsers import SourceStats

# A list whose net contribution falls below this fraction of its fetched domains
# is flagged for removal in the recommendations section.
_LOW_CONTRIBUTION_THRESHOLD = 0.01


def write_build_summary(
    filepath: str,
    source_stats: dict[str, SourceStats],
    subsumption_counts: dict[str, int],
    self_subsumption_counts: dict[str, int],
    final_blocked_count: int,
    local_record_count: int,
) -> None:
    """
    Write a human-readable build summary with per-source statistics, a padded
    overlap matrix for evaluating list redundancy, and a recommendations section
    flagging lists with low net contribution.

    Overlap matrix covers exact duplicates only (same domain string in two lists).
    Subsumption (parent zone makes child redundant) is shown in the per-source
    stats but not in the matrix since it's only detectable after trie construction.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    total_fetched = sum(s.fetched for s in source_stats.values())
    total_unique = sum(s.unique for s in source_stats.values())
    total_exact_dupes = sum(s.exact_dupes for s in source_stats.values())
    total_subsumed = sum(subsumption_counts.values()) + sum(
        self_subsumption_counts.values()
    )

    # Pre-compute per-source net contributions for use in both the table and
    # the recommendations section.
    net_contributions: dict[str, int] = {}
    for url, stats in source_stats.items():
        subsumed = subsumption_counts.get(url, 0)
        self_sub = self_subsumption_counts.get(url, 0)
        net_contributions[url] = stats.unique - subsumed - self_sub

    print(f"Writing: {filepath}")

    try:
        with open(filepath, "w") as f:
            f.write(f"Build Summary — {timestamp}\n")
            f.write("=" * 60 + "\n\n")

            # --- Per-source ingestion stats ---
            f.write("Source lists:\n")
            name_width = max(
                (len(s.short_name) for s in source_stats.values()), default=20
            )

            for url, stats in source_stats.items():
                net = net_contributions[url]
                f.write(
                    f"  {stats.short_name:<{name_width}}"
                    f"  {stats.fetched:>8,} fetched"
                    f"  {stats.unique:>8,} unique"
                    f"  {stats.exact_dupes:>8,} exact dupes"
                    f"  {subsumption_counts.get(url, 0):>6,} subsumed by other"
                    f"  {self_subsumption_counts.get(url, 0):>6,} subsumed by self"
                    f"  {net:>8,} net contribution\n"
                )

            f.write("\n")
            f.write(f"  Total fetched:              {total_fetched:>10,}\n")
            f.write(f"  Total unique (pre-trie):    {total_unique:>10,}\n")
            f.write(f"  Total exact dupes:          {total_exact_dupes:>10,}\n")
            f.write(f"  Pruned by subsumption:      {total_subsumed:>10,}\n")
            f.write(f"  Final blocked zones:        {final_blocked_count:>10,}\n")
            f.write(f"  Local authority records:    {local_record_count:>10,}\n")

            # --- Overlap matrix ---
            if len(source_stats) > 1:
                f.write("\nOverlap matrix (exact duplicates only):\n")
                f.write(
                    "  A domain counted here appeared in list B but was already seen in list A.\n"
                )
                f.write(
                    "  '% of B' = what fraction of B's unique domains were already covered by A.\n\n"
                )

                # Build all rows first so we can measure column widths before writing.
                rows: list[tuple[str, int, float, float]] = []
                max_label_width = 0

                for b_url, b_stats in source_stats.items():
                    if not b_stats.overlaps_with:
                        continue
                    for a_url, overlap_count in sorted(
                        b_stats.overlaps_with.items(), key=lambda x: x[1], reverse=True
                    ):
                        a_name = source_stats[a_url].short_name
                        b_name = b_stats.short_name
                        label = f"{a_name} ∩ {b_name}"
                        pct_of_b = (
                            (overlap_count / b_stats.unique * 100)
                            if b_stats.unique
                            else 0.0
                        )
                        pct_of_a = (
                            (overlap_count / source_stats[a_url].unique * 100)
                            if source_stats[a_url].unique
                            else 0.0
                        )
                        rows.append(
                            (label, overlap_count, pct_of_b, pct_of_a, a_name, b_name)
                        )
                        max_label_width = max(max_label_width, len(label))

                max_count_width = max((len(f"{r[1]:,}") for r in rows), default=6)

                for label, overlap_count, pct_of_b, pct_of_a, a_name, b_name in rows:
                    a_short = a_name.split("/")[-1]
                    b_short = b_name.split("/")[-1]
                    f.write(
                        f"  {label:<{max_label_width}}  "
                        f"{overlap_count:>{max_count_width},} shared  "
                        f"({pct_of_b:5.1f}% of {b_short}, "
                        f"{pct_of_a:5.1f}% of {a_short})\n"
                    )

            # --- Subsumption note ---
            if total_subsumed > 0:
                f.write("\nSubsumption note:\n")
                f.write(
                    "  'Subsumed by other' = domains from this list made redundant by a broader\n"
                    "  zone block from a different list (e.g. list A blocks example.com, making\n"
                    "  list B's ads.example.com entry unnecessary).\n"
                    "  'Subsumed by self' = same as above but the parent zone came from this list.\n"
                )

            # --- Recommendations ---
            f.write("\nRecommendations:\n")

            flagged: list[tuple[str, SourceStats, float]] = []
            for url, stats in source_stats.items():
                net = net_contributions[url]
                ratio = net / stats.fetched if stats.fetched else 0.0
                if ratio < _LOW_CONTRIBUTION_THRESHOLD:
                    flagged.append((url, stats, ratio))

            if flagged:
                f.write(
                    f"  The following lists have a net contribution below "
                    f"{_LOW_CONTRIBUTION_THRESHOLD * 100:.0f}% of their fetched domain count.\n"
                    f"  Consider removing them from adlists_sources.yml.\n\n"
                )
                for url, stats, ratio in sorted(flagged, key=lambda x: x[2]):
                    net = net_contributions[url]
                    f.write(
                        f"  REMOVE?  {stats.short_name}\n"
                        f"           {net:,} net domains from {stats.fetched:,} fetched "
                        f"({ratio * 100:.2f}% contribution)\n"
                        f"           {url}\n\n"
                    )
            else:
                f.write(
                    f"  All lists are above the {_LOW_CONTRIBUTION_THRESHOLD * 100:.0f}% "
                    f"net contribution threshold. No changes recommended.\n"
                )

    except IOError as e:
        print(f"Error writing {filepath}: {e}", file=sys.stderr)
