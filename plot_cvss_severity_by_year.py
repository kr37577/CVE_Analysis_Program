"""Plot CVSS severity distribution by published year from cvss_severity_by_year.csv."""

from __future__ import annotations

import argparse
import csv
from datetime import date
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class YearRow:
    year: int
    published_total: int
    scored_total: int
    missing_cvss: int
    critical: int
    high: int
    medium: int
    low: int
    none: int


SEVERITY_ORDER = ["critical", "high", "medium", "low", "none"]


def _parse_int(value: object) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def load_rows(csv_path: Path) -> list[YearRow]:
    rows: list[YearRow] = []
    with csv_path.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for raw in reader:
            if not raw:
                continue
            year = _parse_int(raw.get("year"))
            if year <= 0:
                continue
            rows.append(
                YearRow(
                    year=year,
                    published_total=_parse_int(raw.get("published_total")),
                    scored_total=_parse_int(raw.get("scored_total")),
                    missing_cvss=_parse_int(raw.get("missing_cvss")),
                    critical=_parse_int(raw.get("critical")),
                    high=_parse_int(raw.get("high")),
                    medium=_parse_int(raw.get("medium")),
                    low=_parse_int(raw.get("low")),
                    none=_parse_int(raw.get("none")),
                )
            )
    return sorted(rows, key=lambda r: r.year)


def filter_years(rows: list[YearRow], min_year: int, max_year: int | None) -> list[YearRow]:
    filtered = [r for r in rows if r.year >= min_year]
    if max_year is not None:
        filtered = [r for r in filtered if r.year <= max_year]
    return filtered


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Plot CVSS severity distribution by year")
    parser.add_argument(
        "--csv",
        default="cvss_severity_by_year.csv",
        help="Input CSV file produced by count_cvss_by_year.py",
    )
    parser.add_argument(
        "--min-year",
        type=int,
        default=2016,
        help="Min year to include (default: 2016)",
    )
    parser.add_argument(
        "--max-year",
        type=int,
        default=None,
        help="Max year to include (default: auto; excludes current year)",
    )
    parser.add_argument(
        "--out",
        default="cvss_severity_by_year.png",
        help="Output image file",
    )
    missing_group = parser.add_mutually_exclusive_group()
    missing_group.add_argument(
        "--include-missing",
        action="store_true",
        help="Include missing_cvss as an extra stacked segment (default: on)",
    )
    missing_group.add_argument(
        "--exclude-missing",
        action="store_true",
        help="Exclude missing_cvss from the stacked bars",
    )
    parser.add_argument(
        "--normalize",
        action="store_true",
        help=(
            "Plot percentages instead of counts. "
            "Denominator is scored_total (or published_total when --include-missing)."
        ),
    )
    parser.add_argument(
        "--dpi",
        type=int,
        default=150,
        help="Output DPI (default: 150)",
    )
    args = parser.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.is_file():
        raise SystemExit(f"CSV not found: {csv_path}")

    include_missing = not args.exclude_missing

    all_rows = load_rows(csv_path)
    if not all_rows:
        raise SystemExit("No data to plot")

    if args.max_year is None:
        data_max_year = max(r.year for r in all_rows)
        current_year = date.today().year
        # Default: exclude current year because it's typically partial/incomplete.
        max_year = min(data_max_year, current_year -
                       1) if data_max_year >= current_year else data_max_year
    else:
        max_year = args.max_year

    rows = filter_years(all_rows, args.min_year, max_year)
    if not rows:
        raise SystemExit("No data to plot")

    try:
        import matplotlib.pyplot as plt
    except Exception as exc:  # pragma: no cover
        raise SystemExit(
            "matplotlib is required. Install with: python -m pip install matplotlib\n"
            f"Import error: {exc}"
        ) from exc

    years = [r.year for r in rows]

    # Values (counts)
    series: dict[str, list[int]] = {
        "critical": [r.critical for r in rows],
        "high": [r.high for r in rows],
        "medium": [r.medium for r in rows],
        "low": [r.low for r in rows],
        "none": [r.none for r in rows],
    }

    if include_missing:
        series["missing_cvss"] = [r.missing_cvss for r in rows]

    # Normalize if requested
    if args.normalize:
        denoms: list[int]
        if include_missing:
            denoms = [max(r.published_total, 1) for r in rows]
        else:
            denoms = [max(r.scored_total, 1) for r in rows]

        for key, values in list(series.items()):
            # type: ignore[list-item]
            series[key] = [round((v / d) * 100.0, 3)
                           for v, d in zip(values, denoms)]

    colors = {
        "critical": "#d62728",
        "high": "#ff7f0e",
        "medium": "#bcbd22",
        "low": "#2ca02c",
        "none": "#7f7f7f",
        "missing_cvss": "#c7c7c7",
    }
    labels = {
        "critical": "Critical (9.0–10.0)",
        "high": "High (7.0–8.9)",
        "medium": "Medium (4.0–6.9)",
        "low": "Low (0.1–3.9)",
        "none": "None (0.0)",
        "missing_cvss": "Missing CVSS (CNA only)",
    }

    plt.rcParams.update(
        {
            "font.size": 12,
            "axes.titlesize": 16,
            "axes.labelsize": 13,
            "xtick.labelsize": 11,
            "ytick.labelsize": 11,
        }
    )
    plt.figure(figsize=(13, 7), dpi=args.dpi)

    bottom = [0.0 if args.normalize else 0] * len(years)
    plot_order = SEVERITY_ORDER + \
        (["missing_cvss"] if include_missing else [])
    for key in plot_order:
        values = series[key]
        bars = plt.bar(
            years,
            values,
            bottom=bottom,
            label=labels[key],
            color=colors[key],
            edgecolor="#2f2f2f",
            linewidth=0.4,
        )
        # hatch for missing to distinguish
        if key == "missing_cvss":
            for bar in bars:
                bar.set_hatch("//")
        bottom = [b + v for b, v in zip(bottom, values)]

    plt.title("CVSS Severity by Published Year (CNA metrics)")
    plt.xlabel("Year")
    plt.ylabel("Percent (%)" if args.normalize else "Count")
    plt.xticks(years, rotation=45, ha="right")
    plt.grid(axis="y", linestyle="--", alpha=0.3)
    plt.gca().set_axisbelow(True)
    if not args.normalize:
        plt.gca().get_yaxis().set_major_formatter(
            plt.FuncFormatter(lambda x, _: f"{int(x):,}"))
    plt.legend(ncol=2, frameon=False)
    plt.tight_layout()
    plt.savefig(args.out, dpi=args.dpi)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
