"""Plot CVE counts per year from a CSV file."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import matplotlib.pyplot as plt


def load_counts(csv_path: Path, min_year: int, max_year: int) -> tuple[list[int], list[int]]:
	years: list[int] = []
	counts: list[int] = []
	with csv_path.open("r", encoding="utf-8") as handle:
		reader = csv.DictReader(handle)
		for row in reader:
			try:
				year = int(row["year"])
				count = int(row["count"])
			except (KeyError, TypeError, ValueError):
				continue
			if year < min_year or year > max_year:
				continue
			years.append(year)
			counts.append(count)
	return years, counts


def main() -> int:
	parser = argparse.ArgumentParser(description="Plot CVE counts per year")
	parser.add_argument(
		"--csv",
		default="result.csv",
		help="Input CSV file with columns year,count",
	)
	parser.add_argument(
		"--min-year",
		type=int,
		default=2015,
		help="Min year to include",
	)
	parser.add_argument(
		"--max-year",
		type=int,
		default=2025,
		help="Max year to include",
	)
	parser.add_argument(
		"--out",
		default="cve_counts_by_year.png",
		help="Output image file",
	)
	args = parser.parse_args()

	csv_path = Path(args.csv)
	if not csv_path.is_file():
		raise SystemExit(f"CSV not found: {csv_path}")

	years, counts = load_counts(csv_path, args.min_year, args.max_year)
	if not years:
		raise SystemExit("No data to plot")

	colors = ["#1f77b4"] * len(years)
	for idx, year in enumerate(years):
		if year == args.max_year:
			colors[idx] = "#ff7f0e"

	plt.rcParams.update(
		{
			"font.size": 12,
			"axes.titlesize": 16,
			"axes.labelsize": 13,
			"xtick.labelsize": 11,
			"ytick.labelsize": 11,
		}
	)
	plt.figure(figsize=(12, 6), dpi=150)
	bars = plt.bar(years, counts, color=colors, edgecolor="#2f2f2f", linewidth=0.6)
	plt.title("CVE Published Counts by Year")
	plt.xlabel("Year")
	plt.ylabel("Count")
	plt.xticks(years, rotation=45, ha="right")
	plt.grid(axis="y", linestyle="--", alpha=0.3)
	plt.gca().set_axisbelow(True)
	plt.gca().get_yaxis().set_major_formatter(
		plt.FuncFormatter(lambda x, _: f"{int(x):,}")
	)
	for bar, count in zip(bars, counts):
		height = bar.get_height()
		plt.annotate(
			f"{count:,}",
			xy=(bar.get_x() + bar.get_width() / 2, height),
			xytext=(0, 4),
			textcoords="offset points",
			ha="center",
			va="bottom",
			fontsize=10,
		)
	plt.tight_layout()
	plt.savefig(args.out, dpi=150)
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
