"""Aggregate CVSS severity levels by published year from cvelistV5 JSON."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from itertools import repeat
from typing import Dict, Iterable, List, Tuple


PUBLISHED_STATE = "PUBLISHED"
DATE_PREFIX_LEN = 4
YEAR_RE = re.compile(r"^CVE-(\d{4})-\d+", re.IGNORECASE)

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "none"]


def find_default_root() -> str:
	here = os.path.dirname(os.path.abspath(__file__))
	candidate = os.path.join(here, "cvelistV5", "cves")
	if os.path.isdir(candidate):
		return candidate
	return os.path.join(here, "cves")


def iter_json_files(root: str) -> Iterable[str]:
	for dirpath, _, filenames in os.walk(root):
		for name in filenames:
			if not name.endswith(".json"):
				continue
			if name in {"delta.json", "deltaLog.json"}:
				continue
			yield os.path.join(dirpath, name)


def extract_published_year(record: Dict, year_policy: str) -> Tuple[str | None, str | None]:
	meta = record.get("cveMetadata", {}) if isinstance(record, dict) else {}
	if meta.get("state") != PUBLISHED_STATE:
		return None, "state"
	date_published = meta.get("datePublished")
	if isinstance(date_published, str) and len(date_published) >= DATE_PREFIX_LEN:
		year = date_published[:DATE_PREFIX_LEN]
		if year.isdigit():
			return year, "datePublished"
	if year_policy == "dateUpdated":
		date_updated = meta.get("dateUpdated")
		if isinstance(date_updated, str) and len(date_updated) >= DATE_PREFIX_LEN:
			year = date_updated[:DATE_PREFIX_LEN]
			if year.isdigit():
				return year, "dateUpdated"
	if year_policy == "cveId":
		cve_id = meta.get("cveId") or record.get("cveId")
		if isinstance(cve_id, str):
			match = YEAR_RE.match(cve_id)
			if match:
				return match.group(1), "cveId"
	return None, "missing"


def extract_cvss_basescores(record: Dict) -> Tuple[List[float], List[float]]:
	cna = record.get("containers", {}).get("cna", {})
	metrics = cna.get("metrics", []) if isinstance(cna, dict) else []
	v31_scores: List[float] = []
	v30_scores: List[float] = []
	for entry in metrics if isinstance(metrics, list) else []:
		if not isinstance(entry, dict):
			continue
		cvss31 = entry.get("cvssV3_1")
		if isinstance(cvss31, dict):
			base = cvss31.get("baseScore")
			if isinstance(base, (int, float)):
				v31_scores.append(float(base))
		cvss30 = entry.get("cvssV3_0")
		if isinstance(cvss30, dict):
			base = cvss30.get("baseScore")
			if isinstance(base, (int, float)):
				v30_scores.append(float(base))
	return v31_scores, v30_scores


def classify_severity(score: float) -> str:
	if score >= 9.0:
		return "critical"
	if score >= 7.0:
		return "high"
	if score >= 4.0:
		return "medium"
	if score >= 0.1:
		return "low"
	return "none"


def load_year_and_severity(
	path: str,
	year_policy: str,
) -> Tuple[str | None, str | None, str | None, bool, bool]:
	try:
		with open(path, "r", encoding="utf-8") as handle:
			record = json.load(handle)
	except (OSError, json.JSONDecodeError):
		return None, None, None, True, False

	year, reason = extract_published_year(record, year_policy)
	if year is None:
		return None, reason, None, False, False

	v31_scores, v30_scores = extract_cvss_basescores(record)
	if v31_scores:
		score = max(v31_scores)
	elif v30_scores:
		score = max(v30_scores)
	else:
		return year, reason, None, False, True

	level = classify_severity(score)
	return year, reason, level, False, False


def count_severity_by_year(
	root: str,
	year_policy: str,
	workers: int,
) -> Tuple[Dict[str, Dict[str, int]], Dict[str, int]]:
	stats = {
		"files": 0,
		"published": 0,
		"missing_year": 0,
		"fallback_dateUpdated": 0,
		"fallback_cveId": 0,
		"missing_cvss": 0,
		"json_error": 0,
	}
	per_year: Dict[str, Dict[str, int]] = defaultdict(
		lambda: {
			"published_total": 0,
			"scored_total": 0,
			"missing_cvss": 0,
			**{k: 0 for k in SEVERITY_LEVELS},
		}
	)

	paths: List[str] = list(iter_json_files(root))
	stats["files"] = len(paths)

	def handle_result(result: Tuple[str | None, str | None, str | None, bool, bool]):
		year, reason, level, had_error, missing_cvss = result
		if had_error:
			stats["json_error"] += 1
			return
		if year is None:
			if reason != "state":
				stats["missing_year"] += 1
			return
		stats["published"] += 1
		per_year[year]["published_total"] += 1
		if reason == "dateUpdated":
			stats["fallback_dateUpdated"] += 1
		elif reason == "cveId":
			stats["fallback_cveId"] += 1
		if missing_cvss or level is None:
			stats["missing_cvss"] += 1
			per_year[year]["missing_cvss"] += 1
			return
		per_year[year]["scored_total"] += 1
		per_year[year][level] += 1

	if workers <= 1:
		for path in paths:
			handle_result(load_year_and_severity(path, year_policy))
		return per_year, stats

	with ProcessPoolExecutor(max_workers=workers) as executor:
		for result in executor.map(load_year_and_severity, paths, repeat(year_policy), chunksize=200):
			handle_result(result)

	return per_year, stats


def main() -> int:
	parser = argparse.ArgumentParser(
		description="Count CVSS severity levels by published year (CNA metrics only)",
	)
	parser.add_argument(
		"--root",
		default=find_default_root(),
		help="Root directory of CVE JSON files (default: cvelistV5/cves)",
	)
	parser.add_argument(
		"--year-policy",
		choices=["exclude", "dateUpdated", "cveId"],
		default="exclude",
		help=(
			"How to handle missing datePublished: exclude, dateUpdated, or cveId"
		),
	)
	parser.add_argument(
		"--out",
		default="cvss_severity_by_year.csv",
		help="Output CSV file",
	)
	parser.add_argument(
		"--workers",
		type=int,
		default=0,
		help="Number of worker processes (0=auto, 1=disable parallel)",
	)
	args = parser.parse_args()

	root = os.path.abspath(args.root)
	if not os.path.isdir(root):
		print(f"Root directory not found: {root}", file=sys.stderr)
		return 2

	if args.workers == 0:
		workers = os.cpu_count() or 1
	else:
		workers = args.workers

	per_year, stats = count_severity_by_year(root, args.year_policy, workers)
	years = sorted(per_year)
	with open(args.out, "w", encoding="utf-8", newline="") as handle:
		writer = csv.writer(handle)
		writer.writerow(
			[
				"year",
				"published_total",
				"scored_total",
				"missing_cvss",
				*SEVERITY_LEVELS,
			]
		)
		for year in years:
			writer.writerow(
				[
					year,
					per_year[year]["published_total"],
					per_year[year]["scored_total"],
					per_year[year]["missing_cvss"],
					*[per_year[year][level] for level in SEVERITY_LEVELS],
				]
			)

	print(
		"\n".join(
			[
				f"out\t{args.out}",
				f"files\t{stats['files']}",
				f"published\t{stats['published']}",
				f"missing_year\t{stats['missing_year']}",
				f"fallback_dateUpdated\t{stats['fallback_dateUpdated']}",
				f"fallback_cveId\t{stats['fallback_cveId']}",
				f"missing_cvss\t{stats['missing_cvss']}",
				f"json_error\t{stats['json_error']}",
			]
		),
		file=sys.stderr,
	)
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
