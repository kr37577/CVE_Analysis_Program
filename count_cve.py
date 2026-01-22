"""Count published CVEs per 1k processed records or per year from cvelistV5."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from typing import Dict, Iterable, List, Tuple


PUBLISHED_STATE = "PUBLISHED"
BUCKET_SIZE = 1_000
DATE_PREFIX_LEN = 4
YEAR_RE = re.compile(r"^CVE-(\d{4})-\d+", re.IGNORECASE)


def find_default_root() -> str:
	here = os.path.dirname(os.path.abspath(__file__))
	candidate = os.path.join(here, "cvelistV5", "cves")
	if os.path.isdir(candidate):
		return candidate
	return os.path.join(here, "cves")


def is_published(record: Dict) -> bool:
	meta = record.get("cveMetadata", {}) if isinstance(record, dict) else {}
	return meta.get("state") == PUBLISHED_STATE


def extract_year(record: Dict, year_policy: str) -> Tuple[str | None, str | None]:
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


def iter_json_files(root: str) -> Iterable[str]:
	for dirpath, _, filenames in os.walk(root):
		for name in filenames:
			if not name.endswith(".json"):
				continue
			if name in {"delta.json", "deltaLog.json"}:
				continue
			yield os.path.join(dirpath, name)


def load_publish_state(path: str) -> Tuple[bool, bool]:
	try:
		with open(path, "r", encoding="utf-8") as handle:
			record = json.load(handle)
	except (OSError, json.JSONDecodeError):
		return False, True

	return is_published(record), False


def count_published_by_batch(root: str, workers: int) -> Tuple[Counter, Counter, Dict[str, int]]:
	published_counts: Counter = Counter()
	processed_counts: Counter = Counter()
	stats = {
		"files": 0,
		"published": 0,
		"skipped_state": 0,
		"json_error": 0,
	}

	paths: List[str] = list(iter_json_files(root))
	stats["files"] = len(paths)

	def handle_result(index: int, result: Tuple[bool, bool]):
		is_pub, had_error = result
		batch = index // BUCKET_SIZE
		processed_counts[batch] += 1
		if had_error:
			stats["json_error"] += 1
			return
		if is_pub:
			stats["published"] += 1
			published_counts[batch] += 1
		else:
			stats["skipped_state"] += 1

	if workers <= 1:
		for index, path in enumerate(paths):
			handle_result(index, load_publish_state(path))
		return published_counts, processed_counts, stats

	with ProcessPoolExecutor(max_workers=workers) as executor:
		for index, result in enumerate(executor.map(load_publish_state, paths, chunksize=200)):
			handle_result(index, result)

	return published_counts, processed_counts, stats


def count_published_by_year(root: str, year_policy: str) -> Tuple[Counter, Dict[str, int]]:
	counts: Counter = Counter()
	stats = {
		"files": 0,
		"published": 0,
		"skipped_state": 0,
		"missing_year": 0,
		"fallback_dateUpdated": 0,
		"fallback_cveId": 0,
		"json_error": 0,
	}

	for path in iter_json_files(root):
		stats["files"] += 1
		try:
			with open(path, "r", encoding="utf-8") as handle:
				record = json.load(handle)
		except (OSError, json.JSONDecodeError):
			stats["json_error"] += 1
			continue

		year, reason = extract_year(record, year_policy)
		if year is None:
			if reason == "state":
				stats["skipped_state"] += 1
			else:
				stats["missing_year"] += 1
			continue

		stats["published"] += 1
		counts[year] += 1
		if reason == "dateUpdated":
			stats["fallback_dateUpdated"] += 1
		elif reason == "cveId":
			stats["fallback_cveId"] += 1

	return counts, stats


def main() -> int:
	parser = argparse.ArgumentParser(
		description="Count published CVEs from cvelistV5/cves",
	)
	parser.add_argument(
		"--root",
		default=find_default_root(),
		help="Root directory of CVE JSON files (default: cvelistV5/cves)",
	)
	parser.add_argument(
		"--csv",
		action="store_true",
		help="Output as CSV",
	)
	parser.add_argument(
		"--out",
		help="Write output to a file (use with --csv)",
	)
	parser.add_argument(
		"--mode",
		choices=["batch", "year"],
		default="batch",
		help="Aggregation mode: batch (1k files) or year",
	)
	parser.add_argument(
		"--year-policy",
		choices=["exclude", "dateUpdated", "cveId"],
		default="exclude",
		help=(
			"How to handle missing datePublished when mode=year: "
			"exclude, dateUpdated, or cveId"
		),
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

	out_stream = sys.stdout
	if args.out:
		if not args.csv:
			print("--out requires --csv", file=sys.stderr)
			return 2
		out_stream = open(args.out, "w", encoding="utf-8")

	if args.mode == "batch":
		if args.workers == 0:
			workers = os.cpu_count() or 1
		else:
			workers = args.workers

		published_counts, processed_counts, stats = count_published_by_batch(root, workers)

		if args.csv:
			print("batch,start,end,processed,published", file=out_stream)
			for batch in sorted(processed_counts):
				start = batch * BUCKET_SIZE + 1
				end = batch * BUCKET_SIZE + processed_counts[batch]
				print(
					f"{batch + 1},{start},{end},"
					f"{processed_counts[batch]},{published_counts.get(batch, 0)}",
					file=out_stream,
				)
		else:
			for batch in sorted(processed_counts):
				start = batch * BUCKET_SIZE + 1
				end = batch * BUCKET_SIZE + processed_counts[batch]
				print(
					f"batch {batch + 1}\t"
					f"{start:07d}-{end:07d}\t"
					f"processed {processed_counts[batch]}\t"
					f"published {published_counts.get(batch, 0)}"
				)
	else:
		counts, stats = count_published_by_year(root, args.year_policy)
		if args.csv:
			print("year,count", file=out_stream)
			for year in sorted(counts):
				print(f"{year},{counts[year]}", file=out_stream)
		else:
			for year in sorted(counts):
				print(f"{year}\t{counts[year]}")

	if out_stream is not sys.stdout:
		out_stream.close()

	print(
		"\n".join(
			[
				"",
				f"files\t{stats['files']}",
				f"published\t{stats['published']}",
				f"skipped_state\t{stats['skipped_state']}",
				f"missing_year\t{stats.get('missing_year', 0)}",
				f"fallback_dateUpdated\t{stats.get('fallback_dateUpdated', 0)}",
				f"fallback_cveId\t{stats.get('fallback_cveId', 0)}",
				f"json_error\t{stats['json_error']}",
			]
		),
		file=sys.stderr,
	)
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
