"""
test_suite_runner.py
---------------------
Runs the full pipeline over every .eml file in samples/ (or samples/test_suite/
if you create one) and prints a pass/fail table. Does NOT touch the SQLite
database used by the web app - this is a separate, offline check.

Expected filename convention for auto-grading:
  files with "phish" in the name  -> expected verdict: Dangerous or Suspicious
  files with "safe"   in the name -> expected verdict: Safe
Anything else is shown with no expected verdict (informational only).

Run:
    python test_suite_runner.py
"""

import os
import glob

from modules import parser, content_analysis, header_analysis, url_analysis
from modules import attachment_analysis, geolocation, scoring

SAMPLE_DIRS = ["samples/test_suite", "samples"]


def find_sample_files():
    for d in SAMPLE_DIRS:
        files = sorted(glob.glob(os.path.join(d, "*.eml")))
        if files:
            return files
    return []


def expected_verdict(filename):
    name = filename.lower()
    if "phish" in name:
        return "Dangerous"
    if "safe" in name:
        return "Safe"
    return None


def run_one(path):
    parsed = parser.parse_email(file_path=path)
    content_result = content_analysis.analyze_content(
        parsed["headers"].get("subject", ""), parsed["body"].get("plain") or parsed["body"].get("html", "")
    )
    header_result = header_analysis.analyze_headers(parsed["headers"])
    url_result = url_analysis.analyze_urls(parsed["urls"])
    attachment_result = attachment_analysis.analyze_attachments(parsed["attachments"])
    geo_result = geolocation.build_route(parsed["received_chain"], parsed["headers"])
    score_result = scoring.compute_threat_score(
        content_result, header_result, url_result, attachment_result, geo_result
    )
    return score_result


def main():
    files = find_sample_files()
    if not files:
        print("No .eml files found in samples/ or samples/test_suite/.")
        return

    print(f"{'Filename':<28} {'Expected':<12} {'Actual':<12} {'Score':<7} {'Match'}")
    print("-" * 70)

    matches, total = 0, 0
    mismatches = []

    for path in files:
        filename = os.path.basename(path)
        expected = expected_verdict(filename)
        result = run_one(path)
        actual = result["verdict"]
        score = result["final_score"]

        if expected:
            total += 1
            # "Suspicious" or "Dangerous" both count as a correct catch for phishing samples
            is_match = (actual == expected) or (expected == "Dangerous" and actual in ("Dangerous", "Suspicious"))
            if is_match:
                matches += 1
            else:
                mismatches.append((filename, expected, actual, result["reasons"]))
            match_str = "Yes" if is_match else "No"
        else:
            match_str = "-"

        print(f"{filename:<28} {expected or '-':<12} {actual:<12} {score:<7} {match_str}")

    if total:
        print("-" * 70)
        print(f"Accuracy on labeled samples: {matches}/{total} ({round(100*matches/total,1)}%)")

    if mismatches:
        print("\nMismatches:")
        for filename, expected, actual, reasons in mismatches:
            print(f"  {filename}: expected {expected}, got {actual}")
            for r in reasons[:3]:
                print(f"    - {r}")


if __name__ == "__main__":
    main()
