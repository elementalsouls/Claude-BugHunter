#!/usr/bin/env python3
"""
harvest_intigriti.py — Intigriti disclosed-report collector (HONEST STUB).

Feasibility (researched): Intigriti has NO public disclosure feed or API. Disclosing
a report to any third party requires approval from BOTH Intigriti and the affected
company; public write-ups are scattered across individual researcher profiles and
external blogs. There is no reliable, structured, ToS-clean bulk source to collect.

Rather than ship a scraper that pretends otherwise, this is a deliberate stub. If a
public Intigriti disclosure feed appears, implement it here on the harvest_h1.py
shape (normalized record -> raw/intigriti/). Until then: gather Intigriti technique
detail manually from researcher profiles / their blog, and feed it in via
draft_patterns-style hand curation.

Usage: python3 research/reports/harvest_intigriti.py
Stdlib only.
"""
import sys


def main():
    print("harvest_intigriti: no reliable public disclosure feed/API exists "
          "(disclosure is approval-gated). Nothing to collect automatically — "
          "curate Intigriti write-ups manually from researcher profiles. See module docstring.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
