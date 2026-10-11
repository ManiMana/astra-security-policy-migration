#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_pipeline.py

Full demo pipeline:
Windows export files -> input_from_windows.json -> migration report/patches.
Optional:
Astra export -> astra_observed.json.

Example:
python run_pipeline.py --secedit exports/security_policy.inf --auditpol exports/audit_policy.txt --astra-export astra_export.tar.gz --out out --no-detect
"""

import argparse
import subprocess
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--secedit", required=True, help="Path to secedit INF export")
    ap.add_argument("--auditpol", help="Path to auditpol CSV/TXT export")
    ap.add_argument("--astra-export", help="Path to Astra export directory or astra_export.tar.gz")
    ap.add_argument("--matrix", default="matrix.json")
    ap.add_argument("--base", default="input.json", help="Base input.json with fields not exported by Windows")
    ap.add_argument("--generated-input", default="input_from_windows.json")
    ap.add_argument("--astra-observed", default="astra_observed.json")
    ap.add_argument("--out", default="out")
    ap.add_argument("--no-detect", action="store_true")
    args = ap.parse_args()

    parse_cmd = [
        sys.executable, "parse_windows_policy.py",
        "--secedit", args.secedit,
        "--base", args.base,
        "--out", args.generated_input,
    ]
    if args.auditpol:
        parse_cmd += ["--auditpol", args.auditpol]

    print("Step 1: Parsing Windows export")
    subprocess.check_call(parse_cmd)

    if args.astra_export:
        print("Step 2: Parsing Astra export")
        subprocess.check_call([
            sys.executable, "parse_astra_export.py",
            "--input", args.astra_export,
            "--out", args.astra_observed,
        ])
        print("Astra observed data saved to", args.astra_observed)

    print("Step 3: Running migration engine")
    migrate_cmd = [
        sys.executable, "migrate.py",
        "--input", args.generated_input,
        "--matrix", args.matrix,
        "--out", args.out,
    ]
    if args.no_detect:
        migrate_cmd.append("--no-detect")

    subprocess.check_call(migrate_cmd)
    print("Done")


if __name__ == "__main__":
    main()
