#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parse_astra_export.py

Reads exported Astra Linux configuration files from a directory or tar.gz archive
and produces astra_observed.json with detected mechanisms.
It does not modify the system.
"""
import argparse, json, os, re, tarfile, tempfile, shutil
from pathlib import Path

def read(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""

def parse_key_values(text, keys):
    out = {}
    for key in keys:
        m = re.search(r"(?m)^\s*" + re.escape(key) + r"\s+(.+?)\s*$", text)
        if m:
            out[key] = m.group(1).strip()
        m2 = re.search(r"(?m)^\s*" + re.escape(key.lower()) + r"\s*=\s*(.+?)\s*$", text)
        if m2:
            out[key] = m2.group(1).strip()
    return out

def parse_astra_dir(root):
    root = Path(root)
    out = {}
    login_defs = read(root/"login.defs.txt")
    pwquality = read(root/"pwquality.conf.txt")
    common_auth = read(root/"common-auth.txt")
    common_account = read(root/"common-account.txt")
    common_password = read(root/"common-password.txt")
    login_pam = read(root/"login_pam.txt")
    access_conf = read(root/"access.conf.txt")

    out.update({f"AstraLogin_{k}": v for k,v in parse_key_values(login_defs, [
        "PASS_MAX_DAYS","PASS_MIN_DAYS","PASS_WARN_AGE","LOGIN_RETRIES","LOGIN_TIMEOUT","UMASK","ENCRYPT_METHOD","PREVENT_NO_AUTH"
    ]).items()})
    out.update({f"AstraPwquality_{k}": v for k,v in parse_key_values(pwquality, [
        "minlen","dcredit","ucredit","lcredit","ocredit","minclass","difok","maxrepeat","maxclassrepeat","retry"
    ]).items()})

    all_pam = "\n".join([common_auth, common_account, common_password, login_pam])
    out["AstraHasPamFaillock"] = "pam_faillock.so" in all_pam
    out["AstraHasPamPwquality"] = "pam_pwquality.so" in all_pam
    out["AstraHasPamAccess"] = "pam_access.so" in all_pam
    out["AstraHasPamIssue"] = "pam_issue.so" in all_pam
    out["AstraHasPamLastlog"] = "pam_lastlog.so" in all_pam
    out["AstraHasParsecPam"] = "pam_parsec" in all_pam
    out["AstraHasNullok"] = "nullok" in all_pam
    out["AstraAccessConfNonCommentRules"] = [ln.strip() for ln in access_conf.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Astra export directory or .tar.gz archive")
    ap.add_argument("--out", default="astra_observed.json")
    args = ap.parse_args()
    temp = None
    src = args.input
    if tarfile.is_tarfile(src):
        temp = tempfile.mkdtemp(prefix="astra_export_")
        with tarfile.open(src, "r:*") as t:
            t.extractall(temp)
        # archive usually contains astra_export/
        root = Path(temp) / "astra_export"
    else:
        root = Path(src)
    data = parse_astra_dir(root)
    Path(args.out).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    if temp:
        shutil.rmtree(temp, ignore_errors=True)
    print(f"OK: wrote {args.out} with {len(data)} observed Astra facts")

if __name__ == "__main__":
    main()
