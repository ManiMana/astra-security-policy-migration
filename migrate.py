#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse, json, os, re, shutil, subprocess, sys
from datetime import datetime

def load_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def mkdirp(p):
    os.makedirs(p, exist_ok=True)

def _cmd_ok(cmd):
    try:
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except Exception:
        return False

def _so_exists(name):
    for d in ('/lib/security','/usr/lib/security','/lib64/security','/usr/lib64/security'):
        if os.path.exists(os.path.join(d, name)):
            return True
    return False

def detect_caps():
    return {
        'auditd': _cmd_ok(['systemctl','is-active','--quiet','auditd']),
        'ausearch': shutil.which('ausearch') is not None,
        'pam_faillock': _so_exists('pam_faillock.so'),
        'pam_tally2': _so_exists('pam_tally2.so'),
        'faillog': shutil.which('faillog') is not None or os.path.exists('/var/log/faillog'),
        'pwquality_conf': os.path.exists('/etc/security/pwquality.conf'),
        'polkit': os.path.isdir('/etc/polkit-1'),
        'pam_access_conf': os.path.exists('/etc/security/access.conf'),
        'pam_issue': os.path.exists('/etc/issue'),
        'pam_lastlog': True,
    }

_var_pattern = re.compile(r"\$\{([^}]+)\}")

def _resolve_field(expr, src):
    expr = expr.strip()
    if '*' in expr:
        field, mul = expr.split('*',1)
        return int(src.get(field.strip(),0) or 0) * int(mul.strip())
    return src.get(expr, '')

def substitute(value, src):
    if not isinstance(value, str):
        return value
    return _var_pattern.sub(lambda m: str(_resolve_field(m.group(1), src)), value)

def match_when(when, src, caps):
    if not when:
        return True
    if 'capability' in when:
        return bool(caps.get(when['capability'], False)) == bool(when.get('equals', True))
    if 'all' in when:
        return all(match_when(x, src, caps) for x in when['all'])
    if 'any' in when:
        return any(match_when(x, src, caps) for x in when['any'])
    for key, cond in when.items():
        val = src.get(key)
        if isinstance(cond, dict):
            if 'exists' in cond:
                exists = key in src and src.get(key) not in (None, '')
                if exists != bool(cond['exists']):
                    return False
            if 'equals' in cond and val != cond['equals']:
                return False
            if 'ne' in cond and val == cond['ne']:
                return False
            if 'gt' in cond and not ((val or 0) > cond['gt']):
                return False
            if 'gte' in cond and not ((val or 0) >= cond['gte']):
                return False
            if 'lt' in cond and not ((val or 0) < cond['lt']):
                return False
            if 'in' in cond and val not in cond['in']:
                return False
            if 'contains_any' in cond:
                current = val or []
                if not any(x in current for x in cond['contains_any']):
                    return False
        else:
            if val != cond:
                return False
    return True

def sanitize_target(p):
    return p.strip('/').replace('/', '_').replace('.', '_')

def write_patch(outdir, target, lines):
    path = os.path.join(outdir, 'patches', sanitize_target(target) + '.patch')
    mkdirp(os.path.dirname(path))
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines).rstrip() + '\n')
    return path

def emit_file_patch(outdir, act, src):
    lines = [f"# Target: {act['target']}"]
    if 'comment' in act:
        lines.append(f"# {act['comment']}")
    lines.append('')
    fmt = act.get('format','key_value')
    if fmt in ('key_value','ini_like'):
        for k,v in act.get('set',{}).items():
            lines.append(f"{k} = {substitute(v, src)}")
    elif fmt in ('raw_text','raw_text_append'):
        lines.append(substitute(act.get('content',''), src).rstrip('\n'))
    else:
        lines.append('# unsupported format')
    return {'type':'file_patch','target':act['target'],'patch':write_patch(outdir, act['target'], lines)}

def emit_file_replace(outdir, act, src):
    lines = [f"# Target: {act['target']}"]
    if 'comment' in act:
        lines.append(f"# {act['comment']}")
    lines += ['', f"FIND: {substitute(act.get('find',''), src)}", f"REPLACE_WITH: {substitute(act.get('replace',''), src)}"]
    return {'type':'file_replace','target':act['target'],'patch':write_patch(outdir, act['target'], lines)}

def emit_pam_edit(outdir, act, src):
    lines = [f"# Target: {act['target']}"]
    if 'comment' in act:
        lines.append(f"# {act['comment']}")
    lines.append('')
    for line in act.get('ensure_lines',[]):
        lines.append(substitute(line, src))
    return {'type':'pam_edit','target':act['target'],'patch':write_patch(outdir, act['target'], lines)}

def emit_shell_template(outdir, act, src):
    lines = ["#!/bin/sh", f"# Target intent: {act.get('target','system')}" ]
    if 'comment' in act:
        lines.append(f"# {act['comment']}")
    for cmd in act.get('commands',[]):
        lines.append(substitute(cmd, src))
    return {'type':'shell_template','target':act.get('target','system'),'patch':write_patch(outdir, act.get('target','system'), lines)}

def iter_source_fields(pol):
    src = pol.get('source', {})
    fields = src.get('fields')
    if isinstance(fields, list):
        return fields
    windows = src.get('windows')
    if isinstance(windows, list):
        return windows
    return []

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', default='input.json', help='Input JSON with Windows policy values (default: input.json)')
    ap.add_argument('--matrix', default='matrix.json', help='Policy matrix JSON (default: matrix.json)')
    ap.add_argument('--out', default='out', help='Output directory (default: out)')
    ap.add_argument('--no-detect', action='store_true')
    args = ap.parse_args()

    src = load_json(args.input)
    matrix = load_json(args.matrix)
    caps = {} if args.no_detect else detect_caps()
    mkdirp(args.out)
    mkdirp(os.path.join(args.out,'patches'))

    report = ["# Migration report (PoC)","",f"Generated at: {datetime.now().isoformat(timespec='seconds')}",f"Source OS: {matrix.get('meta',{}).get('source_os','')}",f"Target OS: {matrix.get('meta',{}).get('target_os','')}",f"Policies in matrix: {len(matrix.get('policies',[]))}",f"Capability detection: {'disabled' if args.no_detect else 'enabled'}",'', '## Policy results','']
    actions_emitted = 0
    notes_emitted = 0
    matched_policies = 0
    unmatched_policies = 0
    for pol in matrix.get('policies', []):
        pid = pol.get('id','unknown')
        title = pol.get('title', pid)
        fields = iter_source_fields(pol)
        src_subset = {k: src.get(k) for k in fields}
        report.append(f"### {title} ({pid})")
        matched = False
        for rule in pol.get('mapping', []):
            if match_when(rule.get('when', {}), src_subset or src, caps):
                matched = True
                for act in rule.get('actions', []):
                    typ = act.get('type')
                    if typ == 'file_patch':
                        res = emit_file_patch(args.out, act, src)
                        report.append(f"- Action: file_patch")
                        report.append(f"  Target: `{act['target']}`")
                        report.append(f"  Patch: `{os.path.relpath(res['patch'], args.out)}`")
                        actions_emitted += 1
                    elif typ == 'file_replace':
                        res = emit_file_replace(args.out, act, src)
                        report.append(f"- Action: file_replace")
                        report.append(f"  Target: `{act['target']}`")
                        report.append(f"  Patch: `{os.path.relpath(res['patch'], args.out)}`")
                        actions_emitted += 1
                    elif typ == 'pam_edit':
                        res = emit_pam_edit(args.out, act, src)
                        report.append(f"- Action: pam_edit")
                        report.append(f"  Target: `{act['target']}`")
                        report.append(f"  Patch: `{os.path.relpath(res['patch'], args.out)}`")
                        actions_emitted += 1
                    elif typ == 'shell_template':
                        res = emit_shell_template(args.out, act, src)
                        report.append(f"- Action: shell_template")
                        report.append(f"  Target: `{act.get('target','system')}`")
                        report.append(f"  Patch: `{os.path.relpath(res['patch'], args.out)}`")
                        actions_emitted += 1
                    elif typ == 'note':
                        sev = act.get('severity','info').upper()
                        report.append(f"- {sev}: {substitute(act.get('message',''), src)}")
                        notes_emitted += 1
        if matched:
            matched_policies += 1
        if not matched:
            unmatched_policies += 1
            report.append('- No matching rule.')
        report.append('')
    summary = [
        "# Summary",
        "",
        f"Total policies in matrix: {len(matrix.get('policies', []))}",
        f"Policies with matched rules: {matched_policies}",
        f"Policies without matched rules: {unmatched_policies}",
        f"Generated patch/template actions: {actions_emitted}",
        f"Generated informational/warning notes: {notes_emitted}",
        "",
    ]
    # Insert summary after header block and before detailed policy results if possible.
    try:
        idx = report.index("## Policy results")
        report[idx:idx] = summary
    except ValueError:
        report = summary + report

    with open(os.path.join(args.out,'report.md'),'w',encoding='utf-8') as f:
        f.write('\n'.join(report))
    print(f"OK: wrote {os.path.join(args.out,'report.md')} and {actions_emitted} patch file(s)")

if __name__ == '__main__':
    sys.exit(main())
