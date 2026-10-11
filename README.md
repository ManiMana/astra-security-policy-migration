# Astra Migration MVP v0.7

Prototype for migration analysis of Windows Server security policies to Astra Linux.

## What changed in v0.7

Earlier versions used manually prepared `input.json`.
This version adds an automatic Windows export parser:

`Windows export -> parse_windows_policy.py -> input_from_windows.json -> migrate.py -> report/patches`

This means the 96-policy matrix is not wasted: the parser simply fills values for the already existing matrix.

## Export policies on Windows Server

Open Command Prompt or PowerShell as Administrator:

```cmd
secedit /export /cfg C:\security_policy.inf
auditpol /get /category:* /r /fo csv > C:\audit_policy.csv
```

If CSV export is not available, use:

```cmd
auditpol /get /category:* > C:\audit_policy.txt
```

Copy these files to the project folder, for example into `exports\`.

## Parse Windows export only

```cmd
python parse_windows_policy.py --secedit exports\security_policy.inf --auditpol exports\audit_policy.csv --base input.json --out input_from_windows.json
```

## Run migration after parsing

```cmd
python migrate.py --input input_from_windows.json --matrix matrix.json --out out --no-detect
```

## Full pipeline

```cmd
python run_pipeline.py --secedit exports\security_policy.inf --auditpol exports\audit_policy.csv --out out --no-detect
```

## Usual demo command

You can still run the old way:

```cmd
python migrate.py --input input.json --matrix matrix.json --out out --no-detect
```

Or simply:

```cmd
python migrate.py
```

In that case defaults are used: `input.json`, `matrix.json`, `out`.

## Outputs

- `out/report.md` — migration report
- `out/patches/` — generated configuration patches/templates
- `input_from_windows.json` — parsed Windows policy values


## What changed in v0.8

- Matrix expanded from 96 to 200 policy entries.
- Added additional Windows user rights, security options, network security settings, UAC settings, device policies, firewall/IPsec placeholders and advanced audit subcategories.
- Added `parse_astra_export.py` for reading Astra Linux exported configuration files and detecting PAM/login.defs/pwquality/access.conf facts.
- Added support for TXT auditpol output when CSV export is not available.
- Important: 200 entries do not mean 200 safe automatic changes. The tool separates full automation, templates with review and analytical/manual mappings.

## Parse Astra export

```cmd
python parse_astra_export.py --input astra_export.tar.gz --out astra_observed.json
```

## Recommended final demo

```cmd
python parse_windows_policy.py --secedit exports\security_policy.inf --auditpol exports\audit_policy.txt --base input.json --out input_from_windows.json
python migrate.py --input input_from_windows.json --matrix matrix.json --out out --no-detect
```

If Windows export files are not available during demo, use:

```cmd
python migrate.py --input input_from_windows.json --matrix matrix.json --out out --no-detect
```
