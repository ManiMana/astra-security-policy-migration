#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parse_windows_policy.py

Parser for Windows Server security policy exports.

Input examples:
  secedit /export /cfg C:\security_policy.inf
  auditpol /get /category:* /r /fo csv > C:\audit_policy.csv

The parser produces input.json for migrate.py.
It does not modify Windows or Astra Linux.
"""

import argparse
import csv
import json
import os
import re
from typing import Dict, Any, Tuple


def read_text(path: str) -> str:
    """Read Windows-exported text with several common encodings."""
    for enc in ("utf-16", "utf-8-sig", "cp1251", "utf-8"):
        try:
            with open(path, "r", encoding=enc) as f:
                return f.read()
        except UnicodeError:
            continue
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def parse_inf(path: str) -> Dict[str, Dict[str, str]]:
    """Parse secedit INF file into {section: {key: value}}."""
    text = read_text(path)
    sections: Dict[str, Dict[str, str]] = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        m = re.match(r"^\[(.+?)\]$", line)
        if m:
            current = m.group(1).strip()
            sections.setdefault(current, {})
            continue
        if current and "=" in line:
            key, value = line.split("=", 1)
            sections[current][key.strip()] = value.strip()
    return sections


def to_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip().strip('"'))
    except Exception:
        return default


def enabled_disabled(value: Any) -> str:
    return "Enabled" if to_int(value) else "Disabled"


def yes_no_bool(value: Any) -> bool:
    return bool(to_int(value))


def clean_name(value: str) -> str:
    return str(value).strip().strip('"')


def audit_value(value: Any) -> str:
    # secedit Event Audit values usually:
    # 0 = No Auditing, 1 = Success, 2 = Failure, 3 = Success and Failure
    mapping = {
        0: "No Auditing",
        1: "Success",
        2: "Failure",
        3: "Success and Failure",
    }
    return mapping.get(to_int(value), str(value))


def registry_value_to_int(value: str) -> int:
    # Examples:
    # 4,1
    # 1,"text"
    # 7,15
    if value is None:
        return 0
    s = str(value).strip()
    parts = s.split(",", 1)
    if len(parts) == 2:
        return to_int(parts[1])
    return to_int(s)


def registry_value_to_string(value: str) -> str:
    if value is None:
        return ""
    s = str(value).strip()
    parts = s.split(",", 1)
    if len(parts) == 2:
        return parts[1].strip().strip('"')
    return s.strip().strip('"')


def registry_lookup(registry: Dict[str, str], suffix: str):
    suffix_norm = suffix.lower()
    for key, value in registry.items():
        if key.lower().endswith(suffix_norm):
            return value
    return None


def parse_secedit_policy(inf_path: str) -> Dict[str, Any]:
    """Convert security_policy.inf into the project's input.json fields."""
    sections = parse_inf(inf_path)
    out: Dict[str, Any] = {}

    system = sections.get("System Access", {})
    event = sections.get("Event Audit", {})
    rights = sections.get("Privilege Rights", {})
    registry = sections.get("Registry Values", {})

    # Password policy
    if "PasswordHistorySize" in system:
        out["PasswordHistoryCount"] = to_int(system["PasswordHistorySize"])
    if "MaximumPasswordAge" in system:
        out["MaximumPasswordAgeDays"] = to_int(system["MaximumPasswordAge"])
    if "MinimumPasswordAge" in system:
        out["MinimumPasswordAgeDays"] = to_int(system["MinimumPasswordAge"])
    if "MinimumPasswordLength" in system:
        out["MinimumPasswordLength"] = to_int(system["MinimumPasswordLength"])
    if "PasswordComplexity" in system:
        out["PasswordComplexity"] = enabled_disabled(system["PasswordComplexity"])
    if "ClearTextPassword" in system:
        out["StoreReversibleEncryption"] = enabled_disabled(system["ClearTextPassword"])

    # Lockout policy
    if "LockoutBadCount" in system:
        out["LockoutThreshold"] = to_int(system["LockoutBadCount"])
    if "LockoutDuration" in system:
        out["LockoutDurationMinutes"] = to_int(system["LockoutDuration"])
    if "ResetLockoutCount" in system:
        out["ResetLockoutCounterMinutes"] = to_int(system["ResetLockoutCount"])

    # Account status / rename
    if "EnableAdminAccount" in system:
        out["AdministratorAccountStatus"] = enabled_disabled(system["EnableAdminAccount"])
    if "EnableGuestAccount" in system:
        out["GuestAccountStatus"] = enabled_disabled(system["EnableGuestAccount"])
    if "NewAdministratorName" in system:
        out["RenameAdminAccountTo"] = clean_name(system["NewAdministratorName"])
    if "NewGuestName" in system:
        out["RenameGuestAccountTo"] = clean_name(system["NewGuestName"])
    if "LSAAnonymousNameLookup" in system:
        out["NetworkAccessAnonymousSIDNameTranslation"] = enabled_disabled(system["LSAAnonymousNameLookup"])
    if "ForceLogoffWhenHourExpire" in system:
        out["NetworkForceLogoffWhenLogonHoursExpire"] = enabled_disabled(system["ForceLogoffWhenHourExpire"])

    # User rights assignment
    for key in [
        "SeInteractiveLogonRight",
        "SeDenyInteractiveLogonRight",
        "SeServiceLogonRight",
        "SeRemoteInteractiveLogonRight",
        "SeDenyRemoteInteractiveLogonRight",
        "SeShutdownPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeLoadDriverPrivilege",
        "SeDebugPrivilege",
        "SeSystemEnvironmentPrivilege",
        "SeChangeNotifyPrivilege",
        "SeAuditPrivilege",
        "SeCreateSymbolicLinkPrivilege",
        "SeCreateGlobalPrivilege",
        "SeCreatePagefilePrivilege",
        "SeIncreaseBasePriorityPrivilege",
        "SeIncreaseWorkingSetPrivilege",
        "SeNetworkLogonRight",
        "SeDenyNetworkLogonRight",
        "SeBatchLogonRight",
        "SeDenyBatchLogonRight",
        "SeTcbPrivilege",
        "SeMachineAccountPrivilege",
        "SeIncreaseQuotaPrivilege",
        "SeSystemtimePrivilege",
        "SeTimeZonePrivilege",
        "SeCreateTokenPrivilege",
        "SeCreatePermanentPrivilege",
        "SeEnableDelegationPrivilege",
        "SeRemoteShutdownPrivilege",
        "SeImpersonatePrivilege",
        "SeLockMemoryPrivilege",
        "SeSecurityPrivilege",
        "SeManageVolumePrivilege",
        "SeProfileSingleProcessPrivilege",
        "SeSystemProfilePrivilege",
        "SeUndockPrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeSyncAgentPrivilege",
        "SeTakeOwnershipPrivilege",
        "SeCreateNamedPipePrivilege",
        "SeRelabelPrivilege",
    ]:
        if key in rights:
            # Keep raw SID/group list: migration matrix can decide how to treat it.
            out[key] = clean_name(rights[key])

    # Basic audit policy
    for key in [
        "AuditSystemEvents",
        "AuditLogonEvents",
        "AuditObjectAccess",
        "AuditPrivilegeUse",
        "AuditPolicyChange",
        "AuditAccountManagement",
        "AuditProcessTracking",
        "AuditDSAccess",
        "AuditAccountLogon",
    ]:
        if key in event:
            target = {
                "AuditDSAccess": "AuditDirectoryServiceAccess",
                "AuditAccountLogon": "AuditAccountLogonEvents",
            }.get(key, key)
            out[target] = audit_value(event[key])

    # Security Options from registry values
    reg_map_bool = {
        r"\Control\Lsa\LimitBlankPasswordUse": "DenyBlankPasswords",
        r"\Control\Lsa\NoLMHash": "NetworkDoNotStoreLMHash",
        r"\Control\Lsa\RestrictAnonymousSAM": "NetworkAccessDoNotAllowAnonymousEnumSAM",
        r"\Services\LanManServer\Parameters\EnableSecuritySignature": "MicrosoftNetworkServerSignIfClientAgrees",
        r"\Services\LanManServer\Parameters\RequireSecuritySignature": "MicrosoftNetworkServerAlwaysSign",
        r"\Policies\System\DontDisplayLastUserName": "InteractiveLogonDoNotDisplayLastUserName",
        r"\Policies\System\DisableCAD": "InteractiveLogonNoCAD",
        r"\Policies\System\ShutdownWithoutLogon": "ShutdownWithoutLogon",
        r"\Policies\System\EnableLUA": "UACAllAdminsInAdminApprovalMode",
        r"\Policies\System\EnableInstallerDetection": "UACDetectApplicationInstallations",
        r"\Policies\System\PromptOnSecureDesktop": "UACSwitchToSecureDesktop",
        r"\Policies\System\EnableVirtualization": "UACVirtualizeFileRegistryWrites",
        r"\Policies\System\ValidateAdminCodeSignatures": "UACOnlyElevateSignedValidated",
    }
    reg_map_bool.update({
        r"\Services\LanManWorkstation\Parameters\EnableSecuritySignature": "MicrosoftNetworkClientSignIfServerAgrees",
        r"\Services\LanManWorkstation\Parameters\RequireSecuritySignature": "MicrosoftNetworkClientAlwaysSign",
        r"\Services\LanManWorkstation\Parameters\EnablePlainTextPassword": "MicrosoftNetworkClientSendUnencryptedPassword",
        r"\Control\Lsa\RestrictAnonymous": "NetworkAccessDoNotAllowAnonymousEnumSAMAndShares",
        r"\Control\Lsa\EveryoneIncludesAnonymous": "NetworkAccessEveryoneIncludesAnonymous",
        r"\Services\LanManServer\Parameters\RestrictNullSessAccess": "NetworkAccessRestrictAnonymousNamedPipesShares",
        r"\Policies\System\FilterAdministratorToken": "UACAdminApprovalModeForBuiltinAdmin",
        r"\Policies\System\EnableUIADesktopToggle": "UACAllowUIAccessWithoutSecureDesktop",
        r"\Policies\System\EnableSecureUIAPaths": "UACOnlyElevateUIAccessInSecureLocations",
        r"\Control\Session Manager\Memory Management\ClearPageFileAtShutdown": "ShutdownClearPageFile",
        r"\Control\Lsa\FIPSAlgorithmPolicy\Enabled": "SystemCryptographyUseFIPS",
        r"\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive": "SystemObjectsRequireCaseInsensitivity",
        r"\CurrentControlSet\Control\Session Manager\ProtectionMode": "SystemObjectsStrengthenDefaultPermissions",
    })

    for suffix, out_key in reg_map_bool.items():
        rv = registry_lookup(registry, suffix)
        if rv is not None:
            out[out_key] = enabled_disabled(registry_value_to_int(rv))

    rv = registry_lookup(registry, r"\Control\Lsa\LmCompatibilityLevel")
    if rv is not None:
        levels = {
            0: "Send LM and NTLM responses",
            1: "Send LM and NTLM - use NTLMv2 session security if negotiated",
            2: "Send NTLM response only",
            3: "Send NTLMv2 response only",
            4: "Send NTLMv2 response only. Refuse LM",
            5: "Send NTLMv2 response only. Refuse LM and NTLM",
        }
        out["NetworkLanManagerAuthLevel"] = levels.get(registry_value_to_int(rv), str(registry_value_to_int(rv)))

    rv = registry_lookup(registry, r"\Policies\System\LegalNoticeCaption")
    if rv is not None:
        out["InteractiveLogonMessageTitle"] = registry_value_to_string(rv)

    rv = registry_lookup(registry, r"\Policies\System\LegalNoticeText")
    if rv is not None:
        out["InteractiveLogonMessageText"] = registry_value_to_string(rv)

    rv = registry_lookup(registry, r"\Policies\System\CachedLogonsCount")
    if rv is not None:
        out["InteractiveLogonPreviousLogonsToCache"] = to_int(registry_value_to_string(rv), default=0)

    rv = registry_lookup(registry, r"\Policies\System\ConsentPromptBehaviorAdmin")
    if rv is not None:
        out["UACElevationPromptBehaviorAdmin"] = str(registry_value_to_int(rv))

    rv = registry_lookup(registry, r"\Policies\System\ConsentPromptBehaviorUser")
    if rv is not None:
        out["UACElevationPromptBehaviorUser"] = str(registry_value_to_int(rv))

    # Additional integer/string security options
    extra_ints = {
        r"\Services\LanManServer\Parameters\AutoDisconnect": "MicrosoftNetworkServerIdleTimeoutMinutes",
        r"\Control\Lsa\MSV1_0\NTLMMinClientSec": "NetworkMinSessionSecurityClient",
        r"\Control\Lsa\MSV1_0\NTLMMinServerSec": "NetworkMinSessionSecurityServer",
        r"\Policies\System\ConsentPromptBehaviorAdmin": "UACElevationPromptBehaviorAdmin",
        r"\Policies\System\ConsentPromptBehaviorUser": "UACElevationPromptBehaviorUser",
        r"\Policies\System\PromptOnSecureDesktop": "UACSwitchToSecureDesktop",
        r"\Policies\System\PasswordExpiryWarning": "PromptChangePasswordBeforeExpirationDays",
    }
    for suffix, out_key in extra_ints.items():
        rv = registry_lookup(registry, suffix)
        if rv is not None:
            out[out_key] = registry_value_to_int(rv)

    extra_strings = {
        r"\Services\LanManServer\Parameters\NullSessionPipes": "NetworkAccessNullSessionPipes",
        r"\Services\LanManServer\Parameters\NullSessionShares": "NetworkAccessNullSessionShares",
        r"\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine": "NetworkAccessAllowedExactPaths",
        r"\Control\SecurePipeServers\Winreg\AllowedPaths\Machine": "NetworkAccessAllowedPaths",
        r"\Control\Session Manager\SubSystems\Optional": "SystemSettingsOptionalSubsystems",
    }
    for suffix, out_key in extra_strings.items():
        rv = registry_lookup(registry, suffix)
        if rv is not None:
            out[out_key] = registry_value_to_string(rv)

    return out


def parse_auditpol_csv(path: str) -> Dict[str, Any]:
    """Parse auditpol CSV output into advanced audit fields."""
    text = read_text(path)
    out: Dict[str, Any] = {}

    # Try CSV first. auditpol /r /fo csv usually has headers like:
    # Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
    try:
        rows = list(csv.DictReader(text.splitlines()))
    except Exception:
        rows = []

    if rows and rows[0]:
        for row in rows:
            subcat = (row.get("Subcategory") or row.get("Подкатегория") or "").lower()
            setting = (row.get("Inclusion Setting") or row.get("Параметр включения") or row.get("Setting") or "").strip()
            if not setting:
                continue
            if "logon" in subcat or "logoff" in subcat or "вход" in subcat:
                out["AdvAuditLogonLogoff"] = setting
            elif "account management" in subcat or "управление учет" in subcat:
                out["AdvAuditAccountManagement"] = setting
            elif "account logon" in subcat:
                out["AdvAuditAccountLogon"] = setting
            elif "object access" in subcat or "доступ к объект" in subcat:
                out["AdvAuditObjectAccess"] = setting
            elif "policy change" in subcat or "изменение полит" in subcat:
                out["AdvAuditPolicyChange"] = setting
            elif "privilege use" in subcat or "использование привил" in subcat:
                out["AdvAuditPrivilegeUse"] = setting
            elif "system" in subcat or "система" in subcat:
                out["AdvAuditSystem"] = setting
            elif "detailed tracking" in subcat or "подробн" in subcat:
                out["AdvAuditDetailedTracking"] = setting
        return out

    # Fallback for simple text output: scan category names and lines.
    lower = text.lower()
    def has_any(*words):
        return any(w.lower() in lower for w in words)

    if has_any("logon/logoff", "вход/выход"):
        out["AdvAuditLogonLogoff"] = "Detected in auditpol output"
    if has_any("account logon", "вход учетной"):
        out["AdvAuditAccountLogon"] = "Detected in auditpol output"
    if has_any("account management", "управление учетными"):
        out["AdvAuditAccountManagement"] = "Detected in auditpol output"
    if has_any("object access", "доступ к объектам"):
        out["AdvAuditObjectAccess"] = "Detected in auditpol output"
    if has_any("policy change", "изменение политики"):
        out["AdvAuditPolicyChange"] = "Detected in auditpol output"
    if has_any("privilege use", "использование привилегий"):
        out["AdvAuditPrivilegeUse"] = "Detected in auditpol output"
    if has_any("system", "система"):
        out["AdvAuditSystem"] = "Detected in auditpol output"

    # Map common English/Russian subcategory keywords when TXT export is used.
    subcategory_keywords = {
        "AdvAuditCredentialValidation": ["credential validation", "проверка учетных данных"],
        "AdvAuditKerberosAuthenticationService": ["kerberos authentication service", "служба проверки подлинности kerberos"],
        "AdvAuditKerberosServiceTicketOperations": ["kerberos service ticket", "операции с билетами службы kerberos"],
        "AdvAuditUserAccountManagement": ["user account management", "управление учетными записями пользователей"],
        "AdvAuditSecurityGroupManagement": ["security group management", "управление группами безопасности"],
        "AdvAuditComputerAccountManagement": ["computer account management", "управление учетными записями компьютеров"],
        "AdvAuditProcessCreation": ["process creation", "создание процесса"],
        "AdvAuditProcessTermination": ["process termination", "завершение процесса"],
        "AdvAuditLogon": [" logon", "вход в систему"],
        "AdvAuditLogoff": [" logoff", "выход из системы"],
        "AdvAuditAccountLockout": ["account lockout", "блокировка учетной записи"],
        "AdvAuditSpecialLogon": ["special logon", "специальный вход"],
        "AdvAuditFileSystem": ["file system", "файловая система"],
        "AdvAuditRegistry": ["registry", "реестр"],
        "AdvAuditFileShare": ["file share", "общий файловый ресурс"],
        "AdvAuditSAM": ["sam"],
        "AdvAuditRemovableStorage": ["removable storage", "съемный носитель"],
        "AdvAuditAuditPolicyChange": ["audit policy change", "изменение политики аудита"],
        "AdvAuditAuthenticationPolicyChange": ["authentication policy change", "изменение политики проверки подлинности"],
        "AdvAuditAuthorizationPolicyChange": ["authorization policy change", "изменение политики авторизации"],
        "AdvAuditSensitivePrivilegeUse": ["sensitive privilege", "использование важных прав"],
        "AdvAuditNonSensitivePrivilegeUse": ["non sensitive privilege", "использование неважных прав"],
        "AdvAuditSecurityStateChange": ["security state change", "изменение состояния безопасности"],
        "AdvAuditSecuritySystemExtension": ["security system extension", "расширение системы безопасности"],
        "AdvAuditSystemIntegrity": ["system integrity", "целостность системы"],
        "AdvAuditIPsecDriver": ["ipsec driver", "драйвер ipsec"],
    }
    for field, words in subcategory_keywords.items():
        if any(w.lower() in lower for w in words):
            # TXT output does not always preserve machine-readable settings; keep detected marker.
            out.setdefault(field, "Detected in auditpol TXT output")
    return out


def merge_inputs(base: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base or {})
    for k, v in update.items():
        if v not in (None, "", []):
            merged[k] = v
    return merged


def main():
    ap = argparse.ArgumentParser(description="Parse Windows security policy export into input.json")
    ap.add_argument("--secedit", help="Path to security_policy.inf exported by secedit")
    ap.add_argument("--auditpol", help="Path to auditpol output (.csv preferred, .txt supported)")
    ap.add_argument("--base", help="Optional existing input.json to preserve fields not present in export")
    ap.add_argument("--out", default="input_from_windows.json", help="Output input.json path")
    args = ap.parse_args()

    result: Dict[str, Any] = {}
    if args.base and os.path.exists(args.base):
        with open(args.base, "r", encoding="utf-8") as f:
            result = json.load(f)

    parsed: Dict[str, Any] = {}
    if args.secedit:
        parsed = merge_inputs(parsed, parse_secedit_policy(args.secedit))
    if args.auditpol:
        parsed = merge_inputs(parsed, parse_auditpol_csv(args.auditpol))

    result = merge_inputs(result, parsed)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"OK: wrote {args.out}")
    print(f"Fields parsed/available: {len(result)}")


if __name__ == "__main__":
    main()
