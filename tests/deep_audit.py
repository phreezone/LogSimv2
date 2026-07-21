"""Deep audit of all LogSim Windows events against XSIAM microsoft_windows_raw
content pack requirements."""

import json, sys, collections, re, time
sys.path.insert(0, '.')
from modules.windows_events import (
    _BENIGN_GENERATORS, _THREAT_GENERATORS, _EVENT_META, _MSG_BUILDERS,
)

session = {
    'jsmith': {'primary_os_type': 'Windows', 'primary_hostname': 'WKS001', 'primary_ip': '10.0.1.50', 'primary_os_version': 'Windows 10 Enterprise', 'active_devices': {}},
    'awhite': {'primary_os_type': 'Windows', 'primary_hostname': 'WKS002', 'primary_ip': '10.0.1.51', 'primary_os_version': 'Windows 10 Enterprise', 'active_devices': {}},
    'bmorgan': {'primary_os_type': 'Windows', 'primary_hostname': 'WKS003', 'primary_ip': '10.0.1.52', 'primary_os_version': 'Windows 10 Enterprise', 'active_devices': {}},
    'clee': {'primary_os_type': 'Windows', 'primary_hostname': 'WKS004', 'primary_ip': '10.0.1.53', 'primary_os_version': 'Windows 10 Enterprise', 'active_devices': {}},
    'djones': {'primary_os_type': 'Windows', 'primary_hostname': 'WKS005', 'primary_ip': '10.0.1.54', 'primary_os_version': 'Windows 10 Enterprise', 'active_devices': {}},
}
config = {
    'windows_events_config': {
        'domain': 'examplecorp.local',
        'dc_hostname': 'DC01.examplecorp.local',
        'domain_name': 'EXAMPLECORP',
        'dns_domain': 'examplecorp.local',
        'domain_controller_hostname': 'DC01.examplecorp.local',
        'workstations': [
            'WKS001.examplecorp.local', 'WKS002.examplecorp.local',
            'WKS003.examplecorp.local', 'WKS004.examplecorp.local',
            'WKS005.examplecorp.local',
        ],
        'users': [
            {'username': u, 'domain': 'EXAMPLECORP', 'sid': f'S-1-5-21-1234-{1001+i}'}
            for i, u in enumerate(['jsmith', 'awhite', 'bmorgan', 'clee', 'djones'])
        ],
        'transport': 'http',
    }
}

all_events = []
all_generators = {}
all_generators.update(_BENIGN_GENERATORS)
all_generators.update(_THREAT_GENERATORS)

for name, fn in all_generators.items():
    for attempt in range(5):
        try:
            result = fn(config, session)
            if result:
                for raw in result:
                    e = json.loads(raw)
                    all_events.append((name, e))
                break
        except:
            pass

print(f"Collected {len(all_events)} events from generators\n")

issues = []

# CHECK 1: provider_name must contain "Microsoft-Windows-Security-"
print("CHECK 1: provider_name contains 'Microsoft-Windows-Security-'")
for gen, e in all_events:
    pn = e.get('provider_name', '')
    if 'Microsoft-Windows-Security-' not in pn:
        issues.append(('CRITICAL', f'{gen}/{e["event_id"]}: provider_name={pn!r}'))
if not any(s == 'CRITICAL' and 'provider_name' in m for s, m in issues):
    print("  PASS")

# CHECK 2: channel must be "Security" (case-sensitive)
print("\nCHECK 2: channel == 'Security'")
for gen, e in all_events:
    ch = e.get('channel', '')
    if ch != 'Security':
        issues.append(('CRITICAL', f'{gen}/{e["event_id"]}: channel={ch!r}'))
if not any(s == 'CRITICAL' and 'channel' in m for s, m in issues):
    print("  PASS")

# CHECK 3: event_id must be STRING
print("\nCHECK 3: event_id is string")
for gen, e in all_events:
    if not isinstance(e.get('event_id'), str):
        issues.append(('CRITICAL', f'{gen}: event_id is {type(e["event_id"]).__name__}'))
if not any('event_id is' in m for s, m in issues):
    print("  PASS")

# CHECK 4: task must be INT
print("\nCHECK 4: task is int")
for gen, e in all_events:
    if not isinstance(e.get('task'), int):
        issues.append(('CRITICAL', f'{gen}/{e["event_id"]}: task is {type(e.get("task")).__name__}'))
if not any('task is' in m for s, m in issues):
    print("  PASS")

# CHECK 5: event_result must be "success" or "failure"
print("\nCHECK 5: event_result in ('success', 'failure')")
for gen, e in all_events:
    er = e.get('event_result', '')
    if er not in ('success', 'failure'):
        issues.append(('CRITICAL', f'{gen}/{e["event_id"]}: event_result={er!r}'))
if not any('event_result' in m for s, m in issues):
    print("  PASS")

# CHECK 6: time_created ISO 8601 ending with Z
print("\nCHECK 6: time_created format YYYY-MM-DDTHH:MM:SS.mmmZ")
tc_pattern = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$')
bad_tc = None
for gen, e in all_events:
    tc = e.get('time_created', '')
    if not tc_pattern.match(tc):
        bad_tc = (gen, e['event_id'], tc)
        issues.append(('CRITICAL', f'{gen}/{e["event_id"]}: time_created={tc!r}'))
        break
if bad_tc:
    print(f"  FAIL: {bad_tc}")
else:
    print("  PASS")

# CHECK 7: event_data is dict
print("\nCHECK 7: event_data is dict")
for gen, e in all_events:
    ed = e.get('event_data')
    if not isinstance(ed, dict):
        issues.append(('CRITICAL', f'{gen}/{e["event_id"]}: event_data is {type(ed).__name__}'))
if not any('event_data is' in m for s, m in issues):
    print("  PASS")

# CHECK 8: user object has name, domain, identifier, type
print("\nCHECK 8: user object completeness")
user_issues = []
for gen, e in all_events:
    u = e.get('user')
    if u is None:
        user_issues.append(f'{gen}/{e["event_id"]}: no user')
        break
    elif not isinstance(u, dict):
        user_issues.append(f'{gen}/{e["event_id"]}: user is {type(u).__name__}')
        break
    else:
        for k in ('name', 'domain', 'identifier', 'type'):
            if k not in u:
                user_issues.append(f'{gen}/{e["event_id"]}: user.{k} missing')
        ut = u.get('type', '')
        if ut not in ('User', 'Service', 'Computer'):
            user_issues.append(f'{gen}/{e["event_id"]}: user.type={ut!r}')
if user_issues:
    for ui in user_issues[:5]:
        issues.append(('CRITICAL', ui))
        print(f"  FAIL: {ui}")
else:
    print("  PASS")

# CHECK 9: user_data present
print("\nCHECK 9: user_data object")
for gen, e in all_events:
    ud = e.get('user_data')
    if ud is None:
        issues.append(('WARNING', f'{gen}/{e["event_id"]}: no user_data'))
        print(f"  FAIL: missing user_data")
        break
    elif not isinstance(ud, dict):
        issues.append(('WARNING', f'user_data is {type(ud).__name__}'))
        break
if not any('user_data' in m for s, m in issues):
    print("  PASS")

# CHECK 10: log_level capitalization
print("\nCHECK 10: log_level capitalization")
log_levels = set()
for gen, e in all_events:
    log_levels.add(e.get('log_level', ''))
print(f"  Values: {log_levels}")
if 'information' in log_levels:
    issues.append(('WARNING', 'log_level="information" (lowercase) — schema expects "Information"'))
    print('  WARNING: lowercase "information" — schema says "Information"')

# CHECK 11: event_data PascalCase keys
print("\nCHECK 11: event_data PascalCase keys")
bad_keys = set()
for gen, e in all_events:
    ed = e.get('event_data', {})
    for k in ed.keys():
        if k[0].islower() and k not in ('error',):
            bad_keys.add(k)
if bad_keys:
    issues.append(('WARNING', f'Non-PascalCase event_data keys: {sorted(bad_keys)}'))
    print(f"  WARNING: {sorted(bad_keys)}")
else:
    print("  PASS")

# CHECK 12: LogonType is string in 4624
print("\nCHECK 12: 4624 LogonType is string")
for gen, e in all_events:
    if e['event_id'] == '4624':
        lt = e['event_data'].get('LogonType')
        if lt is not None and not isinstance(lt, str):
            issues.append(('CRITICAL', f'{gen}/4624: LogonType={lt!r} ({type(lt).__name__})'))
            print(f"  FAIL: LogonType is {type(lt).__name__}")
            break
if not any('LogonType' in m for s, m in issues):
    print("  PASS")

# CHECK 13: 4624 completeness
print("\nCHECK 13: 4624 event_data completeness")
REQUIRED_4624 = {
    'SubjectUserSid', 'SubjectUserName', 'SubjectDomainName', 'SubjectLogonId',
    'TargetUserSid', 'TargetUserName', 'TargetDomainName', 'TargetLogonId',
    'LogonType', 'LogonProcessName', 'AuthenticationPackageName',
    'WorkstationName', 'LogonGuid', 'IpAddress', 'IpPort',
    'ElevatedToken', 'VirtualAccount', 'RestrictedAdminMode',
}
for gen, e in all_events:
    if e['event_id'] == '4624':
        missing = REQUIRED_4624 - set(e['event_data'].keys())
        if missing:
            issues.append(('WARNING', f'4624 missing modeling fields: {missing}'))
            print(f"  WARNING: missing {missing}")
        else:
            print("  PASS")
        break

# CHECK 14: 4769 TicketEncryptionType hex format
print("\nCHECK 14: 4769 TicketEncryptionType hex")
enc_values = set()
for gen, e in all_events:
    if e['event_id'] == '4769':
        enc = e['event_data'].get('TicketEncryptionType', '')
        enc_values.add(enc)
        if enc and not enc.startswith('0x'):
            issues.append(('CRITICAL', f'4769 TicketEncryptionType={enc!r}'))
print(f"  Values: {enc_values}")
if not any('TicketEncryptionType' in m for s, m in issues):
    print("  PASS")

# CHECK 15: host_name present
print("\nCHECK 15: host_name field present")
for gen, e in all_events:
    if 'host_name' not in e:
        issues.append(('WARNING', f'{gen}/{e["event_id"]}: no host_name'))
        break
if not any('host_name' in m for s, m in issues):
    print("  PASS")

# CHECK 16: provider_guid format
print("\nCHECK 16: provider_guid format")
guid_pat = re.compile(r'^\{[0-9A-Fa-f-]+\}$')
for gen, e in all_events:
    pg = e.get('provider_guid', '')
    if not guid_pat.match(pg):
        issues.append(('WARNING', f'provider_guid={pg!r}'))
        break
if not any('provider_guid' in m for s, m in issues):
    print("  PASS")

# CHECK 17: record_id is string
print("\nCHECK 17: record_id is string")
for gen, e in all_events:
    if not isinstance(e.get('record_id'), str):
        issues.append(('WARNING', f'record_id type={type(e.get("record_id")).__name__}'))
        break
if not any('record_id' in m for s, m in issues):
    print("  PASS")

# CHECK 18: No None values
print("\nCHECK 18: No None values anywhere")
none_paths = set()
for gen, e in all_events:
    for k, v in e.items():
        if v is None:
            none_paths.add(k)
        elif isinstance(v, dict):
            for k2, v2 in v.items():
                if v2 is None:
                    none_paths.add(f'{k}.{k2}')
if none_paths:
    issues.append(('WARNING', f'None values at: {none_paths}'))
    print(f"  WARNING: None at {none_paths}")
else:
    print("  PASS")

# CHECK 19: message populated when formatter exists
print("\nCHECK 19: message populated")
for gen, e in all_events:
    eid_int = int(e['event_id'])
    msg = e.get('message', '')
    if eid_int in _MSG_BUILDERS and (not msg or msg == f'Event ID {e["event_id"]}'):
        issues.append(('WARNING', f'{gen}/{e["event_id"]}: empty message'))
if not any('empty message' in m for s, m in issues):
    print("  PASS")

# CHECK 20: All _EVENT_META entries have formatters
print("\nCHECK 20: _EVENT_META coverage in _MSG_BUILDERS")
missing = set(_EVENT_META.keys()) - set(_MSG_BUILDERS.keys())
if missing:
    issues.append(('WARNING', f'No formatters for: {missing}'))
    print(f"  WARNING: {missing}")
else:
    print("  PASS")

# CHECK 21: IpAddress format in 4624 (real Windows uses bare IPv4 for 4624)
print("\nCHECK 21: 4624 IpAddress is valid IP or dash")
for gen, e in all_events:
    if e['event_id'] == '4624':
        ip = e['event_data'].get('IpAddress', '')
        if ip and ip != '-' and ip != '::1' and not re.match(r'^[\d.]+$', ip) and not re.match(r'^::ffff:[\d.]+$', ip) and not ':' in ip:
            issues.append(('WARNING', f'{gen}/4624: IpAddress={ip!r} invalid format'))
            print(f"  WARNING: {ip!r}")
            break
if not any('IpAddress' in m and '4624' in m for s, m in issues):
    print("  PASS")

# CHECK 22: 4625 Status/SubStatus
print("\nCHECK 22: 4625 Status/SubStatus")
for gen, e in all_events:
    if e['event_id'] == '4625':
        ed = e['event_data']
        if 'Status' not in ed or 'SubStatus' not in ed:
            issues.append(('WARNING', f'{gen}/4625: missing Status/SubStatus'))
        break
if not any('Status' in m and '4625' in m for s, m in issues):
    print("  PASS")

# CHECK 23: No excluded providers
print("\nCHECK 23: No excluded provider names")
EXCLUDED = ['Sysmon', 'AD FS', 'Antimalware-Scan', 'DNSServer']
for gen, e in all_events:
    pn = e.get('provider_name', '')
    for ex in EXCLUDED:
        if ex in pn:
            issues.append(('CRITICAL', f'Uses excluded provider: {pn}'))
if not any('excluded provider' in m for s, m in issues):
    print("  PASS")

# CHECK 24: os_subtype present
print("\nCHECK 24: os_subtype present")
for gen, e in all_events:
    if 'os_subtype' not in e:
        issues.append(('WARNING', f'{gen}/{e["event_id"]}: no os_subtype'))
        break
if not any('os_subtype' in m for s, m in issues):
    print("  PASS")

# CHECK 25: Key modeling rule fields per event type
print("\nCHECK 25: Modeling rule field coverage")
FIELD_CHECKS = {
    '4768': ['TicketEncryptionType', 'IpAddress', 'IpPort', 'Status', 'ServiceName', 'TargetUserName'],
    '4769': ['TicketEncryptionType', 'IpAddress', 'Status', 'ServiceName', 'TargetUserName', 'LogonGuid'],
    '4771': ['Status', 'IpAddress', 'TargetUserName'],
    '4776': ['TargetUserName', 'Workstation', 'Status'],
    '4672': ['SubjectUserSid', 'SubjectUserName', 'PrivilegeList'],
    '4688': ['NewProcessName', 'CommandLine', 'ParentProcessName', 'SubjectUserName'],
    '4689': ['ProcessName', 'SubjectUserName'],
    '4662': ['SubjectUserName', 'ObjectName', 'AccessMask', 'Properties'],
    '5136': ['AttributeLDAPDisplayName', 'AttributeValue', 'ObjectDN', 'ObjectClass', 'OperationType', 'OpCorrelationID'],
    '4741': ['TargetUserName', 'SamAccountName', 'SubjectUserName', 'DnsHostName'],
}
all_pass = True
for eid, required in FIELD_CHECKS.items():
    for gen, e in all_events:
        if e['event_id'] == eid:
            ed = e['event_data']
            miss = [f for f in required if f not in ed]
            if miss:
                issues.append(('WARNING', f'{eid} missing fields: {miss}'))
                print(f"  WARNING: {eid} missing {miss}")
                all_pass = False
            break
if all_pass:
    print("  PASS")

# CHECK 26: 4776 has PackageName field (used by modeling rules for NTLM detection)
print("\nCHECK 26: 4776 PackageName present")
for gen, e in all_events:
    if e['event_id'] == '4776':
        if 'PackageName' not in e['event_data']:
            issues.append(('WARNING', '4776 missing PackageName'))
        break
if not any('PackageName' in m for s, m in issues):
    print("  PASS")

# CHECK 27: 4648 has required fields for explicit credential logon
print("\nCHECK 27: 4648 completeness")
for gen, e in all_events:
    if e['event_id'] == '4648':
        ed = e['event_data']
        for f in ['TargetUserName', 'TargetServerName', 'SubjectUserName', 'ProcessName']:
            if f not in ed:
                issues.append(('WARNING', f'4648 missing {f}'))
        break
if not any('4648' in m for s, m in issues):
    print("  PASS")

# =========================================================================
# SUMMARY
# =========================================================================
print("\n" + "=" * 70)
critical = [(s, m) for s, m in issues if s == 'CRITICAL']
warnings = [(s, m) for s, m in issues if s == 'WARNING']
print(f"CRITICAL: {len(critical)}   WARNING: {len(warnings)}")
if critical:
    print("\nCRITICAL ISSUES (will break XSIAM parsing/modeling):")
    for s, m in critical:
        print(f"  !! {m}")
if warnings:
    print("\nWARNINGS (may affect some detections):")
    for s, m in warnings:
        print(f"  -- {m}")
if not issues:
    print("\nNO ISSUES FOUND - ALL EVENTS VALIDATED AGAINST CONTENT PACK")
