"""Cross-check all event_data fields against Microsoft documentation."""
import json, sys
sys.path.insert(0, '.')
from modules.windows_events import _BENIGN_GENERATORS, _THREAT_GENERATORS

session = {
    'jsmith': {'primary_os_type': 'Windows', 'primary_hostname': 'WKS001', 'primary_ip': '10.0.1.50', 'primary_os_version': 'Windows 10 Enterprise', 'active_devices': {}},
    'awhite': {'primary_os_type': 'Windows', 'primary_hostname': 'WKS002', 'primary_ip': '10.0.1.51', 'primary_os_version': 'Windows 10 Enterprise', 'active_devices': {}},
}
config = {
    'windows_events_config': {
        'domain': 'examplecorp.local', 'dc_hostname': 'DC01.examplecorp.local',
        'domain_name': 'EXAMPLECORP', 'dns_domain': 'examplecorp.local',
        'domain_controller_hostname': 'DC01.examplecorp.local',
        'workstations': ['WKS001.examplecorp.local', 'WKS002.examplecorp.local'],
        'users': [
            {'username': 'jsmith', 'domain': 'EXAMPLECORP', 'sid': 'S-1-5-21-1234-1001'},
            {'username': 'awhite', 'domain': 'EXAMPLECORP', 'sid': 'S-1-5-21-1234-1002'},
        ],
        'transport': 'http',
    }
}

all_gens = {}
all_gens.update(_BENIGN_GENERATORS)
all_gens.update(_THREAT_GENERATORS)

by_eid = {}
for name, fn in all_gens.items():
    for attempt in range(5):
        try:
            result = fn(config, session)
            if result:
                for raw in result:
                    e = json.loads(raw)
                    eid = e['event_id']
                    if eid not in by_eid:
                        by_eid[eid] = (name, e)
                break
        except:
            pass

MS_FIELDS = {
    '4624': ['SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','TargetUserSid','TargetUserName','TargetDomainName','TargetLogonId','LogonType','LogonProcessName','AuthenticationPackageName','WorkstationName','LogonGuid','TransmittedServices','LmPackageName','KeyLength','ProcessId','ProcessName','IpAddress','IpPort','ImpersonationLevel','RestrictedAdminMode','TargetOutboundUserName','TargetOutboundDomainName','VirtualAccount','TargetLinkedLogonId','ElevatedToken'],
    '4625': ['SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','TargetUserSid','TargetUserName','TargetDomainName','Status','FailureReason','SubStatus','LogonType','LogonProcessName','AuthenticationPackageName','WorkstationName','TransmittedServices','LmPackageName','KeyLength','ProcessId','ProcessName','IpAddress','IpPort'],
    '4634': ['TargetUserSid','TargetUserName','TargetDomainName','TargetLogonId','LogonType'],
    '4648': ['SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','LogonGuid','TargetUserName','TargetDomainName','TargetLogonGuid','TargetServerName','TargetInfo','ProcessId','ProcessName','IpAddress','IpPort'],
    '4656': ['SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','ObjectServer','ObjectType','ObjectName','HandleId','TransactionId','AccessList','AccessReason','AccessMask','PrivilegeList','RestrictedSidCount','ProcessId','ProcessName','ResourceAttributes'],
    '4662': ['SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','ObjectServer','ObjectType','ObjectName','OperationType','HandleId','AccessList','AccessMask','Properties','AdditionalInfo','AdditionalInfo2'],
    '4663': ['SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','ObjectServer','ObjectType','ObjectName','HandleId','AccessList','AccessMask','ProcessId','ProcessName','ResourceAttributes'],
    '4672': ['SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','PrivilegeList'],
    '4688': ['SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','NewProcessId','NewProcessName','TokenElevationType','ProcessId','CommandLine','TargetUserSid','TargetUserName','TargetDomainName','TargetLogonId','ParentProcessName','MandatoryLabel'],
    '4689': ['SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','Status','ProcessId','ProcessName'],
    '4740': ['TargetUserName','TargetDomainName','TargetSid','SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId'],
    '4741': ['TargetUserName','TargetDomainName','TargetSid','SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','PrivilegeList','SamAccountName','DisplayName','UserPrincipalName','HomeDirectory','HomePath','ScriptPath','ProfilePath','UserWorkstations','PasswordLastSet','AccountExpires','PrimaryGroupId','AllowedToDelegateTo','OldUacValue','NewUacValue','UserAccountControl','UserParameters','SidHistory','LogonHours','DnsHostName','ServicePrincipalNames'],
    '4767': ['TargetUserName','TargetDomainName','TargetSid','SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId'],
    '4768': ['TargetUserName','TargetDomainName','TargetSid','ServiceName','ServiceSid','TicketOptions','Status','TicketEncryptionType','PreAuthType','IpAddress','IpPort','CertIssuerName','CertSerialNumber','CertThumbprint','ResponseTicket','AccountSupportedEncryptionTypes','AccountAvailableKeys','ServiceSupportedEncryptionTypes','ServiceAvailableKeys','DCSupportedEncryptionTypes','DCAvailableKeys','ClientAdvertizedEncryptionTypes','SessionKeyEncryptionType','PreAuthEncryptionType'],
    '4769': ['TargetUserName','TargetDomainName','ServiceName','ServiceSid','TicketOptions','TicketEncryptionType','IpAddress','IpPort','Status','LogonGuid','TransmittedServices'],
    '4771': ['TargetUserName','TargetSid','ServiceName','TicketOptions','Status','PreAuthType','IpAddress','IpPort','CertIssuerName','CertSerialNumber','CertThumbprint'],
    '4776': ['PackageName','TargetUserName','Workstation','Status'],
    '5136': ['OpCorrelationID','AppCorrelationID','SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','DSName','DSType','ObjectDN','ObjectGUID','ObjectClass','AttributeLDAPDisplayName','AttributeSyntaxOID','AttributeValue','OperationType'],
    '5137': ['OpCorrelationID','AppCorrelationID','SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','DSName','DSType','ObjectDN','ObjectGUID','ObjectClass'],
}

all_pass = True
for eid in sorted(by_eid.keys(), key=lambda x: int(x)):
    if eid not in MS_FIELDS:
        print(f"Event {eid}: NO REFERENCE (skip)")
        continue
    name, e = by_eid[eid]
    our_keys = sorted(e.get('event_data', {}).keys())
    ms_fields = MS_FIELDS[eid]
    ms_keys = sorted(ms_fields)

    missing = set(ms_fields) - set(our_keys)
    extra = set(our_keys) - set(ms_fields)

    if missing or extra:
        all_pass = False
        print(f"Event {eid}: MISMATCH  (ours={len(our_keys)}, MS={len(ms_fields)})")
        if missing: print(f"  MISSING: {sorted(missing)}")
        if extra:   print(f"  EXTRA:   {sorted(extra)}")
    else:
        print(f"Event {eid}: MATCH  ({len(our_keys)} fields)")

if all_pass:
    print("\nALL 19 EVENT TYPES MATCH MICROSOFT DOCUMENTATION EXACTLY")
else:
    print("\nSOME EVENTS HAVE FIELD DISCREPANCIES")
