# Bad User use-case playbooks

Bad User drives one simulated employee: every event comes from that person's own computer
or account, so XSIAM can build a single case around them. By default it fires a **random
mix** of threats, each module on its own clock, which gives a wide case with no storyline.

A **playbook** tells one use case as an ordered story instead: step 1, then step 2, and so
on, each a real threat from one of the modules. Pick one in the Bad User tab's **Use case**
list, or pass `playbook` to `POST /api/v1/baduser/start` (or the `start_bad_user` MCP tool).
Leave it empty for the random mix.

## How a run works

- **Same identity as always.** Every step runs as the target, through the same path as the
  random mix: the target's one internal IP on-prem, their office egress IP in the cloud, the
  Bad User allow-list (`modules/bad_user_policy.py`) and the record filter. Nothing outside
  the target's own doing is sent.
- **Normal activity underneath.** The module workers keep sending the target's benign
  traffic, but fire no random threats while a playbook runs. The playbook decides which
  threats fire and when.
- **Paced to the run.** Each step has a nominal gap after the previous one. The whole story
  is stretched or squeezed to finish at about 85% of the duration you set (never slower than
  3x nominal), so a 15-minute run and a 60-minute run tell the same story at different
  speeds. A 1-minute run squeezes it to about 50 seconds. After the last step the run carries
  on with benign traffic until the timer ends.
- **Skipped steps.** A step is skipped, with the reason shown, when its module is not running
  for this user: not ticked in **Modules**, AWS for a user with no `aws_iam_user`, or Windows
  for a user whose computer is a Mac or Linux box. A skipped step adds no gap. The picker
  shows what will be skipped before you start; the start response and the status list them.
- **Retries.** Some generators pick an outside operator part of the time and the filter
  drops those records, so a step is tried up to five times before it is recorded as `no_output`.
- **Progress.** The active card lists every step with its state (pending, running, fired,
  skipped, no output, error) and when it fired. `GET /api/v1/baduser/status` returns the same
  as `playbook.steps`.

## The playbooks

Each step names the module and the threat it fires. Steps are in order.

### Phishing click to data theft (`phish_to_exfil`)

The user's workstation is compromised through a phishing link: command and control, credential theft, movement to a coworker's machine, then a large upload out.

| # | Tactic | What happens | Module | Threat |
|---|---|---|---|---|
| 1 | Initial Access | Clicks a phishing link that the email gateway lets through | Proofpoint Email Gateway | `click_permitted` |
| 2 | Execution | Downloads a payload that the web gateway sandbox flags | Zscaler Web Gateway | `sandbox_threat` |
| 3 | Command and Control | Host starts beaconing to a command-and-control domain over DNS | Infoblox NIOS | `C2_BEACON` |
| 4 | Command and Control | Repeated connections to a rare domain | Palo Alto Networks NGFW | `recurring_rare_domain` |
| 5 | Credential Access | A process opens a handle to LSASS to read credentials | Windows Event Log | `lsass_handle_access` |
| 6 | Discovery | Lists the SMB shares of other hosts | Windows Event Log | `share_enumeration` |
| 7 | Lateral Movement | PsExec to a coworker's machine | Windows Event Log | `psexec_lateral` |
| 8 | Exfiltration | Large upload to external storage through the web gateway | Zscaler Web Gateway | `data_exfil` |
| 9 | Exfiltration | The same upload seen as a large HTTPS session on the firewall | Palo Alto Networks NGFW | `large_upload_https` |
| 10 | Exfiltration | ...and on a second firewall | Cisco Firepower | `large_file_upload` |

### Insider data theft (`insider_data_theft`)

An employee finds, collects and sends out data they can reach: SharePoint and OneDrive discovery, bulk download, external sharing and mail, a bulk S3 read, an upload to a personal cloud app, then deleting files.

| # | Tactic | What happens | Module | Threat |
|---|---|---|---|---|
| 1 | Discovery | Browses SharePoint sites they do not normally use | Office 365 SharePoint Online | `sharepoint_enumeration` |
| 2 | Discovery | Browses other people's OneDrive | Office 365 SharePoint Online | `onedrive_enumeration` |
| 3 | Collection | Downloads a large number of files | Office 365 SharePoint Online | `mass_download` |
| 4 | Exfiltration | Shares files with an external address | Office 365 SharePoint Online | `external_sharing` |
| 5 | Exfiltration | Data loss prevention flags sensitive content sent outside | Office 365 DLP | `dlp_sensitive_external` |
| 6 | Exfiltration | Emails sensitive content to an outside recipient | Office 365 Exchange Online | `sensitive_mail_external` |
| 7 | Collection | Reads a large set of S3 objects | aws | `S3_READ_EXFIL_CHAIN` |
| 8 | Exfiltration | Uploads to a personal cloud storage app | Zscaler Web Gateway | `cloud_app_threat` |
| 9 | Exfiltration | Large upload seen on the firewall | Fortinet FortiGate | `large_upload` |
| 10 | Defense Evasion | Deletes files to cover their tracks | Office 365 SharePoint Online | `mass_file_deletion` |

### Cloud privilege escalation and persistence (`cloud_admin_abuse`)

The user's own cloud account is turned into an administrator across Entra, Azure, AWS and GCP: enumerate, escalate, add backdoor credentials, then switch the audit logs off.

| # | Tactic | What happens | Module | Threat |
|---|---|---|---|---|
| 1 | Initial Access | Signs in with PowerShell instead of a browser | Azure AD Sign-ins | `powershell_signin` |
| 2 | Discovery | Enumerates the directory through Microsoft Graph | Azure AD Sign-ins | `graph_enumeration` |
| 3 | Privilege Escalation | Adds an administrator role | Azure AD Audit | `admin_role_add` |
| 4 | Persistence | Adds a credential to an application | Azure AD Audit | `app_credential_added` |
| 5 | Privilege Escalation | Assigns a powerful role on a subscription | Azure Activity | `wip_role_assignment` |
| 6 | Credential Access | Reads every secret in a Key Vault | Azure Activity | `wip_keyvault_secret_dump` |
| 7 | Discovery | Lists IAM users, roles and policies | aws | `IAM_RECON_LIST` |
| 8 | Privilege Escalation | Attaches AdministratorAccess | aws | `ATTACH_ADMIN_POLICY` |
| 9 | Persistence | Creates a new access key | aws | `CREATE_ACCESS_KEY` |
| 10 | Discovery | Probes which permissions the account holds | Google Cloud Compute | `IAM_RECON_TESTPERMISSIONS` |
| 11 | Privilege Escalation | Grants itself an owner role | Google Cloud Compute | `IAM_PRIVILEGE_ESCALATION` |
| 12 | Persistence | Creates a service account key | Google Cloud Compute | `CREATE_SA_KEY` |
| 13 | Defense Evasion | Deletes Azure diagnostic settings | Azure Activity | `wip_diagnostic_settings_delete` |
| 14 | Defense Evasion | Stops CloudTrail logging | aws | `STOP_CLOUDTRAIL` |
| 15 | Defense Evasion | Disables GCP audit logging | Google Cloud Compute | `DISABLE_AUDIT_LOGGING` |

### Ransomware precursor (`ransomware_precursor`)

From the user's machine: discovery, credential theft, spreading with PsExec and scheduled tasks, SMB movement, preparing the hypervisor, destroying backups, then mass file changes.

| # | Tactic | What happens | Module | Threat |
|---|---|---|---|---|
| 1 | Discovery | Lists the SMB shares of other hosts | Windows Event Log | `share_enumeration` |
| 2 | Credential Access | A process opens a handle to LSASS | Windows Event Log | `lsass_handle_access` |
| 3 | Lateral Movement | PsExec to a coworker's machine | Windows Event Log | `psexec_lateral` |
| 4 | Execution | Creates a scheduled task on a remote host | Windows Event Log | `remote_scheduled_task` |
| 5 | Persistence | Installs a service from a user-writable path | Windows Event Log | `malicious_service_install` |
| 6 | Lateral Movement | SMB to a host this machine never talks to | Fortinet FortiGate | `smb_new_host_lateral` |
| 7 | Lateral Movement | Unusual SMB file transfer | Cisco ASA Firewall | `smb_rare_file_transfer` |
| 8 | Execution | Runs programs inside guest machines from the hypervisor | VMware ESXi | `guest_ops_exec` |
| 9 | Collection | Attaches another VM's disk to read it directly | VMware ESXi | `vm_disk_attach` |
| 10 | Impact | Deletes a backup vault | aws | `BACKUP_VAULT_DELETED` |
| 11 | Impact | Deletes EBS snapshots | aws | `EBS_SNAPSHOT_DELETION` |
| 12 | Impact | Mass modification of files (encryption) | Office 365 SharePoint Online | `mass_file_editing` |
| 13 | Impact | Re-encrypts S3 objects | aws | `S3_RANSOMWARE_ENCRYPT` |

### Mailbox takeover and mail forwarding (`mailbox_takeover`)

The user's mailbox is set up to leak and hide mail: a new device, a new MFA method, forwarding and hiding rules, delegated access, then sensitive mail and files shared outside.

| # | Tactic | What happens | Module | Threat |
|---|---|---|---|---|
| 1 | Initial Access | Signs in from a device not seen before | Azure AD Sign-ins | `new_device_signin` |
| 2 | Persistence | Registers a new MFA method | Azure AD Audit | `auth_method_added` |
| 3 | Collection | Creates an inbox rule that forwards mail out | Office 365 Exchange Online | `inbox_forwarding_rule` |
| 4 | Defense Evasion | Creates a rule that hides incoming mail | Office 365 Exchange Online | `email_hiding_rule` |
| 5 | Collection | Grants another account access to the mailbox | Office 365 Exchange Online | `mailbox_delegation` |
| 6 | Collection | Grants Send As permission | Office 365 Exchange Online | `send_as_permission` |
| 7 | Exfiltration | Emails sensitive content to an outside recipient | Office 365 Exchange Online | `sensitive_mail_external` |
| 8 | Exfiltration | Creates an anyone-with-the-link share | Office 365 SharePoint Online | `anonymous_link` |
| 9 | Defense Evasion | Turns off mailbox audit logging | Office 365 Exchange Online | `exchange_audit_log_disabled` |

### Reconnaissance from the workstation (`recon_and_discovery`)

Someone learning the environment from the user's machine: LDAP and SMB discovery, Kerberos attacks, a port sweep, then directory and cloud enumeration.

| # | Tactic | What happens | Module | Threat |
|---|---|---|---|---|
| 1 | Discovery | Queries the directory over LDAP | Palo Alto Networks NGFW | `ldap_recon` |
| 2 | Discovery | Enumerates SMB shares across hosts | Check Point Firewall | `smb_share_enumeration` |
| 3 | Discovery | Lists the SMB shares of other hosts | Windows Event Log | `share_enumeration` |
| 4 | Credential Access | Requests AS-REP hashes for accounts without pre-auth | Windows Event Log | `as_rep_roasting` |
| 5 | Credential Access | Requests many service tickets (Kerberoasting) | Windows Event Log | `multiple_service_tickets` |
| 6 | Discovery | Sweeps ports across the internal network | Fortinet FortiGate | `port_sweep` |
| 7 | Discovery | Enumerates the directory through Microsoft Graph | Azure AD Sign-ins | `graph_enumeration` |
| 8 | Discovery | Lists the Okta administrator roles | Okta SSO | `admin_role_enumeration` |
| 9 | Discovery | Lists IAM users, roles and policies | aws | `IAM_RECON_LIST` |
| 10 | Discovery | Lists the AWS organization | aws | `ORGANIZATIONS_RECON` |
| 11 | Discovery | Probes which GCP permissions the account holds | Google Cloud Compute | `IAM_RECON_TESTPERMISSIONS` |
| 12 | Discovery | Enumerates resources across Azure regions | Azure Activity | `wip_multi_region_enumeration` |

### Infected endpoint: beaconing and tunneling (`endpoint_beaconing`)

Network-only story that works for any operating system: DNS and web beaconing, fast-flux and tunneling, an SSH tunnel and Tor from the machine, then a miner.

| # | Tactic | What happens | Module | Threat |
|---|---|---|---|---|
| 1 | Command and Control | Beacons to a command-and-control domain over DNS | Infoblox NIOS | `C2_BEACON` |
| 2 | Command and Control | Resolves a fast-flux domain | Infoblox NIOS | `FAST_FLUX_DNS` |
| 3 | Command and Control | Regular web beacon through the gateway | Zscaler Web Gateway | `web_c2_beacon` |
| 4 | Command and Control | DNS beaconing seen on the firewall | Cisco ASA Firewall | `dns_c2_beacon` |
| 5 | Command and Control | Data tunneled inside DNS queries | Infoblox NIOS | `DNS_TUNNEL` |
| 6 | Command and Control | Connects to a dynamic-DNS host | Fortinet FortiGate | `ddns_connection` |
| 7 | Command and Control | Opens a reverse SSH tunnel | Zscaler Web Gateway | `reverse_ssh_tunnel` |
| 8 | Command and Control | SSH hidden on the HTTPS port | Cisco Firepower | `ssh_over_https` |
| 9 | Exfiltration | DNS tunneling seen on the firewall | Check Point Firewall | `dns_tunneling` |
| 10 | Command and Control | Connects to the Tor network | Zscaler Web Gateway | `tor_connection` |
| 11 | Impact | Crypto-mining traffic | Cisco ASA Firewall | `cryptomining` |

## Adding or changing a playbook

Playbooks are data in `modules/bad_user_playbooks.py` (`PLAYBOOKS`). A step is
`_s(module, threat, tactic, label, (min_gap, max_gap))`: the module's `NAME`, one of its
threat names, a tactic from `TACTICS`, the text shown in the UI, and the nominal seconds after
the previous step.

Then check it:

```bash
python -m modules.bad_user_playbooks
```

This verifies every step against the modules' real `get_threat_names()` and the Bad User
allow-list, and exits non-zero on a problem. It does not tell you whether a threat produces
records that carry the target: some generators use an outside source and the record filter
drops them. Run the playbook once as a real user (the Bad User tab, or the API) and look for
steps that end as `no_output`; replace those, or exclude the threat in
`modules/bad_user_policy.py`.

## Choosing a user

Playbooks that include Windows steps (phishing click to data theft, ransomware precursor,
reconnaissance) need a user whose main computer runs Windows; the picker marks the others.
**Endpoint beaconing** is network-only and works for any operating system. AWS steps (in
insider data theft, cloud privilege escalation, ransomware precursor and reconnaissance) run
only for users with an `aws_iam_user`.
