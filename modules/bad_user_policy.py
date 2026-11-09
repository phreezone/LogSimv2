"""Which threats Bad User mode may fire.

Bad User builds ONE case around one identity: every event must be something the target
could have generated themselves -- from their own computer or with their own account. On
the network side it comes from that computer's internal address; in cloud logs (Entra,
O365, Okta, AWS) from the office egress the computer reaches them through, which is also
the firewall's NAT address for it. So a threat is EXCLUDED here when its actor or source
is not the target:

  outside-in    attacks arriving from the internet: scans, IPS/WAF/DoS hits, web exploits
                against the public web server, inbound connections to a new FTP server
  account-from-outside
                the target's account used from somewhere else: Tor, foreign country,
                impossible travel, password spray / brute force / MFA bombing against them,
                AiTM / token theft or replay, VPN logins from outside
  other actors  service / machine / honey / break-glass accounts, applications and service
                principals acting on their own, Kubernetes service accounts, EC2 roles,
                domain controllers and servers as the source, the firewall management plane,
                ESXi host internals, mail delivered TO the user (Proofpoint inbound)

Everything else -- the target's own sign-ins, admin and directory changes, file and mailbox
activity, cloud API calls, and network activity leaving their machine -- is fired, with
its source re-pointed to the target's machine (internal IP on-prem, egress in the cloud) by
the focus-aware source helpers.

Classified 2026-11-03 by firing every threat under the focus
(_local_validation/baduser_threat_classifier.py) and reviewing the names: a threat that
never named the target nor carried their address, or that kept an external source, was
excluded unless it is plainly the target's own action. Threat names not listed here are
allowed, so a NEW threat is allowed by default: classify it when you add it.
"""

EXCLUDED = {
    "Apache httpd": {
        # internet-facing web server: every threat is an outside client attacking it
        "recon_scan", "directory_traversal", "server_error_burst", "critical_error",
        "malicious_payload", "webshell_execution", "log4shell_probe", "shellshock_probe",
        "method_probing", "auth_bruteforce", "credential_stuffing", "data_exfiltration",
    },
    "Azure AD Audit": {
        "mfa_fraud_reported",            # the user reporting someone else's MFA prompt
        "onprem_sync_collision",         # directory sync engine
    },
    "Azure AD Sign-ins": {
        # account used from outside
        "brute_force", "password_spray", "impossible_travel", "high_risk_signin", "tor_signin",
        "saas_api_from_tor", "saas_api_from_tor_mobile", "multi_sso_anon_proxy",
        "suspicious_country_signin", "sso_spray_ip_rotation", "first_sso_new_asn",
        "device_code_auth_flow", "new_country_signin", "account_lockout_spray",
        "wip_unusual_country_api", "wip_high_risk_ip_activity", "wip_api_call_from_tor",
        "wip_multiple_failed_logins", "wip_impossible_travel_cloud", "wip_suspicious_device_code",
        "wip_cloud_identity_unusual_country", "wip_multiple_risk_indicators",
        # other actors: apps / service principals / managed identities / sync / honey / machine
        "aad_connect_sync_unusual_host", "honey_user_signin", "wip_honey_user_sso",
        "unusual_resource_access_by_app", "wip_unusual_resource_by_app",
        "app_access_unknown_tenant", "wip_unknown_tenant_app_access",
        "sp_token_remote_usage", "mi_token_remote_usage", "wip_remote_service_principal_token",
        "wip_remote_managed_identity_token", "wip_app_credential_first_use",
        "graph_denied_burst", "wip_graph_denied_burst", "graph_large_responses",
        "wip_graph_response_size_spike", "graph_privileged_app_call", "wip_graph_privileged_app",
        "graph_throttling_app", "wip_graph_throttling_app", "wip_graph_throttling_exact",
        "wip_cloud_email_infrastructure_enum", "wip_cloud_email_service_abuse",
        "wip_cloud_email_service_activity", "wip_mailbox_enumeration",
        "machine_account_sso", "wip_machine_account_sso", "service_account_sso",
        "wip_service_account_sso",
    },
    "Azure Activity": {
        # Kubernetes service accounts and AI workloads act, not a user
        "kube_anonymous", "kube_dashboard_external", "kube_node_external",
        "wip_kube_secret", "wip_kube_configmap", "wip_kube_deployment", "wip_kube_rolebinding",
        "wip_kube_clusterrole", "wip_kube_namespace", "wip_kube_serviceaccount", "wip_kube_cronjob",
        "wip_kube_daemonset", "wip_kube_statefulset", "wip_kube_exec", "wip_kube_ephemeral",
        "wip_kube_clusterrolebinding", "wip_kube_sidecar_pod", "wip_kube_pod_delete",
        "wip_kube_replicaset", "wip_kube_service", "wip_kube_network_policy", "wip_kube_host_ipc",
        "wip_kube_host_pid", "wip_kube_sensitive_volume", "wip_kube_unknown_registry",
        "wip_kube_host_network", "wip_kube_privileged_pod", "wip_kube_admission_controller",
        "wip_kube_events_delete", "wip_kube_enumeration", "wip_kube_rbac_enumeration",
        "wip_kube_secret_enumeration", "wip_kube_service_account_external", "wip_kube_scan_tool",
        "wip_kube_denied_api", "wip_kube_denied_enumeration", "wip_kube_unusual_sa_api",
        "wip_kube_secret_access", "wip_kube_secret_access_suspicious_ua",
        "wip_kube_clusterrole_created", "wip_kube_rolebinding_create_delete",
        "wip_kube_permission_enumeration", "wip_kube_serviceaccount_create_delete",
        "wip_kube_events_removed", "wip_kube_unusual_secret_access",
        "wip_ai_model_discovery", "wip_ai_denial_of_wallet", "wip_ai_dataset_download",
        # account-key / SAS-token access carries no identity, only the shared egress
        "wip_storage_shared_key_access", "wip_storage_sas_access",
    },
    "Check Point Firewall": {
        "ips", "smartdefense", "external_port_scan",                       # outside-in
        "vpn_brute_force", "vpn_impossible_travel", "vpn_tor_login", "vpn_new_country_login",
        "new_ftp_server",                                                  # inbound clients
        "server_outbound_http", "dc_smb_outbound",                         # server / DC source
        "mgmt_logging_suppressed", "mgmt_config_harvest", "mgmt_admin_unexpected_source",
    },
    "Cisco ASA Firewall": {
        "failed_connections_burst",                                        # outside-in
        "vpn_impossible_travel", "vpn_tor_login", "vpn_new_country_login", "vpn_data_exfil",
        "vpn_concurrent_sessions",
        "new_ftp_server",                                                  # inbound clients
        "server_outbound_http", "dc_smb_outbound",
        "mgmt_logging_suppressed", "mgmt_config_harvest", "mgmt_admin_unexpected_source",
        "mgmt_config_route_change",
    },
    "Cisco Firepower": {
        "ips", "brute_force", "network_anomaly",                           # outside-in
        "vpn_brute_force", "vpn_impossible_travel", "vpn_tor_login", "vpn_new_country_login",
        "new_ftp_server",
        "server_outbound_http", "dc_smb_outbound",
        "mgmt_admin_unexpected_source", "mgmt_config_route_change", "mgmt_logging_suppressed",
        "mgmt_config_harvest",
    },
    "Fortinet FortiGate": {
        "ips", "waf_attack", "dos_anomaly", "auth_brute_force", "external_port_scan",
        "vpn_brute_force", "vpn_impossible_travel", "vpn_password_spray", "vpn_tor_login",
        "vpn_abnormal_os", "vpn_new_country_login",
        "new_ftp_server",
        "server_outbound_http", "dc_smb_outbound",
        "mgmt_config_route_change", "mgmt_config_harvest", "mgmt_admin_unexpected_source",
        "mgmt_logging_suppressed",
    },
    "Google Cloud Compute": {
        "CLI_FROM_SERVERLESS",                                             # service account
        "TOR_API_ACCESS", "VERTEX_TOR_PREDICT",
    },
    "Identity Threat Campaigns": {
        # stories that start with the account taken over from outside, or other actors
        "hybrid_onprem_cloud", "bec_campaign", "ransomware_campaign", "stale_account_reactivation",
        "aitm_token_theft", "spray_compromise_persist", "sp_credential_abuse",
        "mfa_tamper_takeover", "impossible_travel_risky", "legacy_auth_bypass",
        "rt_to_prt_transition",
    },
    "Infoblox NIOS": {
        "DHCP_STARVATION",                                                 # not a user action
    },
    "Office 365 Azure AD": {
        "password_spray", "brute_force", "impossible_travel", "tor_signin",
    },
    "Office 365 Exchange Online": {
        "mail_accessed_multi_ip_subnet",                                   # many outside IPs
    },
    "Office 365 SharePoint Online": {
        "unusual_m365_storage_access", "wip_unusual_m365_storage_access",  # an application
    },
    "Okta SSO": {
        # account used from outside
        "brute_force", "tor_login", "policy_deny", "mfa_bombing", "mfa_bypass", "impersonation",
        "impossible_travel", "password_spray", "fastpass_phishing", "reported_suspicious",
        "sso_brute_force", "intense_sso_failures", "sso_password_spray", "ip_rotation_sso",
        "sso_rejected_country", "sso_impossible_travel", "sso_possible_imp_travel", "sso_tor",
        "sso_suspicious_country", "sso_suspicious_asn", "sso_suspicious_auth", "attack_start",
        "breached_credential", "breached_credential_login", "session_roaming", "token_reuse",
        "risk_detect", "risk_change", "policy_risk_action", "policy_reeval_fail",
        "account_lock_limit", "zone_blacklist", "security_events_provider", "risk_policy_bypass",
        "universal_logout_bypass", "third_party_signal_access", "dormant_account_reactivation",
        "session_clear_bypass", "device_swap_enrollment", "mfa_downgrade_access",
        "tor_zone_bypass_access", "tor_admin_app_pivot", "rogue_oauth_client_spray",
        "mfa_enroll_attack", "device_assurance_bypass", "radius_brute_force", "oauth2_token_farm",
        "refresh_token_persistence", "sms_otp_bombing", "aitm_phishing",
        # other actors
        "threat_detected", "honey_auth", "honey_sso", "scim_bulk_create", "registration_abuse",
        "service_account_login_abuse", "break_glass_login",
    },
    "Palo Alto Networks NGFW": {
        "rdp_unmanaged", "rdp_unmanaged_dense_subnet",                     # unmanaged device
        "smb_from_dc", "dcsync_internet_facing", "rare_appid_internet_facing",
        "new_ftp_server", "new_ftp_server_external",                       # inbound clients
        "ssh_proxy", "ssh_proxy_high_volume", "ssh_proxy_suspicious", "ssh_proxy_detected",
    },
    "Proofpoint Email Gateway": {
        # mail delivered TO the user; only their clicks are their own doing
        "phishing_url", "malware_attachment", "credential_phishing", "bec_impostor",
        "spam_campaign", "malicious_macro", "qr_code_phishing", "callback_phishing",
        "phishing_campaign",
    },
    "VMware ESXi": {
        "uncommon_host_command", "ssh_brute_force", "vuln_scan", "root_login_rare_source",
        "kernel_module_load", "config_harvest", "datastore_upload", "mass_vm_power_off",
        "unplanned_reboot", "log_rotation_disabled",
    },
    "Windows Event Log": {
        "kerberos_relay",                                                  # relayed machine auth
    },
    "Zscaler Web Gateway": {
        "brute_force", "vpn_brute_force", "vpn_impossible_travel", "vpn_tor_login",
        "vpn_new_country_login", "new_ftp_server",
        "server_outbound_http", "dc_smb_outbound",
    },
    "aws": {
        "UNUSUAL_COUNTRY_API", "IMPOSSIBLE_TRAVEL_CLOUD", "MULTIPLE_RISK_INDICATORS",
        "TOR_LOGIN", "BEDROCK_TOR_USAGE", "API_CALL_FROM_TOR", "CONSOLE_LOGIN_BRUTE_FORCE",
        "IMDS_CREDENTIAL_THEFT", "K8S_SA_OUTSIDE_CLUSTER", "ROOT_USER_ACTIVITY",
        "CONSOLE_FIRST_LOGIN_NONUSER", "CROSS_ACCOUNT_ASSUME_ROLE",
    },
}


# Modules whose BENIGN traffic is never the target's own doing, so Bad User sends none of
# it (their allowed threats, if any, still fire). Checked 2026-11-03 by sampling the benign
# records that name the target:
NO_BENIGN = {
    "Apache httpd": "internet clients of the public web server (the target's name appears "
                    "only as a login from an outside address)",
    "Azure AD Identity Protection": "Microsoft's provisioning service and risk detections "
                                    "(new country, unlikely travel, anonymized IP)",
    "Proofpoint Email Gateway": "mail delivered TO the target; only their clicks are theirs",
}


def sends_benign(module):
    """Whether Bad User sends `module`'s benign traffic at all."""
    return getattr(module, "NAME", "") not in NO_BENIGN


def allowed_threats(module):
    """Threat names `module` may fire in Bad User mode, in the module's own order."""
    try:
        names = list(module.get_threat_names() or [])
    except Exception:
        return []
    excluded = EXCLUDED.get(getattr(module, "NAME", ""), set())
    return [n for n in names if n not in excluded]
