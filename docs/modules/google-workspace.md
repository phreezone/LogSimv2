# Google Workspace

**Dataset:** `google_workspace_drive_raw` (Drive events) · built-in datasets for Login / Admin / Token events
**Transport:** HTTP Collector (self-contained; 5 per-app collectors in `config.json`)
**Format:** Google Admin SDK Reports API Activity resource JSON

> **Status: Not currently operational.** The Google Workspace module requires Google Workspace Admin API credentials (OAuth service account with domain-wide delegation). The HTTP collectors for this module are defined in `config.json` but the module is disabled pending API credential setup. Threat events for this module appear only as part of correlated attack scenarios (see [Attack Scenarios](../attack-scenarios.md)).

Simulates Google Workspace audit log events (Drive, Login, Admin, User Accounts, Token) using the exact Admin SDK Reports API Activity resource format. The `GoogleDrive_1_3.xif` XIF rule maps Drive events to XDM (`_vendor="Google"`, `_product="Drive"`). Login, admin, and other app events use XSIAM built-in parsers.

- **XIF:** `GoogleDrive_1_3.xif` for Drive events
- **Scenario events supported:** `LOGIN_SUCCESS`, `DRIVE_VIEW_SENSITIVE`, `DRIVE_PUBLIC_SHARE`, `DRIVE_DOWNLOAD`
- **Impossible travel:** timestamp gap injected into `id.time` field in payload (NOT wall-clock); Event1 = NOW-2..6h, Event2 = NOW
