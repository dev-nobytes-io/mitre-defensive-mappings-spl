# Gaps (ATT&CK v20.1)

What the mappings do not cover yet: feeds on platforms outside the current scope, and data components with no in-scope provider. For the in-scope feeds and what each one supports, see the [log source checklist](checklist.md) and the [index by log source](by-log-source.md).

## Out-of-scope platforms

Listed so the catalogue is complete; rendering for these platforms is a later phase.

| Feed | Platforms | Analytics referencing it | What it is |
|---|---|---|---|
| `macos` | macOS | 354 | macOS unified log / Endpoint Security / osquery / FSEvents |
| `m365_unified` | Office Suite, SaaS, Identity Provider, Windows | 103 | Microsoft 365 unified audit log (Exchange, SharePoint, Teams, Purview) |
| `aws` | IaaS, SaaS, Containers | 98 | AWS CloudTrail / VPC Flow / CloudWatch / Bedrock |
| `gcp` | IaaS, SaaS, Identity Provider | 18 | Google Cloud audit / VPC flow / Workspace admin |
| `okta` | Identity Provider, SaaS | 0 | Okta System Log |
| `saas` | SaaS | 57 | SaaS application audit logs (GitHub, Slack, Salesforce, Zoom, Box, Confluence, Google Workspace...) |
| `mobile` | — | 0 | Mobile EDR / MDM telemetry |
| `ot` | — | 0 | OT / ICS application and protocol logs |
| `threat_intel` | PRE | 39 | External reconnaissance sources (internet scan data, domain registration, malware repositories, persona monitoring) |

## Components with no in-scope provider

| Component | Analytics | Log sources named by ATT&CK |
|---|---|---|
| [DC0022](data-components/DC0022-cloud-storage-deletion.md) Cloud Storage Deletion | 2 | AWS:CloudTrail |
| [DC0023](data-components/DC0023-cloud-storage-modification.md) Cloud Storage Modification | 5 | AWS:CloudTrail, m365:unified, saas:googledrive |
| [DC0024](data-components/DC0024-cloud-storage-creation.md) Cloud Storage Creation | 1 | AWS:CloudTrail |
| [DC0025](data-components/DC0025-cloud-storage-access.md) Cloud Storage Access | 13 | AWS:CloudTrail, m365:unified, m365:sharepoint, saas:github, gcp:workspaceaudit |
| [DC0026](data-components/DC0026-image-deletion.md) Image Deletion | 0 |  |
| [DC0027](data-components/DC0027-cloud-storage-metadata.md) Cloud Storage Metadata | 3 | AWS:CloudTrail, m365:unified, saas:box, saas:dropbox |
| [DC0047](data-components/DC0047-snapshot-enumeration.md) Snapshot Enumeration | 0 |  |
| [DC0052](data-components/DC0052-social-media.md) Social Media | 4 | Persona |
| [DC0058](data-components/DC0058-snapshot-modification.md) Snapshot Modification | 2 | AWS:CloudTrail |
| [DC0062](data-components/DC0062-snapshot-metadata.md) Snapshot Metadata | 2 | AWS:CloudTrail, gcp:audit |
| [DC0070](data-components/DC0070-cloud-service-metadata.md) Cloud Service Metadata | 10 | AWS:CloudTrail, saas:github, AWS:CloudWatch, m365:sharepoint, m365:exchange, m365:unified |
| [DC0074](data-components/DC0074-driver-metadata.md) Driver Metadata | 1 | macos:unifiedlog |
| [DC0080](data-components/DC0080-instance-start.md) Instance Start | 11 | AWS:CloudTrail |
| [DC0086](data-components/DC0086-instance-metadata.md) Instance Metadata | 3 | AWS:CloudTrail |
| [DC0089](data-components/DC0089-instance-stop.md) Instance Stop | 4 | AWS:CloudTrail |
| [DC0093](data-components/DC0093-certificate-registration.md) Certificate Registration | 2 | Certificate |
| [DC0095](data-components/DC0095-volume-enumeration.md) Volume Enumeration | 0 |  |
| [DC0096](data-components/DC0096-passive-dns.md) Passive DNS | 5 | Domain Name |
| [DC0100](data-components/DC0100-volume-metadata.md) Volume Metadata | 0 | Metadata |
| [DC0103](data-components/DC0103-active-dns.md) Active DNS | 5 | Domain Name |
