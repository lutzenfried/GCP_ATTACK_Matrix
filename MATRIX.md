# GCP & Workspace Attack Matrix

This community based matrix main objective is to outlines a comprehensive list of Tactics, Techniques, and Procedures (TTPs) used by threat actor and applicable to Google Cloud Platform (GCP) and Google Workspace environments. 

It is a community-driven project designed to help security professionals, red teamers, and blue teamers understand and defend against threats in the Google Cloud ecosystem.

## Attack Matrix



| **TA0043** | **TA0001** | **TA0002** | **TA0003** | **TA0004** | **TA0005** | **TA0006** | **TA0007** | **TA0009** | **TA0010** | **TA0011** |
|---|---|---|---|---|---|---|---|---|---|---|
| **Reconnaissance** | **Initial Access** | **Execution** | **Persistence** | **Privilege Escalation** | **Defense Evasion** | **Credential Access** | **Discovery** | **Collection** | **Exfiltration** | **Impact** |
| Scan for Public Storage Buckets | OAuth/Consent Grant Phishing | Compute Engine Startup Scripts | Create New Service Account Keys | Abusing iam.serviceAccounts.actAs | Modify Cloud Logging Rules | Impersonate Metadata Server | Enumerate IAM Policies | Access Google Drive Files | Data Transfer to External Storage | Data Loss |
| Enumerate Google Workspace Users | Leaked Service Account Keys | Cloud Functions/Run Engine Deployment | Backdoor IAM Policies | Query Immutable Primitive Roles | Disable/Modify Cloud Monitoring | Google Workspace Token Theft | Enumerate Cloud Resources | Data Transfer to Attacker Controlled Services | Copy Data to External Storage | Service Disruption |
| OSINT for exposed credentials | Vulnerable Web Applications (SSRF/RCE) | Backdoor VM Triggers | Backdoor IaC Templates (Terraform/DM) | Default Service Account Abuse | Obfuscated Cloud Functions | Steal Service Account Tokens | List Cloud Storage Buckets | Access Google Cloud SQL Databases | Exfiltrate via DNS Tunneling | Resource Hijacking |
| Discover Public APIs/Domains | Compromised Third-party apps | Run Custom Containers (GKE, Cloud Run) | Compromise Google Workspace Admin Console | GKE ActAs (1.0.5 Bootstrap Escalation) | Delete Cloud Audit Logs (if permissions allow) | Google Workspace Admin Credentials Harvest | Discover network configurations | Access Cloud SQL Databases | Exfiltrate via VPN | Cryptomining |
| Search for DNS records | Vulnerable Web Applications | Cloud Shell persistence | OAuth app with offline access | Misconfigured Custom Roles | Abusing Google-managed service accounts | Extract credentials from Cloud Build logs | Enumerate VM instances and their service accounts | Download VM Disk Snapshots | Programmatic Cloud Storage transfer | Intellectual Property Theft |
| Enumerate Cloud Functions | Compromised Google Accounts (via malware) | DataFlow Job Execution | Cloud Scheduler Jobs | Implicit Delegation | Living off the land with `gcloud` | Access Cloud KMS Decryption Keys | Enumerate enabled APIs and services | Collect Kubernetes Secrets | Exfiltrate using BigQuery exports | Ransomware |
| Analyze Certificate Transparency logs | DKIM Replay Attacks | Dataproc Job Execution | Plant web shells on App Engine | GCE Login Privilege Escalation | Use VPC Service Controls bypass | Extract secrets from Secret Manager | Identify available Cloud Functions and their perms | Access BigQuery datasets | Cloud Functions as proxy | Defacement |
| Probe Google login endpoints | Supply Chain via Container Images | Execute BigQuery jobs with UDFs | Create recurring Cloud Scheduler jobs | Cloud Function Access Token Theft (cloudbuild SSRF) | Timestomping on Cloud Storage objects | OAuth token refresh abuse | API discovery via error messages | Access Cloud Bigtable data | Cloud Pub/Sub message routing | API Quota Exhaustion |
| Scan for exposed Firebase DBs | CloudImposer Dependency Confusion | Deploy Cloud Composer DAGs | Modify organization policies | Cloud Build IAM Privilege Escalation | Hide malicious activities in normal operations | Browser cookie theft | List organization hierarchy | Access Apigee API proxies | Use Cloud Transfer Service | Compliance Violation |
| GitHub/GitLab dork for GCP resources | OAuth Device Code Flow Phishing | Execute via Cloud Workflows | Create API Keys for persistence | Deployment Manager Editor Access | Disable VPC Flow Logs | SSRF to metadata service | Enumerate Service Account bindings | Access Cloud Filestore | Direct database connections | DDoS Attacks |
| Shodan/Censys for exposed services | Session Hijacking via stolen cookies | Run Cloud Dataflow jobs | Add SSH keys to project metadata | Workload Identity Federation abuse | Use private VPC for C2 | Memory scraping from VMs | Enumerate Workspace groups | Query Cloud Spanner databases | VPC Peering for lateral movement | Data Manipulation |
| Enumerate public VM snapshots | Exploit edge device vulnerabilities | Execute via Vertex AI/ML workloads | Backdoor container images in GCR | Container escape to node | Deploy in regions with less monitoring | Steal credentials from VM memory | Discover Workspace users and groups | Access Cloud Memorystore | Scheduled exfiltration | Business Email Compromise |
| Search public datasets for hostnames | Insider threats/North Korean IT workers | Serial Console execution | Golden Image persistence | Cross-project role assumption | Modify VPC firewall rules | Extract from Cloud Source Repos | Security Command Center enumeration | Snapshot disk access | Storage Transfer Service abuse | Rapid Reset DDoS |
| Job postings analysis for tech stack | GCP Marketplace N-day vulnerabilities | Cloud Tasks execution | VMAccess extension abuse (Azure equiv) | Confused deputy via Service Accounts | Use legitimate GCP tools maliciously | Harvest from GCE instance metadata | Attack path simulation discovery | Access shared drives | Abuse ingress/egress rules | VM disk encryption for ransom |
| Public code repo scanning | Brute-force/Password spraying | Abusing Cloud Scheduler | Bootstrap token persistence | Domain-wide delegation abuse | Custom metadata to hide payloads | Cloud Function token theft | VPC Flow Logs analysis | Clone VM disks via snapshots | Exfiltrate via legitimate APIs | Supply chain disruption |
| DNS subdomain enumeration | SAML/SSO vulnerabilities | Execute commands via OS Login | Service account key rotation | Federation misconfigurations | Disable Security Command Center | Workload identity token extraction | Cloud Asset Inventory enumeration | VM Serial Console access | Data staging in temp buckets | Reputation damage |
| Email validation probing | Zero-day exploitation | Cloud Build trigger abuse | Modify startup scripts | Group membership escalation | VPC Service Controls dry run abuse | TPM key extraction | Enumerate firewall rules | LiveRamp match tables access | Compress and encrypt before exfil | Unauthorized cryptocurrency mining |
| Exposed API endpoint discovery | Compromised CI/CD credentials | Execute via Cloud Run Jobs | OAuth tokens with extended expiry | Org Policy constraint bypass | Blend with legitimate traffic patterns | DKIM signed email replay | List all accessible projects | Container image layer extraction | Use webhooks for data transfer | Service unavailability |
| Cloud asset inventory scanning | Recycled domain OAuth hijacking | Invoke Cloud Functions via HTTP | Metadata server persistence | RBAC misconfigurations in GKE | Deploy lookalike services | Extract from environment variables | Discover integration connectors | Export Vault archived data | Abuse OAuth redirect URIs | Trust relationship damage |

## New Techniques Added with Sources

### TA0043 - Reconnaissance
- **Scan for exposed Firebase DBs** - Source: Cyserch Top 10 GCP Vulnerabilities 2025
- **GitHub/GitLab dork for GCP resources** - Source: GitLab Tutorial on GCP privilege escalation
- **Shodan/Censys for exposed services** - Source: StationX Cloud Security Statistics 2025

### TA0001 - Initial Access
- **DKIM Replay Attacks** - Source: Doppel and BleepingComputer articles on Google OAuth/DKIM attacks
- **Supply Chain via Container Images** - Source: Cyber Press on GCP exploitation methods
- **CloudImposer Dependency Confusion** - Source: Dark Reading RCE flaw in Google Cloud
- **OAuth Device Code Flow Phishing** - Source: Doppel phishing campaign analysis
- **Exploit edge device vulnerabilities** - Source: Help Net Security M-Trends 2025 report
- **Insider threats/North Korean IT workers** - Source: Help Net Security on insider threat rise
- **Recycled domain OAuth hijacking** - Source: The Hacker News Google OAuth vulnerability

### TA0002 - Execution
- **Serial Console execution** - Source: Unit42 cloud lateral movement techniques

### TA0003 - Persistence
- **Add SSH keys to project metadata** - Source: Google Cloud Blog and Unit42 on lateral movement
- **Backdoor container images in GCR** - Source: GitLab GCP post-exploitation tactics
- **Golden Image persistence** - Source: Google Community on Golden Image lateral movement
- **Bootstrap token persistence** - Source: Assured AB on exploiting GKE defaults

### TA0004 - Privilege Escalation
- **Deployment Manager Editor Access** - Source: Rhino Security Labs GCP privilege escalation
- **Workload Identity Federation abuse** - Source: Multiple sources on Workload Identity Federation
- **Container escape to node** - Source: Assured AB GKE exploitation
- **Confused deputy via Service Accounts** - Source: Tenable ConfusedFunction vulnerability

### TA0005 - Defense Evasion
- **OAuth token refresh abuse** - Source: Google Cloud on OAuth token mitigation
- **Modify VPC firewall rules** - Source: Google Cloud Blog on Compute Engine defense
- **VPC Service Controls dry run abuse** - Source: Google Cloud VPC Service Controls overview

### TA0006 - Credential Access
- **Browser cookie theft** - Source: BleepingComputer on phishing attacks
- **SSRF to metadata service** - Source: Multiple sources on SSRF attacks
- **Steal credentials from VM memory** - Source: GitLab on GCP post-exploitation
- **Extract from Cloud Source Repos** - Source: Help Net Security on repository exposure
- **Cloud Function token theft** - Source: Multiple sources on Cloud Build exploitation
- **Workload identity token extraction** - Source: mozillazg's Blog on Workload Identity
- **TPM key extraction** - Source: Assured AB on TPM abuse in GKE
- **DKIM signed email replay** - Source: Multiple sources on DKIM replay attacks

### TA0007 - Discovery
- **Enumerate Workspace groups** - Source: SANS on Google Workspace audit logs
- **Security Command Center enumeration** - Source: Google Cloud threat investigation
- **Attack path simulation discovery** - Source: Google Cloud attack exposure documentation

### TA0008 - Collection
- **Snapshot disk access** - Source: Google Cloud Blog on lateral movement prevention
- **Access shared drives** - Source: Strac on Google Workspace security
- **Clone VM disks via snapshots** - Source: Multiple sources on VM disk cloning
- **VM Serial Console access** - Source: Unit42 on serial console abuse

### TA0010 - Exfiltration
- **VPC Peering for lateral movement** - Source: Wiz Blog on VPC lateral movement
- **Storage Transfer Service abuse** - Source: Google Cloud VPC Service Controls
- **Abuse ingress/egress rules** - Source: VPC Service Controls documentation

### TA0011 - Impact
- **DDoS Attacks** - Source: Google Cloud on Rapid Reset DDoS
- **Rapid Reset DDoS** - Source: Google Cloud largest DDoS attack mitigation
- **VM disk encryption for ransom** - Source: Google Cloud Cybersecurity Forecast 2025

## Notes - To Do
- This matrix should be regularly updated as new techniques are discovered
- Procedures need to be added for each techniques with according blog post / resources / references
- Consider implementing detection and prevention controls for each documented TTP