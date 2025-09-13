# GCP & Workspace ATT&CK Matrix

This community based matrix main objective is to outlines a comprehensive list of Tactics, Techniques, and Procedures (TTPs) used by threat actor and applicable to Google Cloud Platform (GCP) and Google Workspace environments. 

It is a community-driven project designed to help security professionals, red teamers, and blue teamers understand and defend against threats in the Google Cloud ecosystem.
# GCP & Workspace ATT&CK Matrix

| Reconnaissance | Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Collection | Exfiltration | Impact |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Scan for Public Cloud Storage Buckets & Public VM Snapshots | | | | | | | | | | |
| Enumerate Google Groups for sensitive user congregations | | | | | | | | | | |
| OSINT: Search public code repositories for leaked credentials | | | | | | | | | | |
| OSINT: Analyze job postings & employee profiles for tech stack info | | | | | | | | | | |
| Analyze Certificate Transparency logs for subdomains and services | | | | | | | | | | |
| Probe Google login endpoints to validate employee email addresses | | | | | | | | | | |
| Discover public-facing Cloud Functions, Cloud Run, and App Engine services | | | | | | | | | | |
| Search for exposed GCP service hostnames in public datasets | | | | | | | | | | |
| | Leaked Service Account Keys | | | | | | | | | |
| | OAuth Device Code Phishing | | | | | | | | | |
| | Vulnerable Web Application on GCE/GKE (SSRF, RCE, SQLi) | | | | | | | | | |
| | Compromised Third-Party OAuth Application | | | | | | | | | |
| | Exposed VM with weak SSH/RDP credentials | | | | | | | | | |
| | Compromised CI/CD Pipeline credentials | | | | | | | | | |
| | GCP Marketplace Application with N-day vulnerability | | | | | | | | | |
| | Session Hijacking via stolen browser cookies | | | | | | | | | |
| | Supply Chain Attack via compromised container image | | | | | | | | | |
| | | Remote Code Execution via `gcloud compute ssh` | | | | | | | | |
| | | Injecting commands into VM `startup-script` metadata | | | | | | | | |
| | | Deploying a malicious Cloud Function or Cloud Run service | | | | | | | | |
| | | Triggering a malicious Cloud Build pipeline | | | | | | | | |
| | | Executing a job on a Dataflow or Dataproc cluster | | | | | | | | |
| | | Deploying a malicious container to a GKE cluster | | | | | | | | |
| | | Running commands interactively via the GCE Serial Console | | | | | | | | |
| | | Abusing Cloud Scheduler to trigger malicious functions | | | | | | | | |
| | | | Create new, long-lived keys for a Service Account | | | | | | | |
| | | | Add attacker-controlled principal to IAM policy | | | | | | | |
| | | | Modify a VM's metadata to add an attacker's SSH key | | | | | | | |
| | | | Create a malicious OAuth application in Workspace | | | | | | | |
| | | | Backdoor an Infrastructure-as-Code (IaC) template | | | | | | | |
| | | | Create a Cloud Build trigger that re-establishes access | | | | | | | |
| | | | Plant a malicious web shell on an App Engine application | | | | | | | |
| | | | | Abuse `iam.serviceAccounts.actAs` | | | | | | |
| | | | | Exploit broad permissions of a primitive role | | | | | | |
| | | | | Leverage the Compute Engine default service account | | | | | | |
| | | | | Exploit custom IAM role with `setIamPolicy` | | | | | | |
| | | | | Exploit custom IAM role with `iam.serviceAccountKeys.create` | | | | | | |
| | | | | Abuse `iam.roles.update` on a manageable custom role | | | | | | |
| | | | | Escalate from a compromised GKE pod to the node | | | | | | |
| | | | | Leverage a trusted Service Account from another project | | | | | | |
| | | | | | Disable or reconfigure Cloud Logging sinks | | | | | |
| | | | | | Disable or suppress Security Command Center findings | | | | | |
| | | | | | Use Google APIs to bypass VPC Service Controls | | | | | |
| | | | | | Stop or delete VM instances to remove evidence | | | | | |
| | | | | | Clear or modify command history in Cloud Shell | | | | | |
| | | | | | | Query the GCE metadata service for tokens | | | | |
| | | | | | | Access secrets stored in Secret Manager | | | | |
| | | | | | | Read credentials hardcoded in VM metadata | | | | |
| | | | | | | Extract Kubernetes secrets from a GKE cluster | | | | |
| | | | | | | Steal OAuth refresh/access tokens for Workspace | | | | |
| | | | | | | | Probe permissions with `iam.testIamPermissions` | | | |
| | | | | | | | List all IAM policies on Organization, Folders, and Projects | | | |
| | | | | | | | Enumerate all Cloud Storage buckets, VMs, and Databases | | | |