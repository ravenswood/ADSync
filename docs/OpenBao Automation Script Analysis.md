This documentation provides a deep technical analysis and operational guide for the **Invoke-BaoAutomation.ps1** script. This script is the "Operational Orchestrator" responsible for maintaining the health and readiness of the OpenBao security vault after the initial environment has been established.

# ---

**Technical Specification: Vault Lifecycle & Automation**

## **1\. System Philosophy**

The **Invoke-BaoAutomation.ps1** script is designed to ensure "Zero-Touch" security operations. In a typical secure environment, a vault starts in a "Sealed" state—meaning its cryptographic keys are locked in memory and unavailable for use. This script automates the transition from a dormant service to a fully functional security provider, handling unsealing, engine provisioning, and the secure ingestion of administrative credentials.

## **2\. Core Architecture & Workflow**

The automation follows a logical sequence to move the vault from a protected state to an operational state:

### **Stage 1: Service Verification**

* **Resiliency Check**: The script verifies that the "OpenBao" Windows service is active.  
* **Auto-Correction**: If the service is stopped, it attempts an automatic restart and pauses to allow the API to become responsive.

### **Stage 2: Automated Unsealing**

Vaults are mathematically locked until an unseal key is provided.

* **Key Discovery**: The script parses vault\_keys.json to extract the Base64-encoded unseal keys.  
* **API Unseal**: It transmits the unseal key via a secure local API call to the /v1/sys/unseal endpoint. This process makes the vault's master key available in memory without human intervention.

### **Stage 3: Engine Provisioning (Infrastructure-as-Code)**

The script ensures the vault is "formatted" with the correct data structures required by the transport engine:

* **KV-V2 (Secret Engine)**: Enabled at /secret to store persistent data like AD Admin credentials and user passwords.  
* **Transit (Encryption Engine)**: Enabled at /transit to provide high-speed RSA-4096 encryption/decryption services for the sync process.

### **Stage 4: Secure Credential Ingestion & Purge**

This is a critical security step for initial setup:

* **Detection**: The script looks for a temporary plaintext file: ad\_creds\_temp.json.  
* **Vault Injection**: If found, it reads the AD Admin username and password, pushes them into the Vault's encrypted storage at secret/data/ad-admin, and confirms successful storage.  
* **Secure Deletion**: To prevent credential leakage, the script immediately performs a permanent deletion of the plaintext source file.

## ---

**3\. Configuration & Dependency Map**

| Component | Path/Value | Purpose |
| :---- | :---- | :---- |
| **Credential Source** | C:\\ADSync\\Sync\\ad\_creds\_temp.json | Temporary landing zone for AD Admin credentials. |
| **Vault Secret Path** | secret/data/ad-admin | The permanent, encrypted home for the sync admin account. |
| **Auth Token** | $Keys.root\_token | The master administrative token used to configure vault engines. |

## ---

**4\. Operational Troubleshooting**

### **Common Error Resolutions**

1. **"CRITICAL: vault\_keys.json missing"**: This indicates the environment initialization has not been run. You must run Initialize-ADSyncEnvironment.ps1 first to generate the master keys.  
2. **"NullArray" Indexing Errors**: Version 2.5 of this script was specifically updated to handle multiple JSON formats from different OpenBao versions (supporting both unseal\_keys\_b64 and keys\_base64 keys).  
3. **Failed Credential Ingestion**: If the ad\_creds\_temp.json file is present but ingestion fails, ensure the JSON is correctly formatted with "username" and "password" fields.

### **Best Practices**

* **Scheduled Task**: It is recommended to run this script as a Scheduled Task on system boot. This ensures that if the server reboots, the Vault unseals itself automatically, and the AD Sync remains operational.  
* **Cleanup Verification**: Always verify that the ad\_creds\_temp.json file has disappeared after the first run; its presence indicates the vault was not ready to receive the data.

