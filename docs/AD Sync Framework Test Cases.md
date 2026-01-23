To ensure the reliability and security of the Active Directory (AD) synchronization framework, testing must be conducted in three distinct phases: **Individual Component Validation**, **Security/Secret Management**, and **Collective Lifecycle Integration**.

### **Prerequisites for Testing**

Before executing any test cases, the following environment conditions must be met:

* **Operating System:** Windows Server with the Active Directory Domain Services (AD DS) role and AD PowerShell module installed.  
* **Security Binary:** The bao.exe (OpenBao) binary must be placed in C:\\ADSync\\OpenBao.  
* **Dictionary File:** The bip39\_english.txt wordlist must be present in C:\\ADSync for password generation.  
* **Permissions:** The user executing the scripts must have local Administrator rights and AD "Full Control" over the target Organizational Unit (OU).  
* **Network:** Connectivity to the local loopback (**127.0.0.1**) on port **8200** must be unobstructed.

### ---

**Phase 1: Individual Component Testing**

#### **1\. Environment Initialization (Initialize-ADSyncEnvironment.ps1)**

**Goal:** Validate the filesystem, network rules, and core service registration.

* **TC-1.1: Directory Scaffolding**  
  * **Action:** Run the script on a fresh server.  
  * **Verification:** Confirm that C:\\ADSync and all 8 subdirectories (OpenBao, Export, Import, etc.) are created.  
* **TC-1.2: Firewall Logic**  
  * **Action:** Inspect Windows Advanced Firewall after execution.  
  * **Verification:** Confirm inbound/outbound rules for SSH (22), Vault (8200), and AD ports (LDAP/Kerberos) are active.  
* **TC-1.3: Cryptographic Root**  
  * **Action:** Check for the output of the initialization.  
  * **Verification:** Confirm C:\\ADSync\\OpenBao\\vault\_keys.json exists and contains valid JSON with root\_token and unseal\_keys\_b64.

#### **2\. Vault Automation (Invoke-BaoAutomation.ps1)**

**Goal:** Test unsealing logic, engine provisioning, and secure credential ingestion.

* **TC-2.1: Automated Unseal**  
  * **Action:** Manually seal the vault using bao operator seal, then run the script.  
  * **Verification:** Run bao status via CLI; verify Sealed is false.  
* **TC-2.2: Secure Ingestion**  
  * **Action:** Create a dummy ad\_creds\_temp.json with test credentials.  
  * **Verification:** Run the script and verify the file is deleted. Query the Vault API to ensure the data is present at secret/data/ad-admin.

#### **3\. AD Sync & Transport (Sync-AD-Transport.ps1)**

**Goal:** Validate the integrity of the export logic and the reconciliation engine.

* **TC-3.1: State Export**  
  * **Action:** Run the script with an empty Import folder.  
  * **Verification:** Confirm AD\_State\_Export.json and .hmac are generated in the Export folder.  
* **TC-3.2: Integrity Check (Negative Test)**  
  * **Action:** Move export files to the Import folder; manually edit the JSON content; run the script.  
  * **Verification:** The script must abort immediately with a "HMAC Signature verification failed" error.

### ---

**Phase 2: Collective Integration Testing**

**Objective:** Verify the end-to-end workflow from environment setup to final AD reconciliation.

| Test Case | Step-by-Step Action | Expected Result |
| :---- | :---- | :---- |
| **Full Lifecycle Sync** | Run Initialize → Automation → Export → Import. | System is configured, unsealed, and the target AD matches the source. |
| **OU Hierarchy Sync** | Create a multi-level OU in Source; sync to Target. | The entire tree structure is recreated in the Target OU. |
| **Destructive Sync** | Manually create an "Unauthorized OU" in Target; run Import. | The unauthorized OU is deleted during the cleanup phase. |
| **Password Forced Drift** | Change a user's password in Target AD manually; run Import. | The user's password is reset to the source value, and login is restored. |
| **Membership Delta** | Add/Remove a user from a group in Source; run sync. | Group memberships in Target are updated to mirror Source exactly. |

