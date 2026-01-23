### **Prerequisites for Testing**

Before executing any test cases, the following environment conditions must be met:

* **Operating System:** Windows Server with the Active Directory Domain Services (AD DS) role and AD PowerShell module installed.  
* **Security Binary:** The bao.exe (OpenBao) binary must be placed in C:\\ADSync\\OpenBao.  
* **Dictionary File:** The bip39\_english.txt wordlist must be present in C:\\ADSync for password generation.  
* **Permissions:** Run PowerShell as **Administrator** with AD "Full Control" over the target OU.  
* **Network:** Connectivity to **127.0.0.1** on port **8200** must be unobstructed.

### ---

**Phase 1: Individual Component Testing**

#### **1\. Environment Initialization (Initialize-ADSyncEnvironment.ps1)**

**Goal:** Validate the filesystem, network rules, and core service registration.

* **TC-1.1: Directory Scaffolding**  
  * **Action:** Run .\\Initialize-ADSyncEnvironment.ps1.  
  * **Expected Result:** The following 8 directories must exist: C:\\ADSync\\OpenBao, C:\\ADSync\\OpenBao\\data, C:\\ADSync\\Sync, C:\\ADSync\\Export, C:\\ADSync\\Import, C:\\ADSync\\Logs, C:\\ADSync\\Users, and C:\\ADSync\\Bin.  
* **TC-1.2: Firewall Logic**  
  * **Action:** Run Get-NetFirewallRule \-DisplayName "ADSync\*".  
  * **Expected Result:** Confirm the following ports are open:  
    * **Inbound:** Port 22 (SSH/SFTP), Port 8200 (Vault API).  
    * **Outbound:** Port 389/636 (LDAP/S), Port 445 (SMB), Port 88 (Kerberos), Port 3268/3269 (Global Catalog).  
* **TC-1.3: Cryptographic Root**  
  * **Action:** Check for the output of the initialization.  
  * **Expected Result:** C:\\ADSync\\OpenBao\\vault\_keys.json must be created and contain exactly 1 root\_token and a valid array of unseal\_keys\_b64.

#### **2\. Vault Automation (Invoke-BaoAutomation.ps1)**

**Goal:** Test unsealing logic, engine provisioning, and secure credential ingestion.

* **TC-2.1: Automated Unseal**  
  * **Action:** Manually seal the vault using bao operator seal, then run .\\Invoke-BaoAutomation.ps1.  
  * **Expected Result:** Running bao status via CLI should return Sealed: false.  
* **TC-2.2: Secure Ingestion**  
  * **Action:** Create C:\\ADSync\\Sync\\ad\_creds\_temp.json with dummy creds; run the script.  
  * **Expected Result:** The ad\_creds\_temp.json file must be **deleted** automatically, and the credentials must be accessible within the Vault at secret/data/ad-admin.

#### **3\. AD Sync & Transport (Sync-AD-Transport.ps1)**

**Goal:** Validate the integrity of the export logic and the reconciliation engine.

* **TC-3.1: State Export**  
  * **Action:** Run the script with an empty Import folder.  
  * **Expected Result:** Confirm AD\_State\_Export.json and .hmac are generated in the Export folder.  
* **TC-3.2: Integrity Check (Negative Test)**  
  * **Action:** Move export files to the Import folder; manually edit the JSON content; run the script.  
  * **Expected Result:** The script must abort immediately with a **"HMAC Signature verification failed"** error.

### ---

**Phase 2: Collective Integration Testing**

**Objective:** Verify the end-to-end workflow from environment setup to final AD reconciliation.

* **Full Lifecycle Sync:** Run Initialize → Automation → Export → Import. **Expected Result:** System is configured, unsealed, and the target AD objects exactly match the source state.  
* **OU Hierarchy Sync:** Create a multi-level OU in the Source environment; perform a full sync. **Expected Result:** The entire nested OU tree structure is recreated in the Target OU with correct parentage.  
* **Destructive Sync:** Manually create an "Unauthorized OU" in the Target environment's root; run Import. **Expected Result:** The unauthorized OU is successfully **deleted** during the cleanup phase.  
* **Password Forced Drift:** Manually change a Target user password to a random value; run Import. **Expected Result:** The password is reset to the source value, and the user can log in with source credentials again.  
* **Membership Delta:** Add or remove a user from a group in the Source environment; run a sync. **Expected Result:** Group memberships in the Target AD are updated to mirror the Source exactly.

