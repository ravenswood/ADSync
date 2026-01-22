This comprehensive documentation provides a deep technical analysis and operational guide for the **Sync-AD-Transport.ps1**  utility.

# ---

**Technical Specification: Sync-AD-Transport System**

## **1\. System Philosophy**

The **Sync-AD-Transport** script is a "Desired State" engine designed for high-assurance Active Directory environments. Unlike traditional synchronization tools that only perform incremental updates, this script enforces absolute parity between a source environment and a target environment. It treats the exported JSON state file as the "Source of Truth," meaning any object in the target environment not present in the source is considered obsolete and is purged.

## **2\. Core Architecture & Workflow**

The system operates in two distinct phases: **Export (State Capture)** and **Import (State Reconciliation)**.

### **Phase A: The Export Workflow**

In the source environment, the script executes the following logic:

1. **Identity Verification**: Authenticates with OpenBao using a local root\_token.  
2. **Cryptographic Initialization**: Checks for an RSA-4096 "transport-key" in the OpenBao Transit engine; if missing, it generates one and creates a protected backup.  
3. **Recursive Discovery**:  
   * Identifies all OUs under the $TargetOU.  
   * Collects Users and Groups, mapping their properties to LDAP attributes.  
4. **Secret Provisioning**: For any user without a stored secret, the script generates a 3-word BIP-39 compliant password (e.g., Apple\_Banana\_Cherry\_99\#).  
5. **Data Protection**: Encrypts the user passwords using the RSA-4096 public key.  
6. **Package Signing**: Serializes the data into JSON and generates a SHA2-256 HMAC to ensure the package cannot be modified during transit.

### **Phase B: The Import Workflow**

In the target environment, the script acts as a controller to converge the local AD state:

1. **Integrity Validation**: Verifies the HMAC signature against the JSON payload before any AD modifications occur.  
2. **Exclusion Filtering**: Strips out any objects belonging to OUs defined in the $OUExcludeFilters (e.g., Staging or Testing OUs).  
3. **Tiered Creation**:  
   * **OUs**: Recreates the folder hierarchy.  
   * **Groups**: Syncs group objects.  
   * **Users**: Creates or updates users, forcibly resetting passwords to match the source.  
4. **Membership Delta Sync**: Compares current group memberships against the JSON and performs additions or removals as needed.  
5. **Pruning**: Deletes obsolete Users, Groups, and OUs to ensure the target environment is "clean".

## ---

**3\. Data Schema & Security**

The script utilizes a specific mapping for AD objects to ensure consistency across different domain controllers.

### **LDAP Attribute Mapping**

| PowerShell Property | LDAP Attribute | Purpose |
| :---- | :---- | :---- |
| DisplayName | displayName | Full name for Global Address List (GAL). |
| EmailAddress | mail | Primary SMTP address. |
| GivenName | givenName | User's first name. |
| Surname | sn | User's last name. |
| Department | department | Organizational unit tagging. |

### **Security Guardrails**

* **Transit Key Backup**: The script generates a transport-key.backup file. Without this file, the target environment cannot decrypt user passwords, even with the root token.  
* **HMAC Signing**: Prevents unauthorized users from injecting malicious account data (e.g., creating a backdoor Admin account) into the transport file.  
* **Primary Group Protection**: The script specifically ignores the "Domain Users" group during membership reconciliation to prevent account lockouts or schema errors.

## ---

**4\. Troubleshooting & Operational Support**

### **Event Logging (Event ID 1000\)**

All operations are logged to the Windows Event Log under ADSync/ADSyncScript.

* **Information**: Normal CRUD (Create, Read, Update, Delete) operations.  
* **Warning**: Object deletions or removal of users from groups.  
* **Error**: Cryptographic failures, missing files, or AD permission issues.

### **Common Error Resolutions**

1. **HMAC Verification Failed**: Re-export the data. This usually indicates the JSON file was opened and saved in an editor that changed the file encoding (e.g., adding a Byte Order Mark).  
2. **Access Denied (AD)**: Ensure the account stored in secret/data/ad-admin has "Full Control" and "Delete Subtree" permissions on the $TargetOU.  
3. **Missing Transit Key**: If moving to a completely new OpenBao instance, you **must** have the transport-key.backup file to restore the cryptographic context.

