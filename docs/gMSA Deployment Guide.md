# **Deploying Sync-AD-Transport with gMSA**

Using a gMSA is the best practice for this sync script as it handles password rotation automatically and provides a non-interactive security context.

## **1\. Prerequisites**

* **Active Directory:** A KDS Root Key must exist in the forest (at least 10 hours old).  
* **Permissions:** The gMSA must have "Full Control" or "Read/Write/Create/Delete Child Objects" on the OU=RBAC,DC=jml,DC=local OU.  
* **Vault Access:** The gMSA does not need to know the Vault Token, but it must have Read/Write access to the C:\\ADSync directory to read the vault\_keys.json and export/import files.

## **2\. AD Object Permissions**

The gMSA needs specific delegation on the Target OU to perform CRUD operations:

1. Open **AD Users and Computers**.  
2. Right-click the **RBAC OU** \> **Delegate Control**.  
3. Add the gMSA (e.g., svc\_adsync$).  
4. Select **Create a custom task to delegate**.  
5. Select **This folder, existing objects... and creation of new objects**.  
6. Check **Full Control** (required for the Purge/Delete logic).

## **3\. Local Server Permissions**

The gMSA must be allowed to "Log on as a batch job" on the sync server.

1. Run secpol.msc.  
2. Go to **Local Policies** \> **User Rights Assignment**.  
3. Add the gMSA account to **Log on as a batch job**.

## **4\. Scheduled Task Parameters**

The task must be configured with these specific settings:

* **Run whether user is logged on or not**: Enabled.  
* **Do not store password**: Enabled (required for gMSA).  
* **Run with highest privileges**: Enabled.  
* **Program/script**: powershell.exe  
* **Arguments**: \-ExecutionPolicy Bypass \-File "C:\\ADSync\\Sync-AD-Transport.ps1"