# Vaulter
Smart Tool for Enumerate and abuse Azure Key Vault

This tool was developed after we broke EntraID enviroment, and find strong Serivce Principal
for understanding what was his ability on Azure Resource API, I build this tool to enumeration Ket Vault Resources
and abuse RBAC or Access Policy for set my Identity permissions and exctracting data..

Simple use:
Import the tool on PowerShell Terminal:
```powershell
Import-Module Vaulter.ps1
```

Run:
```powershell
Vaulter
```

Enter Service Principal Credentials:

<img width="706" height="553" alt="image" src="https://github.com/user-attachments/assets/2ddd2a6e-83a2-4a02-8026-eadb4c6f2c2a" />



A file called 'kv_results.ndjson' will created, and all the data will be there
In the end of running, use Report-Builder.ps1 for create a beautiful report for you data baby

```powershell
Import-Module Report-Builder.ps1
```

```powershell
Import-Module Report-Builder -InputFile .\kv_results.ndjson
```
