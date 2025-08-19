# ARM-Enum&Abuse
Collection Tools for Enumeration and abuse Azure WebApp and Azure Key Vaults recources

These tools developed for help IT Administrators (not not realy..)...
These tools are developed for Red Teamers, whos secceded to find a high privileged Service Prinicpal with high permissions on ARM API.
you can use it:
- for data exflitration with Vaulter.ps1
- for lateral movment with WebApp-Shell.ps1
- for enumeration on WebApps with EnumWebApp.ps1

### Vaulter
this tool is checking if the key vault is manged by RBAC or by Access Policy, and abuse yout Ideneity's pemissions for adding:
- "Key Vault Administrator" role (RBAC), and adding your IP Addres to NetWork Rule.
- Adding your Object ID (of your Identity) (Access Policy), and adding your IP Addres to NetWork Rule.

```powershell
Import-Module Vaulter.ps1
```
```powershell
Vaulter
```
A file called 'kv_results.ndjson' will created, and all the data will be there
In the end of running, use Report-Builder.ps1 for create a beautiful report for you data baby

```powershell
Import-Module Report-Builder.ps1
```
```powershell
Import-Module Report-Builder -InputFile .\kv_results.ndjson
```
### WebApp-Shell
Enumerating all WebApp and trying to create an interactive shell (by using KUDU actions/api)

```powershell
Import-Module WebApp-Shell.ps1
```
```powershell
WebApp-Shell
```

### WebAppEnum
Enumerating all WebApp, and check if "/.env" file is exsit with public access
and more fuzzing stafffff

```powershell
Import-Module WebAppEnum.ps1
```
```powershell
WebAppEnum
```

Enter Service Principal Credentials:

<img width="706" height="553" alt="image" src="https://github.com/user-attachments/assets/2ddd2a6e-83a2-4a02-8026-eadb4c6f2c2a" />




