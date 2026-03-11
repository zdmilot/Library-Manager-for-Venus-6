

   

Read [](file:///c%3A/Users/admin/Desktop/Library-Manager/installer.iss#1-1), lines 1 to 80

Read [](file:///c%3A/Users/admin/Desktop/Library-Manager/package.json#1-1), lines 1 to 40

Searched for regex `SignTool|signtool|codesign|Authenticode` (`**/installer.iss`), no results

There's no code signing configured yet. Here's how to sign the app and installer:

---

## Windows Authenticode Code Signing

This is separate from the Ed25519 *package* signing already in the app. Authenticode signs the **EXE/DLL/installer binaries** so Windows trusts them (no SmartScreen warnings, no "Unknown Publisher" dialogs).

### 1. Get a Code Signing Certificate

You have two options:

| Option | Cost | SmartScreen | Notes |
|--------|------|-------------|-------|
| **Standard OV (Organization Validation)** | ~$200-400/yr | Builds reputation gradually | From DigiCert, Sectigo, GlobalSign, etc. |
| **EV (Extended Validation)** | ~$300-600/yr | Immediate SmartScreen trust | Requires hardware token (USB) or cloud HSM; **recommended** |

Since 2023, all new code signing certs must be stored on a hardware token (FIPS 140-2 Level 2). Most CAs ship a USB token or offer cloud signing (e.g., DigiCert KeyLocker, SSL.com eSigner).

### 2. Sign the NW.js EXE

Sign the main application binary before packaging it into the installer:

```powershell
# Using Windows SDK signtool.exe
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 ^
  /n "Zachary Milot" ^
  "Library Manager.exe"
```

If using a hardware token (EV cert), `signtool` will prompt for the token PIN. For CI/CD, use the CA's cloud signing tools.

### 3. Sign the Installer

Add this to installer.iss in the `[Setup]` section:

```ini
[Setup]
; ... existing settings ...
SignTool=signtool /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /n "Zachary Milot" $f
SignedUninstaller=yes
```

Then register the sign tool name with Inno Setup (one-time, in Inno Setup IDE → Tools → Configure Sign Tools):
- **Name:** `signtool`
- **Command:** `"C:\Program Files (x86)\Windows Kits\10\bin\10.0.xxxxx.0\x64\signtool.exe" sign $p`

This tells Inno Setup to sign:
- The installer EXE output
- The embedded uninstaller EXE (via `SignedUninstaller=yes`)

### 4. Sign the COM DLL

Also sign the .NET COM interop DLL so `RegAsm` registration doesn't trigger warnings:

```powershell
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 ^
  /n "Zachary Milot" ^
  "com\VenusLibraryManager.dll"
```

### 5. Build Script (recommended)

Create a build script that signs everything in the right order:

```powershell
$cert = "Zachary Milot"
$ts = "http://timestamp.digicert.com"

# 1. Sign the main app EXE
signtool sign /fd SHA256 /tr $ts /td SHA256 /n $cert "Library Manager.exe"

# 2. Sign the COM DLL
signtool sign /fd SHA256 /tr $ts /td SHA256 /n $cert "com\VenusLibraryManager.dll"

# 3. Build the installer (Inno Setup signs it via SignTool directive)
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer.iss

# 4. Verify signatures
signtool verify /pa /v "Library Manager.exe"
signtool verify /pa /v "Output\LibraryManager_v1.9.13_Setup.exe"
```

### Key Points

- **Always timestamp** (`/tr` + `/td SHA256`) - without it, the signature expires when the certificate does
- **SHA-256** (`/fd SHA256`) - SHA-1 is deprecated and rejected by modern Windows
- Sign the EXE **before** packaging it into the installer
- EV certificates give **immediate** SmartScreen reputation (no "unknown publisher" warnings on first download)
- `signtool.exe` comes with the Windows SDK - install via Visual Studio Installer or standalone SDK