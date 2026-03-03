; ============================================================================
; Inno Setup Script for Library Manager for Venus 6
; Version: 1.4.8
; ============================================================================

#define MyAppName "Library Manager for Venus 6"
#define MyAppVersion "1.4.8"
#define MyAppPublisher "Zachary Milot"
#define MyAppURL "https://github.com/zdmilot/Library-Manager-for-Venus-6"
#define MyAppExeName "Library Manager for Venus 6.exe"
#define MyAppIcon "LibraryManagerForVenus6.ico"

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputBaseFilename=LibraryManagerForVenus6_v{#MyAppVersion}_Setup
SetupIconFile={#MyAppIcon}
UninstallDisplayIcon={app}\{#MyAppIcon}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64
MinVersion=10.0
LicenseFile=
; Show the "Ready to Install" summary page
DisableReadyPage=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel2=This will install [name/ver] on your computer.%n%nLibrary Manager for Venus 6 provides a complete solution for managing Hamilton VENUS libraries, including importing, exporting, packaging, and version control.%n%nIt is recommended that you close all other applications before continuing.

; ============================================================================
; Custom Pages (Pascal Script tasks: Regulated Mode, Dark Mode, GitHub Links)
; ============================================================================

[Code]
var
  ConfigPage: TWizardPage;
  RegulatedCheckbox: TNewCheckBox;
  DarkModeCheckbox: TNewCheckBox;
  GithubLinksCheckbox: TNewCheckBox;
  RegulatedInfoLabel: TNewStaticText;
  IsRegulatedMode: Boolean;
  IsDarkMode: Boolean;
  IsGithubLinksHidden: Boolean;

procedure RegulatedCheckboxClick(Sender: TObject);
var
  Confirmed: Boolean;
begin
  if RegulatedCheckbox.Checked then
  begin
    Confirmed := (MsgBox(
      'Are you sure you want to enable Regulated Environment Mode?' + #13#10 + #13#10 +
      'Enabling this mode has the following consequences:' + #13#10 + #13#10 +
      '  - Only users in authorized Windows groups (Lab Method Programmer, ' + #13#10 +
      '    Lab Service) or Administrators can manage libraries' + #13#10 +
      '  - GitHub repository links will be disabled and cannot be re-enabled' + #13#10 +
      '  - Unsigned libraries will be disabled (all packages must be signed)' + #13#10 +
      '  - An audit log is maintained for all library operations' + #13#10 +
      '  - Import/export operations require authorized group membership' + #13#10 +
      '  - Action comments and signatures may be enforced' + #13#10 + #13#10 +
      'This mode is designed for GxP-regulated laboratory environments ' +
      'where strict access control and traceability are required.' + #13#10 + #13#10 +
      'Click Yes to enable Regulated Environment Mode, or No to leave it disabled.',
      mbConfirmation, MB_YESNO) = IDYES);
    if not Confirmed then
    begin
      RegulatedCheckbox.Checked := False;
    end
    else
    begin
      // Force GitHub links off when regulated mode is on
      GithubLinksCheckbox.Checked := False;
      GithubLinksCheckbox.Enabled := False;
      RegulatedInfoLabel.Caption :=
        'Regulated mode is ENABLED. GitHub links are disabled and unsigned ' +
        'libraries are not permitted. Only authorized Windows group members ' +
        'can manage libraries.';
      RegulatedInfoLabel.Font.Color := $000080; // Dark red
    end;
  end
  else
  begin
    GithubLinksCheckbox.Enabled := True;
    RegulatedInfoLabel.Caption :=
      'Regulated mode is disabled. All users can manage libraries freely.';
    RegulatedInfoLabel.Font.Color := clGray;
  end;
end;

procedure InitializeWizard();
var
  SectionLabel: TNewStaticText;
  DividerBevel: TBevel;
  DividerBevel2: TBevel;
begin
  // -----------------------------------------------------------------------
  // Custom configuration page
  // -----------------------------------------------------------------------
  ConfigPage := CreateCustomPage(
    wpSelectDir,
    'Application Configuration',
    'Choose the default settings for Library Manager for Venus 6.'
  );

  // === Section 1: Regulated Environment ===
  SectionLabel := TNewStaticText.Create(WizardForm);
  SectionLabel.Parent := ConfigPage.Surface;
  SectionLabel.Caption := 'Environment Mode';
  SectionLabel.Top := 4;
  SectionLabel.Left := 0;
  SectionLabel.Font.Style := [fsBold];
  SectionLabel.Font.Size := 9;

  RegulatedCheckbox := TNewCheckBox.Create(WizardForm);
  RegulatedCheckbox.Parent := ConfigPage.Surface;
  RegulatedCheckbox.Caption := 'Enable Regulated Environment Mode (GxP)';
  RegulatedCheckbox.Top := SectionLabel.Top + SectionLabel.Height + 8;
  RegulatedCheckbox.Left := 8;
  RegulatedCheckbox.Width := ConfigPage.SurfaceWidth - 16;
  RegulatedCheckbox.Checked := False;
  RegulatedCheckbox.OnClick := @RegulatedCheckboxClick;

  RegulatedInfoLabel := TNewStaticText.Create(WizardForm);
  RegulatedInfoLabel.Parent := ConfigPage.Surface;
  RegulatedInfoLabel.Caption :=
    'Regulated mode is disabled. All users can manage libraries freely.';
  RegulatedInfoLabel.Top := RegulatedCheckbox.Top + RegulatedCheckbox.Height + 4;
  RegulatedInfoLabel.Left := 24;
  RegulatedInfoLabel.Width := ConfigPage.SurfaceWidth - 32;
  RegulatedInfoLabel.WordWrap := True;
  RegulatedInfoLabel.Font.Color := clGray;
  RegulatedInfoLabel.Font.Size := 8;

  // --- Divider ---
  DividerBevel := TBevel.Create(WizardForm);
  DividerBevel.Parent := ConfigPage.Surface;
  DividerBevel.Top := RegulatedInfoLabel.Top + RegulatedInfoLabel.Height + 16;
  DividerBevel.Left := 0;
  DividerBevel.Width := ConfigPage.SurfaceWidth;
  DividerBevel.Height := 2;
  DividerBevel.Shape := bsBottomLine;

  // === Section 2: Appearance ===
  SectionLabel := TNewStaticText.Create(WizardForm);
  SectionLabel.Parent := ConfigPage.Surface;
  SectionLabel.Caption := 'Appearance';
  SectionLabel.Top := DividerBevel.Top + DividerBevel.Height + 12;
  SectionLabel.Left := 0;
  SectionLabel.Font.Style := [fsBold];
  SectionLabel.Font.Size := 9;

  DarkModeCheckbox := TNewCheckBox.Create(WizardForm);
  DarkModeCheckbox.Parent := ConfigPage.Surface;
  DarkModeCheckbox.Caption := 'Enable Dark Mode (Night theme)';
  DarkModeCheckbox.Top := SectionLabel.Top + SectionLabel.Height + 8;
  DarkModeCheckbox.Left := 8;
  DarkModeCheckbox.Width := ConfigPage.SurfaceWidth - 16;
  DarkModeCheckbox.Checked := False;

  // --- Divider ---
  DividerBevel2 := TBevel.Create(WizardForm);
  DividerBevel2.Parent := ConfigPage.Surface;
  DividerBevel2.Top := DarkModeCheckbox.Top + DarkModeCheckbox.Height + 16;
  DividerBevel2.Left := 0;
  DividerBevel2.Width := ConfigPage.SurfaceWidth;
  DividerBevel2.Height := 2;
  DividerBevel2.Shape := bsBottomLine;

  // === Section 3: GitHub Links ===
  SectionLabel := TNewStaticText.Create(WizardForm);
  SectionLabel.Parent := ConfigPage.Surface;
  SectionLabel.Caption := 'GitHub Integration';
  SectionLabel.Top := DividerBevel2.Top + DividerBevel2.Height + 12;
  SectionLabel.Left := 0;
  SectionLabel.Font.Style := [fsBold];
  SectionLabel.Font.Size := 9;

  GithubLinksCheckbox := TNewCheckBox.Create(WizardForm);
  GithubLinksCheckbox.Parent := ConfigPage.Surface;
  GithubLinksCheckbox.Caption := 'Show GitHub Repository Links';
  GithubLinksCheckbox.Top := SectionLabel.Top + SectionLabel.Height + 8;
  GithubLinksCheckbox.Left := 8;
  GithubLinksCheckbox.Width := ConfigPage.SurfaceWidth - 16;
  GithubLinksCheckbox.Checked := False;  // Hidden by default
end;

// -----------------------------------------------------------------------
// Update the "Ready to Install" memo with chosen configuration
// -----------------------------------------------------------------------
function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo,
  MemoTypeInfo, MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
var
  Memo: String;
begin
  Memo := '';

  if MemoDirInfo <> '' then
    Memo := Memo + MemoDirInfo + NewLine + NewLine;

  if MemoGroupInfo <> '' then
    Memo := Memo + MemoGroupInfo + NewLine + NewLine;

  // Application Configuration Summary
  Memo := Memo + 'Application Configuration:' + NewLine;
  Memo := Memo + Space + 'Regulated Environment Mode: ';
  if RegulatedCheckbox.Checked then
    Memo := Memo + 'Enabled (GxP)' + NewLine
  else
    Memo := Memo + 'Disabled' + NewLine;

  Memo := Memo + Space + 'Theme: ';
  if DarkModeCheckbox.Checked then
    Memo := Memo + 'Dark Mode (Night)' + NewLine
  else
    Memo := Memo + 'Light Mode (Day)' + NewLine;

  Memo := Memo + Space + 'GitHub Repository Links: ';
  if GithubLinksCheckbox.Checked then
    Memo := Memo + 'Visible' + NewLine
  else
    Memo := Memo + 'Hidden' + NewLine;

  if RegulatedCheckbox.Checked then
  begin
    Memo := Memo + NewLine;
    Memo := Memo + 'IMPORTANT - Regulated Environment Mode Consequences:' + NewLine;
    Memo := Memo + Space + '- Only authorized Windows group members can manage libraries' + NewLine;
    Memo := Memo + Space + '- GitHub links are disabled and cannot be re-enabled' + NewLine;
    Memo := Memo + Space + '- All packages must be signed (unsigned libraries disabled)' + NewLine;
    Memo := Memo + Space + '- Full audit log is maintained for all operations' + NewLine;
    Memo := Memo + Space + '- Import/export requires authorized group membership' + NewLine;
  end;

  Result := Memo;
end;

// -----------------------------------------------------------------------
// Write settings JSON after installation
// -----------------------------------------------------------------------
procedure WriteSettingsFile(const SettingsPath: String);
var
  Json: String;
  RegVal, DarkVal, GithubVal: String;
begin
  if RegulatedCheckbox.Checked then
    RegVal := 'true'
  else
    RegVal := 'false';

  if DarkModeCheckbox.Checked then
    DarkVal := 'true'
  else
    DarkVal := 'false';

  if GithubLinksCheckbox.Checked then
    GithubVal := 'true'
  else
    GithubVal := 'false';

  Json := '[{"_id":"0",' +
    '"recent-max":"20",' +
    '"chk_confirmBeforeInstall":true,' +
    '"chk_hideSystemLibraries":false,' +
    '"sysLibMetadataComplete":true,' +
    '"sysLibBackupComplete":true,' +
    '"windowMaximized":true,' +
    '"chk_includeUnsignedLibs":false,' +
    '"starred_libs":[],' +
    '"chk_requireActionComment":true,' +
    '"chk_requireActionSignature":false,' +
    '"chk_regulatedEnvironment":' + RegVal + ',' +
    '"chk_darkMode":' + DarkVal + ',' +
    '"chk_showGitHubLinks":' + GithubVal +
    '}]';

  // Ensure the parent directory exists (needed for the %LOCALAPPDATA% path)
  ForceDirectories(ExtractFileDir(SettingsPath));
  SaveStringToFile(SettingsPath, Json, False);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    // Write configured settings to the shared app-local data directory
    // and the bundled db/ reference copy.
    WriteSettingsFile(ExpandConstant('{app}\local\settings.json'));
    WriteSettingsFile(ExpandConstant('{app}\db\settings.json'));

    // Grant the Users group Modify permissions on the local data directory.
    // The [Dirs] section sets initial ACLs, but icacls ensures inheritance
    // propagates to all existing files and future subdirectories.
    Exec('icacls.exe',
      '"' + ExpandConstant('{app}\local') + '" /grant *S-1-5-32-545:(OI)(CI)M /T /Q',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Main NW.js executable
Source: "Library Manager for Venus 6.exe"; DestDir: "{app}"; Flags: ignoreversion

; Application icon
Source: "LibraryManagerForVenus6.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "LibraryManagerForVenus6.png"; DestDir: "{app}"; Flags: ignoreversion

; NW.js runtime DLLs and resources
Source: "nw.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "node.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "nw_elf.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "d3dcompiler_47.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "ffmpeg.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "libEGL.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "libGLESv2.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "nw_100_percent.pak"; DestDir: "{app}"; Flags: ignoreversion
Source: "nw_200_percent.pak"; DestDir: "{app}"; Flags: ignoreversion
Source: "resources.pak"; DestDir: "{app}"; Flags: ignoreversion
Source: "icudtl.dat"; DestDir: "{app}"; Flags: ignoreversion
Source: "natives_blob.bin"; DestDir: "{app}"; Flags: ignoreversion
Source: "v8_context_snapshot.bin"; DestDir: "{app}"; Flags: ignoreversion
Source: "notification_helper.exe"; DestDir: "{app}"; Flags: ignoreversion

; SwiftShader (software rendering fallback)
Source: "swiftshader\*"; DestDir: "{app}\swiftshader"; Flags: ignoreversion recursesubdirs

; Locales
Source: "locales\*"; DestDir: "{app}\locales"; Flags: ignoreversion recursesubdirs

; Application package manifest
Source: "package.json"; DestDir: "{app}"; Flags: ignoreversion

; CLI
Source: "cli.js"; DestDir: "{app}"; Flags: ignoreversion
Source: "cli-schema.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "cli-spec-example.json"; DestDir: "{app}"; Flags: ignoreversion

; Shared library module
Source: "lib\*"; DestDir: "{app}\lib"; Flags: ignoreversion recursesubdirs

; GUI (HTML/CSS/JS/images/fonts)
Source: "html\*"; DestDir: "{app}\html"; Flags: ignoreversion recursesubdirs

; Node.js modules (production dependencies)
Source: "node_modules\*"; DestDir: "{app}\node_modules"; Flags: ignoreversion recursesubdirs

; Asset images
Source: "assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs

; Application icons
Source: "icons\*"; DestDir: "{app}\icons"; Flags: ignoreversion recursesubdirs

; Database template files (initial state)
Source: "db\groups.json"; DestDir: "{app}\db"; Flags: ignoreversion
Source: "db\installed_libs.json"; DestDir: "{app}\db"; Flags: ignoreversion
Source: "db\links.json"; DestDir: "{app}\db"; Flags: ignoreversion
Source: "db\system_libraries.json"; DestDir: "{app}\db"; Flags: ignoreversion
Source: "db\system_library_hashes.json"; DestDir: "{app}\db"; Flags: ignoreversion
Source: "db\tree.json"; DestDir: "{app}\db"; Flags: ignoreversion
Source: "db\unsigned_libs.json"; DestDir: "{app}\db"; Flags: ignoreversion
; db\settings.json is written by the [Code] section post-install

; Local data directory deployed to {app}\local and shared across all users.
; The installer grants write permissions to the Users group via icacls
; so that non-admin users can read/write application data.
Source: "local\installed_libs.json"; DestDir: "{app}\local"; Flags: ignoreversion
Source: "local\groups.json"; DestDir: "{app}\local"; Flags: ignoreversion
Source: "local\settings.json"; DestDir: "{app}\local"; Flags: ignoreversion
Source: "local\tree.json"; DestDir: "{app}\local"; Flags: ignoreversion
Source: "local\links.json"; DestDir: "{app}\local"; Flags: ignoreversion
Source: "local\unsigned_libs.json"; DestDir: "{app}\local"; Flags: ignoreversion
Source: "local\publisher_registry.json"; DestDir: "{app}\local"; Flags: ignoreversion

; Help file
Source: "Library Manager for Venus 6.chm"; DestDir: "{app}"; Flags: ignoreversion

; README
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
; Local data directory with full write access for the Users group.
; This allows non-admin users to read/write shared application data
; within the Program Files install directory.
Name: "{app}\local"; Permissions: users-modify
Name: "{app}\local\packages"; Permissions: users-modify
Name: "{app}\local\exports"; Permissions: users-modify

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppIcon}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{commondesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppIcon}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
