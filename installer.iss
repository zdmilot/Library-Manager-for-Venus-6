; ============================================================================
; Inno Setup Script for Library Manager
; Version: 2.98.83
; ============================================================================

#define MyAppName "Library Manager"
#define MyAppVersion "2.98.83"
#define MyAppPublisher "Zachary Milot"
#define MyAppURL "https://github.com/zdmilot/Library-Manager"
#define MyAppExeName "Library Manager.exe"
#define MyAppIcon "LibraryManager.ico"

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} v{#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputBaseFilename=LibraryManager_v{#MyAppVersion}_Setup
SetupIconFile={#MyAppIcon}
UninstallDisplayIcon={app}\{#MyAppIcon}
OutputDir=C:\Users\admin\Desktop
UninstallFilesDir={app}
WizardImageFile=WizardImage.bmp
WizardSmallImageFile=WizardSmallImage.bmp
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64
MinVersion=10.0
; LicenseFile is intentionally empty — the Terms of Use and Privacy Policy are
; displayed on a custom acceptance page (with checkbox) created in [Code] below,
; rather than using Inno Setup's built-in license page.
LicenseFile=
DisableWelcomePage=no
; Show the "Ready to Install" summary page
DisableReadyPage=no
; Notify Windows shell of file association changes
ChangesAssociations=yes
; Detect running instances via Windows Restart Manager (upgrade safety)
CloseApplications=yes
CloseApplicationsFilter=*.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel2=This will install [name/ver] on your computer.%n%nLibrary Manager provides a complete solution for managing Hamilton VENUS libraries, including importing, exporting, packaging, and version control.%n%nIt is recommended that you close all other applications before continuing.
; The upgrade welcome text is set dynamically in InitializeWizard.

; ============================================================================
; Custom Pages (Pascal Script tasks: Regulated Mode, Dark Mode)
; ============================================================================

[Code]
var
  ConfigPage: TWizardPage;
  RegulatedCheckbox: TNewCheckBox;
  DarkModeCheckbox: TNewCheckBox;
  RegulatedInfoLabel: TNewStaticText;
  IsRegulatedMode: Boolean;
  IsDarkMode: Boolean;
  TermsPage: TWizardPage;
  TermsMemo: TNewMemo;
  AcceptCheckbox: TNewCheckBox;
  RegulatedWarningPage: TWizardPage;
  RegulatedWarningMemo: TNewMemo;
  RegulatedAcceptCheckbox: TNewCheckBox;
  UninstallMode: Integer;
  gIsUpgrade: Boolean;
  gPreviousVersion: String;

// -----------------------------------------------------------------------
// Running-instance detection — blocks install while app is open
// -----------------------------------------------------------------------
function IsLibraryManagerRunning(): Boolean;
var
  ResultCode: Integer;
  TmpFile: String;
  Output: AnsiString;
begin
  Result := False;
  TmpFile := ExpandConstant('{tmp}\lm_proccheck.tmp');
  if Exec(ExpandConstant('{sys}\cmd.exe'),
    '/C tasklist /FI "IMAGENAME eq Library Manager.exe" /NH > "' + TmpFile + '" 2>&1',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    if LoadStringFromFile(TmpFile, Output) then
      Result := Pos('library manager.exe', Lowercase(String(Output))) > 0;
  end;
  DeleteFile(TmpFile);
end;

// -----------------------------------------------------------------------
// Upgrade detection — checks the Inno Setup uninstall registry key
// -----------------------------------------------------------------------
function DetectPreviousInstall(var PrevVersion: String): Boolean;
var
  UninstKey: String;
  DisplayVersion: String;
begin
  Result := False;
  PrevVersion := '';
  UninstKey := ExpandConstant('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{#SetupSetting("AppId")}_is1');
  if RegQueryStringValue(HKEY_LOCAL_MACHINE, UninstKey, 'DisplayVersion', DisplayVersion) then
  begin
    PrevVersion := DisplayVersion;
    Result := True;
  end;
end;

// -----------------------------------------------------------------------
// Hamilton VENUS 6+ prerequisite check
// -----------------------------------------------------------------------

{ Extract the major version number that follows "VENUS" in a DisplayName
  string.  Returns 0 when no version can be parsed. }
function ExtractVenusVersion(const DisplayName: String): Integer;
var
  P, I: Integer;
  UpName, VersionStr: String;
begin
  Result := 0;
  UpName := Uppercase(DisplayName);
  P := Pos('VENUS', UpName);
  if P = 0 then Exit;

  I := P + 5; { skip past "VENUS" }
  { skip whitespace }
  while (I <= Length(UpName)) and (UpName[I] = ' ') do
    I := I + 1;

  { read consecutive digits }
  VersionStr := '';
  while (I <= Length(UpName)) and (UpName[I] >= '0') and (UpName[I] <= '9') do
  begin
    VersionStr := VersionStr + UpName[I];
    I := I + 1;
  end;

  if VersionStr <> '' then
    Result := StrToIntDef(VersionStr, 0);
end;

{ Scan the Windows Uninstall registry for a "Hamilton VENUS <N>" entry
  where <N> >= 6.  Checks both native and WOW6432Node paths. }
function IsVenus6OrLaterInstalled(): Boolean;
var
  SubKeys: TArrayOfString;
  DisplayName: String;
  I, J, Ver: Integer;
  UninstallKey: String;
begin
  Result := False;

  for I := 0 to 1 do
  begin
    if I = 0 then
      UninstallKey := 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    else
      UninstallKey := 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall';

    if RegGetSubkeyNames(HKEY_LOCAL_MACHINE, UninstallKey, SubKeys) then
    begin
      for J := 0 to GetArrayLength(SubKeys) - 1 do
      begin
        if RegQueryStringValue(HKEY_LOCAL_MACHINE,
            UninstallKey + '\' + SubKeys[J], 'DisplayName', DisplayName) then
        begin
          Ver := ExtractVenusVersion(DisplayName);
          if Ver >= 6 then
          begin
            Result := True;
            Exit;
          end;
        end;
      end;
    end;
  end;
end;

{ InitializeSetup is called before the wizard is shown.  Returning False
  cancels the installation immediately. }
function InitializeSetup(): Boolean;
begin
  if not IsVenus6OrLaterInstalled() then
  begin
    MsgBox(
      'Hamilton VENUS version 6 or later is required to install ' +
      'Library Manager.' + #13#10 + #13#10 +
      'The installer could not detect a Hamilton VENUS 6 (or later) ' +
      'installation on this computer.' + #13#10 + #13#10 +
      'Please install Hamilton VENUS 6 or a newer version and then ' +
      'run this installer again.' + #13#10 + #13#10 +
      'Setup will now exit',
      mbCriticalError, MB_OK);
    Result := False;
  end
  else
  begin
    gIsUpgrade := DetectPreviousInstall(gPreviousVersion);

    // Block installation if Library Manager is currently running
    if IsLibraryManagerRunning() then
    begin
      if gIsUpgrade then
        MsgBox(
          'Library Manager is currently running.' + #13#10 + #13#10 +
          'You must close all instances of Library Manager before ' +
          'upgrading. Running the upgrade while Library Manager is ' +
          'open may cause data corruption or incomplete file ' +
          'replacement.' + #13#10 + #13#10 +
          'Please close Library Manager and run the installer again.' + #13#10 + #13#10 +
          'Setup will now exit.',
          mbCriticalError, MB_OK)
      else
        MsgBox(
          'Library Manager is currently running.' + #13#10 + #13#10 +
          'You must close all instances of Library Manager before ' +
          'installing. Please close Library Manager and run the ' +
          'installer again.' + #13#10 + #13#10 +
          'Setup will now exit.',
          mbCriticalError, MB_OK);
      Result := False;
      Exit;
    end;

    Result := True;
  end;
end;

// -----------------------------------------------------------------------

procedure AcceptCheckboxClick(Sender: TObject);
begin
  WizardForm.NextButton.Enabled := AcceptCheckbox.Checked;
end;

procedure RegulatedAcceptCheckboxClick(Sender: TObject);
begin
  WizardForm.NextButton.Enabled := RegulatedAcceptCheckbox.Checked;
end;

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
      '  - Unsigned libraries will be disabled (all packages must be signed)' + #13#10 +
      '  - An audit log is maintained for all library operations' + #13#10 +
      '  - Import/export operations require authorized group membership' + #13#10 +
      '  - Action comments and signatures may be enforced' + #13#10 + #13#10 +
      'This mode is designed for regulated laboratory environments ' +
      'where strict access control and traceability are required.' + #13#10 + #13#10 +
      'Click Yes to enable Regulated Environment Mode, or No to leave it disabled.',
      mbConfirmation, MB_YESNO) = IDYES);
    if not Confirmed then
    begin
      RegulatedCheckbox.Checked := False;
    end
    else
    begin
      RegulatedInfoLabel.Caption :=
        'Regulated mode is ENABLED. Unsigned ' +
        'libraries are not permitted. Only authorized Windows group members ' +
        'can manage libraries.';
      RegulatedInfoLabel.Font.Color := $000080; // Dark red
    end;
  end
  else
  begin
    RegulatedInfoLabel.Caption :=
      'Regulated mode is disabled. All users can manage libraries freely.';
    RegulatedInfoLabel.Font.Color := clGray;
    // Reset the disclaimer acceptance when regulated mode is unchecked
    RegulatedAcceptCheckbox.Checked := False;
  end;
end;

procedure InitializeWizard();
var
  SectionLabel: TNewStaticText;
  DividerBevel: TBevel;
  DividerBevel2: TBevel;
  TermsText, PrivacyText: AnsiString;
begin
  // ----- Dynamic welcome text for upgrades -----
  if gIsUpgrade then
  begin
    WizardForm.WelcomeLabel2.Caption :=
      'An existing installation of Library Manager (v' + gPreviousVersion +
      ') has been detected.' + #13#10 + #13#10 +
      'This will upgrade Library Manager to v{#MyAppVersion}.' + #13#10 + #13#10 +
      'Your library database, settings, audit trail, and all other user ' +
      'data will be preserved. Only application files will be updated.' + #13#10 + #13#10 +
      'You must close all running instances of Library Manager before ' +
      'continuing. The upgrade cannot proceed while Library Manager is open.';
  end;
  // -----------------------------------------------------------------------
  // Terms of Use and Privacy Policy acceptance page
  // -----------------------------------------------------------------------
  TermsPage := CreateCustomPage(
    wpWelcome,
    'Terms of Use and Privacy Policy',
    'Please read the following Terms of Use and Privacy Policy before continuing.'
  );

  TermsMemo := TNewMemo.Create(WizardForm);
  TermsMemo.Parent := TermsPage.Surface;
  TermsMemo.Left := 0;
  TermsMemo.Top := 0;
  TermsMemo.Width := TermsPage.SurfaceWidth;
  TermsMemo.Height := TermsPage.SurfaceHeight - ScaleY(30);
  TermsMemo.ScrollBars := ssVertical;
  TermsMemo.ReadOnly := True;
  TermsMemo.WordWrap := True;
  TermsMemo.TabStop := False;
  TermsMemo.Anchors := [akLeft, akTop, akRight, akBottom];

  ExtractTemporaryFile('TERMS_OF_USE.txt');
  ExtractTemporaryFile('PRIVACY_POLICY.txt');
  if LoadStringFromFile(ExpandConstant('{tmp}\TERMS_OF_USE.txt'), TermsText) and
     LoadStringFromFile(ExpandConstant('{tmp}\PRIVACY_POLICY.txt'), PrivacyText) then
  begin
    TermsMemo.Text := String(TermsText) + #13#10 + #13#10 +
      '════════════════════════════════════════════════════════' + #13#10 + #13#10 +
      String(PrivacyText);
  end;

  AcceptCheckbox := TNewCheckBox.Create(WizardForm);
  AcceptCheckbox.Parent := TermsPage.Surface;
  AcceptCheckbox.Caption := 'I accept the Terms of Use and Privacy Policy';
  AcceptCheckbox.Top := TermsMemo.Top + TermsMemo.Height + ScaleY(6);
  AcceptCheckbox.Left := 0;
  AcceptCheckbox.Width := TermsPage.SurfaceWidth;
  AcceptCheckbox.Anchors := [akLeft, akBottom, akRight];
  AcceptCheckbox.Checked := False;
  AcceptCheckbox.OnClick := @AcceptCheckboxClick;

  // -----------------------------------------------------------------------
  // Custom configuration page
  // -----------------------------------------------------------------------
  ConfigPage := CreateCustomPage(
    wpSelectDir,
    'Application Configuration',
    'Choose the default settings for Library Manager.'
  );

  // === Section 1: Appearance ===
  SectionLabel := TNewStaticText.Create(WizardForm);
  SectionLabel.Parent := ConfigPage.Surface;
  SectionLabel.Caption := 'Appearance';
  SectionLabel.Top := 4;
  SectionLabel.Left := 0;
  SectionLabel.Font.Style := [fsBold];
  SectionLabel.Font.Size := 9;

  DarkModeCheckbox := TNewCheckBox.Create(WizardForm);
  DarkModeCheckbox.Parent := ConfigPage.Surface;
  DarkModeCheckbox.Caption := 'Always use dark mode (otherwise follows system setting)';
  DarkModeCheckbox.Top := SectionLabel.Top + SectionLabel.Height + 8;
  DarkModeCheckbox.Left := 8;
  DarkModeCheckbox.Width := ConfigPage.SurfaceWidth - 16;
  DarkModeCheckbox.Checked := False;

  // --- Divider ---
  DividerBevel := TBevel.Create(WizardForm);
  DividerBevel.Parent := ConfigPage.Surface;
  DividerBevel.Top := DarkModeCheckbox.Top + DarkModeCheckbox.Height + 16;
  DividerBevel.Left := 0;
  DividerBevel.Width := ConfigPage.SurfaceWidth;
  DividerBevel.Height := 2;
  DividerBevel.Shape := bsBottomLine;

  // === Section 2: Regulated Environment Mode ===
  SectionLabel := TNewStaticText.Create(WizardForm);
  SectionLabel.Parent := ConfigPage.Surface;
  SectionLabel.Caption := 'Regulated Environment Mode';
  SectionLabel.Top := DividerBevel.Top + DividerBevel.Height + 12;
  SectionLabel.Left := 0;
  SectionLabel.Font.Style := [fsBold];
  SectionLabel.Font.Size := 9;

  RegulatedCheckbox := TNewCheckBox.Create(WizardForm);
  RegulatedCheckbox.Parent := ConfigPage.Surface;
  RegulatedCheckbox.Caption := 'Enable Regulated Environment Mode';
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

  // -----------------------------------------------------------------------
  // Regulated Environment Warning page (shown only when regulated mode is selected)
  // -----------------------------------------------------------------------
  RegulatedWarningPage := CreateCustomPage(
    ConfigPage.ID,
    'Regulated Environment Mode Disclaimer',
    'Please read the following important disclaimer before continuing.'
  );

  RegulatedWarningMemo := TNewMemo.Create(WizardForm);
  RegulatedWarningMemo.Parent := RegulatedWarningPage.Surface;
  RegulatedWarningMemo.Left := 0;
  RegulatedWarningMemo.Top := 0;
  RegulatedWarningMemo.Width := RegulatedWarningPage.SurfaceWidth;
  RegulatedWarningMemo.Height := RegulatedWarningPage.SurfaceHeight - ScaleY(30);
  RegulatedWarningMemo.ScrollBars := ssVertical;
  RegulatedWarningMemo.ReadOnly := True;
  RegulatedWarningMemo.WordWrap := True;
  RegulatedWarningMemo.TabStop := False;
  RegulatedWarningMemo.Anchors := [akLeft, akTop, akRight, akBottom];
  RegulatedWarningMemo.Text :=
    'IMPORTANT DISCLAIMER' + #13#10 +
    '════════════════════════════════════════════════' + #13#10 + #13#10 +
    'You have selected Regulated Environment Mode.' + #13#10 + #13#10 +
    'If the App provides a "regulated environment mode," it is provided as an ' +
    'optional feature intended to help reduce certain operational risks (for ' +
    'example, by disabling optional behaviors). Regulated environment mode does ' +
    'not guarantee compliance with any law, regulation, guidance, or internal ' +
    'policy, and does not replace required validation/qualification, documentation, ' +
    'change control, audit readiness, or security controls in your environment.' + #13#10 + #13#10 +
    'The developer makes no warranties or representations regarding regulated use, ' +
    'and assumes no liability arising from reliance on or use of regulated ' +
    'environment mode.' + #13#10 + #13#10 +
    '════════════════════════════════════════════════' + #13#10 + #13#10 +
    'By clicking Next, you acknowledge that you have read and understood this ' +
    'disclaimer and that enabling regulated environment mode does not constitute ' +
    'compliance with any regulatory requirements.';

  RegulatedAcceptCheckbox := TNewCheckBox.Create(WizardForm);
  RegulatedAcceptCheckbox.Parent := RegulatedWarningPage.Surface;
  RegulatedAcceptCheckbox.Caption := 'I have read and accept the regulated environment mode disclaimer';
  RegulatedAcceptCheckbox.Top := RegulatedWarningMemo.Top + RegulatedWarningMemo.Height + ScaleY(6);
  RegulatedAcceptCheckbox.Left := 0;
  RegulatedAcceptCheckbox.Width := RegulatedWarningPage.SurfaceWidth;
  RegulatedAcceptCheckbox.Anchors := [akLeft, akBottom, akRight];
  RegulatedAcceptCheckbox.Checked := False;
  RegulatedAcceptCheckbox.OnClick := @RegulatedAcceptCheckboxClick;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = TermsPage.ID then
    WizardForm.NextButton.Enabled := AcceptCheckbox.Checked
  else if CurPageID = RegulatedWarningPage.ID then
    WizardForm.NextButton.Enabled := RegulatedAcceptCheckbox.Checked
  else
    WizardForm.NextButton.Enabled := True;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;

  // On upgrade, skip Terms, Configuration, and Regulated Warning pages
  // — user data and settings are preserved from the previous install.
  if gIsUpgrade then
  begin
    if (PageID = TermsPage.ID) or
       (PageID = ConfigPage.ID) or
       (PageID = RegulatedWarningPage.ID) then
    begin
      Result := True;
      Exit;
    end;
  end;

  // Skip the regulated warning page if regulated mode is not selected
  if PageID = RegulatedWarningPage.ID then
    Result := not RegulatedCheckbox.Checked;
end;

// -----------------------------------------------------------------------
// PrepareToInstall — last-chance gate before file extraction.
// If the user opened Library Manager after the wizard started,
// this catches it and blocks the install.
// -----------------------------------------------------------------------
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if IsLibraryManagerRunning() then
  begin
    NeedsRestart := False;
    if gIsUpgrade then
      Result := 'Library Manager is currently running. You must close ' +
        'all instances of Library Manager before upgrading. Running the ' +
        'upgrade while the application is open may cause data corruption ' +
        'or incomplete file replacement.'
    else
      Result := 'Library Manager is currently running. Please close all ' +
        'instances of Library Manager before continuing with the ' +
        'installation.';
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = TermsPage.ID then
  begin
    if not AcceptCheckbox.Checked then
    begin
      MsgBox('You must accept the Terms of Use and Privacy Policy to continue.',
        mbError, MB_OK);
      Result := False;
    end;
  end;
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

  if gIsUpgrade then
  begin
    Memo := Memo + 'Upgrade:' + NewLine;
    Memo := Memo + Space + 'Previous version: v' + gPreviousVersion + NewLine;
    Memo := Memo + Space + 'New version: v{#MyAppVersion}' + NewLine + NewLine;
    Memo := Memo + 'Preserved Data:' + NewLine;
    Memo := Memo + Space + '- Library database and installed libraries' + NewLine;
    Memo := Memo + Space + '- Application settings and configuration' + NewLine;
    Memo := Memo + Space + '- Audit trail and event history' + NewLine;
    Memo := Memo + Space + '- Package archives and exports' + NewLine;
    Memo := Memo + Space + '- Publisher registry and signing keys' + NewLine + NewLine;
    if MemoDirInfo <> '' then
      Memo := Memo + MemoDirInfo + NewLine + NewLine;
    Result := Memo;
    Exit;
  end;

  if MemoDirInfo <> '' then
    Memo := Memo + MemoDirInfo + NewLine + NewLine;

  if MemoGroupInfo <> '' then
    Memo := Memo + MemoGroupInfo + NewLine + NewLine;

  // Application Configuration Summary
  Memo := Memo + 'Application Configuration:' + NewLine;
  Memo := Memo + Space + 'Regulated Environment Mode: ';
  if RegulatedCheckbox.Checked then
    Memo := Memo + 'Enabled' + NewLine
  else
    Memo := Memo + 'Disabled' + NewLine;

  Memo := Memo + Space + 'Theme: ';
  if DarkModeCheckbox.Checked then
    Memo := Memo + 'Always Dark Mode' + NewLine
  else
    Memo := Memo + 'Use System Setting' + NewLine;

  if RegulatedCheckbox.Checked then
  begin
    Memo := Memo + NewLine;
    Memo := Memo + 'IMPORTANT - Regulated Environment Mode Consequences:' + NewLine;
    Memo := Memo + Space + '- Only authorized Windows group members can manage libraries' + NewLine;
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
  RegVal, DarkVal: String;
begin
  if RegulatedCheckbox.Checked then
    RegVal := 'true'
  else
    RegVal := 'false';

  if DarkModeCheckbox.Checked then
    DarkVal := 'dark'
  else
    DarkVal := 'system';

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
    '"themeMode":"' + DarkVal + '",' +
    '"chk_showGitHubLinks":false' +
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
    // On upgrade, preserve existing settings — only write on fresh install.
    // Also guard against the case where the registry key is missing but data
    // folders still exist from a previous installation (e.g. manual uninstall
    // or registry cleanup).  Never overwrite existing settings files.
    if not gIsUpgrade then
    begin
      if not FileExists(ExpandConstant('{app}\local\settings.json')) then
        WriteSettingsFile(ExpandConstant('{app}\local\settings.json'));
      if not FileExists(ExpandConstant('{app}\db\settings.json')) then
        WriteSettingsFile(ExpandConstant('{app}\db\settings.json'));
    end;

    // Grant the Users group Modify permissions on the local data directory.
    // The [Dirs] section sets initial ACLs, but icacls ensures inheritance
    // propagates to all existing files and future subdirectories.
    Exec('icacls.exe',
      '"' + ExpandConstant('{app}\local') + '" /grant *S-1-5-32-545:(OI)(CI)M /T /Q',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

    // Rename the default uninstaller to a friendly name
    if FileExists(ExpandConstant('{app}\unins000.exe')) then
    begin
      RenameFile(ExpandConstant('{app}\unins000.exe'), ExpandConstant('{app}\Uninstall Library Manager.exe'));
      RenameFile(ExpandConstant('{app}\unins000.dat'), ExpandConstant('{app}\Uninstall Library Manager.dat'));
      RegWriteStringValue(HKEY_LOCAL_MACHINE,
        ExpandConstant('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{#SetupSetting("AppId")}_is1'),
        'UninstallString', '"' + ExpandConstant('{app}\Uninstall Library Manager.exe') + '"');
      RegWriteStringValue(HKEY_LOCAL_MACHINE,
        ExpandConstant('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{#SetupSetting("AppId")}_is1'),
        'QuietUninstallString', '"' + ExpandConstant('{app}\Uninstall Library Manager.exe') + '" /SILENT');
    end;
  end;
end;

// =========================================================================
// UNINSTALLER - Three-tier removal
// =========================================================================
//   Tier 1 - Application Only: removes binaries/UI; keeps all user data.
//   Tier 2 - Standard: also removes settings; keeps packages, audit log,
//            exports, and verification hashes.
//   Tier 3 - Full Removal: deletes everything under {app}.
// =========================================================================

function InitializeUninstall(): Boolean;
var
  Form: TSetupForm;
  OKButton, CancelButton: TNewButton;
  RadioAppOnly, RadioStandard, RadioFull: TNewRadioButton;
  HeaderLabel, Desc1, Desc2, Desc3: TNewStaticText;
  Bevel1, Bevel2: TBevel;
begin
  Result := False;
  UninstallMode := 1;

  Form := CreateCustomForm();
  try
    Form.ClientWidth := ScaleX(510);
    Form.ClientHeight := ScaleY(400);
    Form.Caption := 'Uninstall - Select Removal Mode';
    Form.Position := poScreenCenter;

    // --- Header ---
    HeaderLabel := TNewStaticText.Create(Form);
    HeaderLabel.Parent := Form;
    HeaderLabel.Left := ScaleX(16);
    HeaderLabel.Top := ScaleY(12);
    HeaderLabel.Width := Form.ClientWidth - ScaleX(32);
    HeaderLabel.WordWrap := True;
    HeaderLabel.Caption := 'Choose how much data to remove along with the application:';
    HeaderLabel.Font.Style := [fsBold];
    HeaderLabel.Font.Size := 9;

    // --- Option 1: Application Only ---
    RadioAppOnly := TNewRadioButton.Create(Form);
    RadioAppOnly.Parent := Form;
    RadioAppOnly.Left := ScaleX(20);
    RadioAppOnly.Top := HeaderLabel.Top + HeaderLabel.Height + ScaleY(16);
    RadioAppOnly.Width := Form.ClientWidth - ScaleX(40);
    RadioAppOnly.Caption := 'Application Only  (least destructive)';
    RadioAppOnly.Checked := True;
    RadioAppOnly.Font.Style := [fsBold];

    Desc1 := TNewStaticText.Create(Form);
    Desc1.Parent := Form;
    Desc1.Left := ScaleX(38);
    Desc1.Top := RadioAppOnly.Top + RadioAppOnly.Height + ScaleY(2);
    Desc1.Width := Form.ClientWidth - ScaleX(54);
    Desc1.WordWrap := True;
    Desc1.Caption :=
      'Removes only the core application files (EXE, DLLs, dependencies, ' +
      'UI assets). Keeps all user data, including package archives and ' +
      'application settings, so the app can be reinstalled without losing anything.';
    Desc1.Font.Color := clGray;
    Desc1.Font.Size := 8;

    // --- Divider 1 ---
    Bevel1 := TBevel.Create(Form);
    Bevel1.Parent := Form;
    Bevel1.Left := ScaleX(16);
    Bevel1.Top := Desc1.Top + Desc1.Height + ScaleY(10);
    Bevel1.Width := Form.ClientWidth - ScaleX(32);
    Bevel1.Height := 2;
    Bevel1.Shape := bsBottomLine;

    // --- Option 2: Standard ---
    RadioStandard := TNewRadioButton.Create(Form);
    RadioStandard.Parent := Form;
    RadioStandard.Left := ScaleX(20);
    RadioStandard.Top := Bevel1.Top + Bevel1.Height + ScaleY(10);
    RadioStandard.Width := Form.ClientWidth - ScaleX(40);
    RadioStandard.Caption := 'Standard';
    RadioStandard.Font.Style := [fsBold];

    Desc2 := TNewStaticText.Create(Form);
    Desc2.Parent := Form;
    Desc2.Left := ScaleX(38);
    Desc2.Top := RadioStandard.Top + RadioStandard.Height + ScaleY(2);
    Desc2.Width := Form.ClientWidth - ScaleX(54);
    Desc2.WordWrap := True;
    Desc2.Caption :=
      'Removes the application files and deletes application settings/' +
      'configuration. Keeps package archives, audit logs/history, and ' +
      'file verification data (hashes) required to validate retained ' +
      'archives and logs.';
    Desc2.Font.Color := clGray;
    Desc2.Font.Size := 8;

    // --- Divider 2 ---
    Bevel2 := TBevel.Create(Form);
    Bevel2.Parent := Form;
    Bevel2.Left := ScaleX(16);
    Bevel2.Top := Desc2.Top + Desc2.Height + ScaleY(10);
    Bevel2.Width := Form.ClientWidth - ScaleX(32);
    Bevel2.Height := 2;
    Bevel2.Shape := bsBottomLine;

    // --- Option 3: Full Removal ---
    RadioFull := TNewRadioButton.Create(Form);
    RadioFull.Parent := Form;
    RadioFull.Left := ScaleX(20);
    RadioFull.Top := Bevel2.Top + Bevel2.Height + ScaleY(10);
    RadioFull.Width := Form.ClientWidth - ScaleX(40);
    RadioFull.Caption := 'Full Removal  (most destructive)';
    RadioFull.Font.Style := [fsBold];

    Desc3 := TNewStaticText.Create(Form);
    Desc3.Parent := Form;
    Desc3.Left := ScaleX(38);
    Desc3.Top := RadioFull.Top + RadioFull.Height + ScaleY(2);
    Desc3.Width := Form.ClientWidth - ScaleX(54);
    Desc3.WordWrap := True;
    Desc3.Caption :=
      'WARNING: Destructive action. Removes the application and ALL ' +
      'associated data, including audit files, event history, package ' +
      'archives, backups, and verification data. Libraries already ' +
      'installed in external VENUS directories will not be affected.';
    Desc3.Font.Color := $000080;  // Dark red (BGR format)
    Desc3.Font.Size := 8;

    // --- Buttons ---
    CancelButton := TNewButton.Create(Form);
    CancelButton.Parent := Form;
    CancelButton.Width := ScaleX(80);
    CancelButton.Height := ScaleY(26);
    CancelButton.Left := Form.ClientWidth - CancelButton.Width - ScaleX(16);
    CancelButton.Top := Form.ClientHeight - CancelButton.Height - ScaleY(12);
    CancelButton.Caption := 'Cancel';
    CancelButton.ModalResult := mrCancel;
    CancelButton.Cancel := True;

    OKButton := TNewButton.Create(Form);
    OKButton.Parent := Form;
    OKButton.Width := ScaleX(80);
    OKButton.Height := ScaleY(26);
    OKButton.Left := CancelButton.Left - OKButton.Width - ScaleX(8);
    OKButton.Top := CancelButton.Top;
    OKButton.Caption := 'Uninstall';
    OKButton.ModalResult := mrOK;
    OKButton.Default := True;

    Form.ActiveControl := OKButton;

    if Form.ShowModal() = mrOK then
    begin
      if RadioFull.Checked then
      begin
        // Extra confirmation for destructive full removal
        if MsgBox(
          'Are you sure you want to perform a FULL removal?' + #13#10 + #13#10 +
          'This will permanently delete:' + #13#10 +
          '  - All audit files and event history' + #13#10 +
          '  - All archived library packages' + #13#10 +
          '  - All backups and verification data' + #13#10 + #13#10 +
          'This action cannot be undone.',
          mbConfirmation, MB_YESNO) = IDYES then
        begin
          UninstallMode := 3;
          Result := True;
        end;
      end
      else if RadioStandard.Checked then
      begin
        UninstallMode := 2;
        Result := True;
      end
      else
      begin
        UninstallMode := 1;
        Result := True;
      end;
    end;
  finally
    Form.Free();
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  AppDir: String;
begin
  if CurUninstallStep <> usPostUninstall then
    Exit;

  AppDir := ExpandConstant('{app}');

  case UninstallMode of
    // -- Tier 1: Application Only ----------------------------------------
    // The built-in uninstaller already removed tracked app files.
    // All local/ and db/ data is preserved (uninsneveruninstall flag).
    1:
    begin
      // Nothing extra to do - data stays for a future reinstall.
    end;

    // -- Tier 2: Standard ------------------------------------------------
    // Remove settings & configuration; keep packages, audit, hashes.
    2:
    begin
      // --- local/ settings & config ---
      DeleteFile(AppDir + '\local\settings.json');
      DeleteFile(AppDir + '\local\installed_libs.json');
      DeleteFile(AppDir + '\local\groups.json');
      DeleteFile(AppDir + '\local\tree.json');
      DeleteFile(AppDir + '\local\links.json');
      DeleteFile(AppDir + '\local\unsigned_libs.json');
      DeleteFile(AppDir + '\local\publisher_registry.json');

      // --- db/ settings & config ---
      // Keep system_library_hashes.json and system_libraries.json
      // (verification data required to validate retained archives/logs).
      DeleteFile(AppDir + '\db\settings.json');
      DeleteFile(AppDir + '\db\installed_libs.json');
      DeleteFile(AppDir + '\db\groups.json');
      DeleteFile(AppDir + '\db\tree.json');
      DeleteFile(AppDir + '\db\links.json');
      DeleteFile(AppDir + '\db\unsigned_libs.json');

      // Remove db/ only if it is now empty (hashes/system_libraries remain)
      RemoveDir(AppDir + '\db');
      // local/ intentionally kept (packages/, exports/, installers/, audit_trail.json)
    end;

    // -- Tier 3: Full Removal --------------------------------------------
    // Nuke every remaining file under {app}.
    3:
    begin
      DelTree(AppDir + '\local', True, True, True);
      DelTree(AppDir + '\db', True, True, True);
      // Attempt to remove the now-empty install directory
      RemoveDir(AppDir);
    end;
  end;
end;

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Main NW.js executable
Source: "Library Manager.exe"; DestDir: "{app}"; Flags: ignoreversion

; Application icon
Source: "LibraryManager.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "LibraryManager.png"; DestDir: "{app}"; Flags: ignoreversion

; File type association icon (greyscale - separate from internal app icons)
Source: "hxlib_filetype.ico"; DestDir: "{app}"; Flags: ignoreversion

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

; COM Bridge (stdin/stdout dispatcher for COM object)
Source: "com-bridge.js"; DestDir: "{app}"; Flags: ignoreversion
Source: "cli-schema.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "cli-spec-example.json"; DestDir: "{app}"; Flags: ignoreversion

; COM object (32-bit DLL for VENUS x86 interop)
Source: "com\bin\VenusLibraryManager.dll"; DestDir: "{app}\com"; Flags: ignoreversion
Source: "com\register-com.bat"; DestDir: "{app}\com"; Flags: ignoreversion
Source: "com\unregister-com.bat"; DestDir: "{app}\com"; Flags: ignoreversion
Source: "com\verify-com.bat"; DestDir: "{app}\com"; Flags: ignoreversion

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
; onlyifdoesntexist — never overwrite existing data on upgrade.
; uninsneveruninstall — three-tier uninstaller controls removal.
Source: "db\groups.json"; DestDir: "{app}\db"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "db\installed_libs.json"; DestDir: "{app}\db"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "db\links.json"; DestDir: "{app}\db"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "db\system_libraries.json"; DestDir: "{app}\db"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "db\system_library_hashes.json"; DestDir: "{app}\db"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "db\tree.json"; DestDir: "{app}\db"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "db\unsigned_libs.json"; DestDir: "{app}\db"; Flags: onlyifdoesntexist uninsneveruninstall
; db\settings.json is written by the [Code] section post-install (fresh only)

; Local data directory deployed to {app}\local and shared across all users.
; onlyifdoesntexist — never overwrite existing user data on upgrade.
; uninsneveruninstall — three-tier uninstaller controls removal.
Source: "local\installed_libs.json"; DestDir: "{app}\local"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "local\groups.json"; DestDir: "{app}\local"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "local\settings.json"; DestDir: "{app}\local"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "local\tree.json"; DestDir: "{app}\local"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "local\links.json"; DestDir: "{app}\local"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "local\unsigned_libs.json"; DestDir: "{app}\local"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "local\publisher_registry.json"; DestDir: "{app}\local"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "local\audit_trail.json"; DestDir: "{app}\local"; Flags: onlyifdoesntexist uninsneveruninstall

; Help file
Source: "Library Manager.chm"; DestDir: "{app}"; Flags: ignoreversion

; README
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion

; Legal
Source: "LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "NOTICE"; DestDir: "{app}"; Flags: ignoreversion
Source: "PRIVACY_POLICY.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "TERMS_OF_USE.txt"; DestDir: "{app}"; Flags: ignoreversion

; Legal (temp copies for installer terms acceptance page)
Source: "TERMS_OF_USE.txt"; Flags: dontcopy
Source: "PRIVACY_POLICY.txt"; Flags: dontcopy

[Dirs]
; Local data directory with full write access for the Users group.
; This allows non-admin users to read/write shared application data
; within the Program Files install directory.
Name: "{app}\local"; Permissions: users-modify
Name: "{app}\local\packages"; Permissions: users-modify
Name: "{app}\local\exports"; Permissions: users-modify
Name: "{app}\local\installers"; Permissions: users-modify

[Registry]
; --------------------------------------------------------------------------
; File type associations for .hxlibpkg and .hxlibarch
; Uses the greyscale icon (hxlib_filetype.ico) which is intentionally
; separate from the coloured icons used inside the application UI.
; --------------------------------------------------------------------------
; .hxlibpkg  ->  HxLibPkg file type
Root: HKLM; Subkey: "Software\Classes\.hxlibpkg"; ValueType: string; ValueName: ""; ValueData: "HxLibPkg"; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Classes\HxLibPkg"; ValueType: string; ValueName: ""; ValueData: "Library Package"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\HxLibPkg\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\hxlib_filetype.ico,0"
Root: HKLM; Subkey: "Software\Classes\HxLibPkg\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""

; .hxlibarch  ->  HxLibArch file type
Root: HKLM; Subkey: "Software\Classes\.hxlibarch"; ValueType: string; ValueName: ""; ValueData: "HxLibArch"; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Classes\HxLibArch"; ValueType: string; ValueName: ""; ValueData: "Library Archive"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\HxLibArch\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\hxlib_filetype.ico,0"
Root: HKLM; Subkey: "Software\Classes\HxLibArch\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppIcon}"
Name: "{commondesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppIcon}"; Tasks: desktopicon

[Run]
; Register COM DLL with 32-bit RegAsm during install (silent, requires admin)
Filename: "C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe"; Parameters: "/codebase ""{app}\com\VenusLibraryManager.dll"""; StatusMsg: "Registering COM object..."; Flags: runhidden waituntilterminated

Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Unregister COM DLL with 32-bit RegAsm during uninstall
Filename: "C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe"; Parameters: "/unregister ""{app}\com\VenusLibraryManager.dll"""; Flags: runhidden waituntilterminated
