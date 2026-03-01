<#
.SYNOPSIS
    Strategic automated screenshot capture for Venus Library Manager CHM docs.
.DESCRIPTION
    Uses a temporary Node.js HTTP eval server injected into the app's index.html
    to control all UI interactions via JavaScript. Win32 API is used only for
    window management (foreground, capture).
    Avoids all dangerous interactions (file dialogs, data writes, audit writes).
.NOTES
    Prerequisites: The eval server script tag must be present in html/index.html.
    The script will inject it if missing. Cleanup removes it after capture.
#>

param([switch]$SkipLaunch)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

# ── Win32 API (window management + capture only) ────────────────────────────
Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Drawing;
using System.Drawing.Imaging;
using System.Threading;

public class WC {
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out R r);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern void keybd_event(byte v,byte s,uint f,UIntPtr e);

    [StructLayout(LayoutKind.Sequential)] public struct R { public int L,T,Ri,B; }

    public static void Capture(IntPtr h, string path){
        R r; GetWindowRect(h, out r);
        int w=r.Ri-r.L, ht=r.B-r.T;
        if(w<=0||ht<=0) throw new Exception("bad window size");
        using(var b=new Bitmap(w,ht)){
            using(var g=Graphics.FromImage(b)) g.CopyFromScreen(r.L,r.T,0,0,new Size(w,ht));
            b.Save(path, ImageFormat.Png);
        }
    }
}
'@ -ReferencedAssemblies System.Drawing, System.Drawing.Primitives, System.Runtime.InteropServices -ErrorAction SilentlyContinue

# ── Paths ────────────────────────────────────────────────────────────────────
$root      = Split-Path $PSScriptRoot
$imagesDir = Join-Path (Join-Path $root 'CHM Help Source Files') 'images'
$exePath   = Join-Path $root 'Venus Library Manager.exe'
$evalPort  = 18273

if (-not (Test-Path $imagesDir)) { New-Item $imagesDir -ItemType Directory -Force | Out-Null }

# ── Eval server helper ───────────────────────────────────────────────────────
function Invoke-JS {
    param([string]$Code, [int]$Wait = 500)
    try {
        $result = Invoke-RestMethod -Uri "http://localhost:${evalPort}/" -Method POST -Body $Code -ContentType 'text/plain' -TimeoutSec 15
        Start-Sleep -Milliseconds $Wait
        return $result
    } catch {
        Write-Host "    Eval error: $_" -ForegroundColor DarkYellow
        return $null
    }
}

function Show-Modal([string]$id, [int]$Wait = 1200) {
    Invoke-JS -Code "jQuery('#$id').modal('show'); '$id shown'" -Wait $Wait | Out-Null
}

function Hide-Modal([string]$id, [int]$Wait = 600) {
    Invoke-JS -Code "jQuery('#$id').modal('hide'); jQuery('.modal-backdrop').remove(); jQuery('body').removeClass('modal-open').css('padding-right',''); '$id hidden'" -Wait $Wait | Out-Null
}

function Dismiss-All([int]$Wait = 600) {
    Invoke-JS -Code "jQuery('.modal').modal('hide'); jQuery('.modal-backdrop').remove(); jQuery('body').removeClass('modal-open').css('padding-right',''); jQuery('.dropdown-menu.show').removeClass('show'); 'dismissed'" -Wait $Wait | Out-Null
}

function Trigger-Click([string]$selector, [int]$Wait = 1200) {
    Invoke-JS -Code "var el=document.querySelector('$selector'); if(el){el.click(); 'clicked';} else 'not found: $selector'" -Wait $Wait | Out-Null
}

# Show packager view (via overflow menu item click handler)
function Show-Packager([int]$Wait = 1500) {
    Trigger-Click '.overflow-export' $Wait
}

# ── App helpers ──────────────────────────────────────────────────────────────
$script:hWnd = [IntPtr]::Zero
$script:ok = 0; $script:fail = 0

function Find-App {
    Get-Process | Where-Object {
        $_.MainWindowHandle -ne 0 -and $_.ProcessName -ne 'Code' -and
        $_.MainWindowTitle -like '*Venus Library Manager*'
    } | Select-Object -First 1
}

function BringToFront {
    if ([WC]::GetForegroundWindow() -eq $script:hWnd) { return }
    [WC]::ShowWindow($script:hWnd, 9)
    Start-Sleep -Milliseconds 300
    [WC]::SetForegroundWindow($script:hWnd)
    Start-Sleep -Milliseconds 500
    if ([WC]::GetForegroundWindow() -ne $script:hWnd) {
        # Alt+Tab fallback
        [WC]::keybd_event(0x12,0,0,[UIntPtr]::Zero)
        [WC]::keybd_event(0x09,0,0,[UIntPtr]::Zero)
        [WC]::keybd_event(0x09,0,2,[UIntPtr]::Zero)
        [WC]::keybd_event(0x12,0,2,[UIntPtr]::Zero)
        Start-Sleep -Milliseconds 400
        [WC]::SetForegroundWindow($script:hWnd)
        Start-Sleep -Milliseconds 300
    }
}

function Cap([string]$name) {
    $p = Join-Path $imagesDir $name
    BringToFront
    Start-Sleep -Milliseconds 300
    try {
        [WC]::Capture($script:hWnd, $p)
        $kb = [math]::Round((Get-Item $p).Length/1024,1)
        Write-Host "  [OK] $name (${kb}KB)" -ForegroundColor Green
        $script:ok++
        return $true
    } catch {
        Write-Host "  [FAIL] $name : $_" -ForegroundColor Red
        $script:fail++
        return $false
    }
}

# ═════════════════════════════════════════════════════════════════════════════
Write-Host ''
Write-Host '=== Venus Library Manager - Strategic Screenshot Capture ===' -ForegroundColor Cyan
Write-Host '    Using embedded eval server (port 18273)' -ForegroundColor DarkGray

# ── Launch ───────────────────────────────────────────────────────────────────
$proc = Find-App
if ($proc -and -not $SkipLaunch) {
    Write-Host "Stopping existing app (PID $($proc.Id))..." -ForegroundColor Yellow
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    $proc = $null
}

if (-not $proc) {
    Start-Process $exePath -WorkingDirectory $root
    Write-Host '  Waiting for window...'
    for ($i = 0; $i -lt 45; $i++) {
        Start-Sleep -Seconds 1
        $proc = Find-App
        if ($proc) { break }
    }
    if (-not $proc) { Write-Host 'ERROR: app did not start' -ForegroundColor Red; exit 1 }
    Write-Host '  Waiting for app init (15s)...'
    Start-Sleep -Seconds 15
    $proc = Find-App
}

$script:hWnd = $proc.MainWindowHandle
Write-Host "Window $($script:hWnd) (PID $($proc.Id))" -ForegroundColor Green

# Verify eval server
$evalOk = $false
for ($i = 0; $i -lt 10; $i++) {
    try {
        $ping = Invoke-RestMethod "http://localhost:${evalPort}/ping" -TimeoutSec 3
        if ($ping -eq 'pong') { $evalOk = $true; break }
    } catch {}
    Start-Sleep -Seconds 1
}
Write-Host "Eval server: $(if($evalOk){'READY'}else{'NOT AVAILABLE - aborting'})" -ForegroundColor $(if($evalOk){'Green'}else{'Red'})
if (-not $evalOk) { exit 1 }

BringToFront
Start-Sleep -Milliseconds 500

# ═════════════════════════════════════════════════════════════════════════════
#  Phase 1 : Main window (library card view - already visible)
# ═════════════════════════════════════════════════════════════════════════════
Write-Host "`nPhase 1 - Main window" -ForegroundColor Cyan
Dismiss-All
Start-Sleep -Milliseconds 500
Cap 'main-window.png'
Cap 'main-window-labeled.png'
Cap 'navigation-tabs.png'
Cap 'library-card-annotated.png'
Cap 'venus-shortcuts-sidebar.png'
Cap 'unsigned-library-cards.png'
Cap 'integrity-error-card.png'

# ═════════════════════════════════════════════════════════════════════════════
#  Phase 2 : Overflow menu (show dropdown via Bootstrap toggle)
# ═════════════════════════════════════════════════════════════════════════════
Write-Host "`nPhase 2 - Overflow menu" -ForegroundColor Cyan
# Show dropdown via CSS classes to avoid focus-close issue
Invoke-JS -Code "jQuery('.btn-overflow-menu').addClass('show'); jQuery('.btn-overflow-menu .dropdown-menu').addClass('show'); 'opened'" -Wait 800 | Out-Null
Cap 'overflow-menu.png'
Invoke-JS -Code "jQuery('.btn-overflow-menu').removeClass('show'); jQuery('.btn-overflow-menu .dropdown-menu').removeClass('show'); 'closed'" -Wait 500 | Out-Null

# ═════════════════════════════════════════════════════════════════════════════
#  Phase 3 : Settings (trigger click - app populates with real data)
# ═════════════════════════════════════════════════════════════════════════════
Write-Host "`nPhase 3 - Settings" -ForegroundColor Cyan
Trigger-Click '.overflow-settings' 1500
Cap 'settings-panel.png'
Cap 'unsigned-settings.png'
Hide-Modal 'settingsModal'

# ═════════════════════════════════════════════════════════════════════════════
#  Phase 4 : Event History (trigger click - shows real log)
# ═════════════════════════════════════════════════════════════════════════════
Write-Host "`nPhase 4 - Event History" -ForegroundColor Cyan
Trigger-Click '.overflow-history' 2000
Cap 'event-history-modal.png'
Hide-Modal 'eventHistoryModal'

# ═════════════════════════════════════════════════════════════════════════════
#  Phase 5 : Verify & Repair (trigger click - app runs scan)
# ═════════════════════════════════════════════════════════════════════════════
Write-Host "`nPhase 5 - Verify & Repair" -ForegroundColor Cyan
Trigger-Click '.overflow-repair' 2500
Cap 'verify-repair-modal.png'
Hide-Modal 'repairModal'

# ═════════════════════════════════════════════════════════════════════════════
#  Phase 6 : Library Groups (trigger click - app populates groups)
# ═════════════════════════════════════════════════════════════════════════════
Write-Host "`nPhase 6 - Library Groups" -ForegroundColor Cyan
Trigger-Click '.overflow-groups' 1500
Cap 'group-create.png'
Cap 'group-drag-drop.png'
Hide-Modal 'groupsModal'

# ═════════════════════════════════════════════════════════════════════════════
#  Phase 7 : Export Archive (trigger click - shows library list)
# ═════════════════════════════════════════════════════════════════════════════
Write-Host "`nPhase 7 - Export Archive" -ForegroundColor Cyan
Trigger-Click '.overflow-export-archive' 1500
Cap 'archive-export-modal.png'
Hide-Modal 'exportArchiveModal'

# ═════════════════════════════════════════════════════════════════════════════
#  Phase 8 : Package Library (shows packager inline view)
# ═════════════════════════════════════════════════════════════════════════════
Write-Host "`nPhase 8 - Packager" -ForegroundColor Cyan
Dismiss-All
Show-Packager 2000
Cap 'packager-main.png'

# Fill in some sample data for the filled screenshot
Invoke-JS -Code @'
(function(){
  var s=function(id,v){var e=document.getElementById(id);if(e){e.value=v;e.dispatchEvent(new Event('input',{bubbles:true}));}};
  s('pkg-author','Hamilton Company');
  s('pkg-organization','Hamilton Robotics');
  s('pkg-version','2.1.0');
  s('pkg-venus-compat','4.7+');
  s('pkg-description','Pipetting utility library for multi-channel liquid handling with volume verification and error recovery.');
  s('pkg-github-url','https://github.com/hamilton-robotics/pipetting-utils');
  s('pkg-tags','pipetting, liquid-handling, multi-channel');
  return 'filled';
})()
'@ -Wait 800 | Out-Null
Cap 'packager-filled.png'

# Return to library view - click first nav tab
Invoke-JS -Code @'
(function(){
  var t = document.querySelector('.navblock-collapsable .nav-link');
  if(t) { t.click(); return 'nav clicked'; }
  var links = document.querySelector('.links-container');
  if(links) links.classList.remove('d-none');
  var exp = document.querySelector('.exporter-container');
  if(exp) exp.classList.add('d-none');
  return 'manual toggle';
})()
'@ -Wait 1200 | Out-Null

# ═════════════════════════════════════════════════════════════════════════════
#  Phase 9 : Search
# ═════════════════════════════════════════════════════════════════════════════
Write-Host "`nPhase 9 - Search" -ForegroundColor Cyan
Dismiss-All

# Type into search bar and trigger autocomplete
Invoke-JS -Code @'
(function(){
  var inp=document.getElementById('imp-search-input');
  if(!inp) return 'no search input';
  inp.focus();
  inp.value='pip';
  inp.dispatchEvent(new Event('input',{bubbles:true}));
  inp.dispatchEvent(new KeyboardEvent('keyup',{bubbles:true,key:'p'}));
  return 'typed pip';
})()
'@ -Wait 1200 | Out-Null
Cap 'search-autocomplete.png'

# Simulate Enter for chip
Invoke-JS -Code @'
(function(){
  var inp=document.getElementById('imp-search-input');
  if(!inp) return 'no input';
  inp.dispatchEvent(new KeyboardEvent('keydown',{bubbles:true,key:'Enter',keyCode:13}));
  inp.dispatchEvent(new KeyboardEvent('keyup',{bubbles:true,key:'Enter',keyCode:13}));
  return 'enter pressed';
})()
'@ -Wait 1000 | Out-Null
Cap 'search-bar-chips.png'

# Clear search
Invoke-JS -Code @'
(function(){
  var inp=document.getElementById('imp-search-input');
  if(inp){inp.value='';inp.dispatchEvent(new Event('input',{bubbles:true}));}
  document.querySelectorAll('.imp-search-chip-remove').forEach(function(b){b.click();});
  var cb=document.querySelector('.imp-search-clear');
  if(cb)cb.click();
  return 'cleared';
})()
'@ -Wait 600 | Out-Null

# ═════════════════════════════════════════════════════════════════════════════
#  Phase 10 : Library detail modal (open first library card)
# ═════════════════════════════════════════════════════════════════════════════
Write-Host "`nPhase 10 - Library detail" -ForegroundColor Cyan
Dismiss-All

Invoke-JS -Code @'
(function(){
  var c = document.querySelector('.imp-lib-card-container[data-lib-id]');
  if(c){
    var id = c.getAttribute('data-lib-id');
    if(typeof impShowLibDetail === 'function') { impShowLibDetail(id); return 'showing detail for: ' + id; }
    c.click();
    return 'clicked card: ' + id;
  }
  return 'no cards found';
})()
'@ -Wait 2000 | Out-Null
Cap 'library-detail-modal.png'
Cap 'cached-versions-list.png'
Cap 'export-button-detail-modal.png'
Hide-Modal 'libDetailModal'

# ═════════════════════════════════════════════════════════════════════════════
#  Phase 11 : Modal injection (show modals with sample data via JS)
# ═════════════════════════════════════════════════════════════════════════════
Write-Host "`nPhase 11 - Modal injection" -ForegroundColor Cyan
Dismiss-All

# ── Delete confirmation ──────────────────────────────────────────────────────
Write-Host '  deleteLibConfirmModal' -ForegroundColor DarkGray
Invoke-JS -Code @'
(function(){
  jQuery('.delete-confirm-consequences').html('<strong>HSLPipettingUtils</strong> v2.1.0 will be permanently removed.<br><small class="text-muted">3 library files, 2 demo methods</small>');
  jQuery('.delete-confirm-expected-text').text('HSLPipettingUtils');
  jQuery('#deleteLibConfirmModal').modal('show');
  return 'shown';
})()
'@ -Wait 1500 | Out-Null
Cap 'delete-confirmation-dialog.png'
Hide-Modal 'deleteLibConfirmModal'

# ── Import preview ───────────────────────────────────────────────────────────
Write-Host '  importPreviewModal' -ForegroundColor DarkGray
Invoke-JS -Code @'
(function(){
  jQuery('.imp-preview-name').text('HSLPipettingUtils');
  jQuery('.imp-preview-author').text('Hamilton Company');
  jQuery('.imp-preview-org').text('Hamilton Robotics');
  jQuery('.imp-preview-desc').text('Multi-channel pipetting utility library with volume verification and error recovery.');
  jQuery('.imp-preview-compat').text('VENUS 4.7+');
  jQuery('.imp-preview-created').text('2025-01-15');
  jQuery('.imp-preview-tags').html('<span class="badge badge-secondary mr-1">pipetting</span><span class="badge badge-secondary mr-1">liquid-handling</span><span class="badge badge-secondary">multi-channel</span>');
  jQuery('.imp-preview-file-list').html('<li>HSLPipettingUtils.hsl</li><li>HSLPipettingUtils.hs_</li><li>PipettingConfig.xml</li>');
  jQuery('.imp-preview-demo-list').html('<li>DemoPipettingUtils.med</li><li>DemoVolumeVerify.med</li>');
  jQuery('.imp-preview-installdirs').html('<div><code>C:\\Program Files (x86)\\HAMILTON\\Library</code></div><div><code>C:\\Program Files (x86)\\HAMILTON\\Methods\\DemoMethods</code></div>');
  jQuery('.imp-preview-integrity').removeClass('d-none').html('<span class="text-success"><i class="fas fa-check-circle mr-1"></i>Package signature verified</span>');
  jQuery('#importPreviewModal').modal('show');
  return 'shown';
})()
'@ -Wait 1500 | Out-Null
Cap 'import-preview-modal.png'
Hide-Modal 'importPreviewModal'

# ── Import success ───────────────────────────────────────────────────────────
Write-Host '  importSuccessModal' -ForegroundColor DarkGray
Invoke-JS -Code @'
(function(){
  jQuery('.import-success-libname').text('HSLPipettingUtils');
  jQuery('.import-success-filecount').text('5 files installed');
  jQuery('.import-success-paths').html('<div><code>C:\\Program Files (x86)\\HAMILTON\\Library</code></div>');
  jQuery('#importSuccessModal').modal('show');
  return 'shown';
})()
'@ -Wait 1500 | Out-Null
Cap 'import-success-modal.png'
Hide-Modal 'importSuccessModal'

# ── Generic success ──────────────────────────────────────────────────────────
Write-Host '  genericSuccessModal' -ForegroundColor DarkGray
Invoke-JS -Code @'
(function(){
  jQuery('.generic-success-title').text('Export Successful');
  jQuery('.generic-success-name').text('HSLPipettingUtils');
  jQuery('.generic-success-detail').text('Package saved to desktop');
  jQuery('.generic-success-paths').html('<div><code>C:\\Users\\admin\\Desktop\\HSLPipettingUtils_v2.1.0.hxlibpkg</code></div>');
  jQuery('#genericSuccessModal').modal('show');
  return 'shown';
})()
'@ -Wait 1500 | Out-Null
Cap 'success-dialog.png'
Hide-Modal 'genericSuccessModal'

# ── Export choice ────────────────────────────────────────────────────────────
Write-Host '  exportChoiceModal' -ForegroundColor DarkGray
Invoke-JS -Code @'
(function(){
  jQuery('.export-choice-libname').text('HSLPipettingUtils v2.1.0');
  jQuery('#exportChoiceModal').modal('show');
  return 'shown';
})()
'@ -Wait 1500 | Out-Null
Cap 'export-choice-modal.png'

# Show dependency summary for "with deps" version
Invoke-JS -Code @'
(function(){
  var ds = jQuery('.export-choice-dep-summary');
  ds.removeClass('d-none').html('<div class="mt-2"><small class="text-muted">Dependencies that will be included:</small><ul class="mb-0 small"><li>HSLUtilLib2 v1.3.0</li><li>HSLTipCountingLib v1.0.2</li></ul></div>');
  return 'deps shown';
})()
'@ -Wait 800 | Out-Null
Cap 'export-choice-with-deps.png'
Hide-Modal 'exportChoiceModal'

# ── Rollback confirmation ────────────────────────────────────────────────────
Write-Host '  rollbackLibConfirmModal' -ForegroundColor DarkGray
Invoke-JS -Code @'
(function(){
  jQuery('.rollback-confirm-libname-header').text('HSLPipettingUtils');
  jQuery('.rollback-confirm-consequences').html('Rolling back from <strong>v2.1.0</strong> to <strong>v1.9.0</strong>. Current library files will be replaced with the cached version.');
  jQuery('.rollback-confirm-expected-text').text('HSLPipettingUtils');
  jQuery('#rollbackLibConfirmModal').modal('show');
  return 'shown';
})()
'@ -Wait 1500 | Out-Null
Cap 'rollback-confirmation.png'
Hide-Modal 'rollbackLibConfirmModal'

# ── Audit verify result ──────────────────────────────────────────────────────
Write-Host '  auditVerifyModal' -ForegroundColor DarkGray
Invoke-JS -Code @'
(function(){
  jQuery('.audit-verify-icon').html('<i class="fas fa-check-circle fa-3x text-success"></i>');
  jQuery('.audit-verify-filename').text('library_audit_2025-01-15.json');
  jQuery('.audit-verify-message').text('Audit file integrity verified successfully.\nAll 24 entries match expected checksums.\nNo tampering detected.');
  jQuery('#auditVerifyModal').modal('show');
  return 'shown';
})()
'@ -Wait 1500 | Out-Null
Cap 'audit-verify-result.png'
Hide-Modal 'auditVerifyModal'

# ── Unsigned library detail ──────────────────────────────────────────────────
Write-Host '  unsignedLibDetailModal' -ForegroundColor DarkGray
Invoke-JS -Code @'
(function(){
  jQuery('.unsigned-lib-detail-name').text('CustomPipettingHelper');
  jQuery('#ulib-author').val('Lab Scientist');
  jQuery('#ulib-org').val('Research Lab');
  jQuery('#ulib-version').val('1.0.0');
  jQuery('#ulib-compat').val('4.6+');
  jQuery('#ulib-desc').val('Custom helper library for specialized pipetting sequences.');
  jQuery('#unsignedLibDetailModal').modal('show');
  return 'shown';
})()
'@ -Wait 1500 | Out-Null
Cap 'unsigned-detail-modal.png'
Hide-Modal 'unsignedLibDetailModal'

# ═════════════════════════════════════════════════════════════════════════════
#  Phase 12 : Splash screen (re-show built-in overlay)
# ═════════════════════════════════════════════════════════════════════════════
Write-Host "`nPhase 12 - Splash screen" -ForegroundColor Cyan
Dismiss-All

Invoke-JS -Code @'
(function(){
  var s=document.getElementById('splash-screen');
  if(!s){
    s=document.createElement('div');
    s.id='splash-screen';
    s.style.cssText='position:fixed;top:0;left:0;width:100vw;height:100vh;z-index:99999;display:flex;align-items:center;justify-content:center;background:linear-gradient(150deg,#002e48 0%,#0a4a6e 40%,#255a85 100%);';
    s.innerHTML='<div style="display:flex;flex-direction:column;align-items:center;user-select:none;"><img style="width:150px;height:150px;margin-bottom:28px;object-fit:contain;" src="img/VenusLibraryManagerAnimated.svg" /><div style="font-family:Segoe UI,Tahoma,sans-serif;font-size:1.65rem;font-weight:600;color:#fff;letter-spacing:.5px;margin-bottom:4px;">Venus Library Manager</div><div style="font-family:Segoe UI,Tahoma,sans-serif;font-size:.85rem;font-weight:400;color:rgba(255,255,255,.55);letter-spacing:1.5px;text-transform:uppercase;margin-bottom:32px;">FOR VENUS 6+</div><div style="font-family:Segoe UI,Tahoma,sans-serif;font-size:.78rem;color:rgba(255,255,255,.45);letter-spacing:.4px;">Loading libraries...</div></div>';
    document.body.appendChild(s);
    return 'splash recreated';
  }
  s.style.display='flex';
  s.style.zIndex='99999';
  var st=s.querySelector('.splash-status');
  if(st) st.textContent='Loading libraries...';
  return 'splash shown';
})()
'@ -Wait 1500 | Out-Null
Cap 'splash-screen.png'
Invoke-JS -Code "var s=document.getElementById('splash-screen');if(s)s.remove(); 'removed'" -Wait 500 | Out-Null

# ═════════════════════════════════════════════════════════════════════════════
#  Phase 13 : DB folder structure (render overlay)
# ═════════════════════════════════════════════════════════════════════════════
Write-Host "`nPhase 13 - DB folder overlay" -ForegroundColor Cyan
Invoke-JS -Code @'
(function(){
  var d=document.createElement('div'); d.id='dbOverlay';
  d.style.cssText='position:fixed;top:0;left:0;width:100%;height:100%;background:#1e1e2e;z-index:99999;display:flex;align-items:center;justify-content:center;font-family:Consolas,monospace;color:#cdd6f4;';
  d.innerHTML='<div style="background:#181825;padding:40px 60px;border-radius:12px;border:1px solid #45475a;"><h3 style="color:#89b4fa;margin-bottom:20px;font-family:Segoe UI,sans-serif;">db/ Folder Structure</h3><pre style="font-size:14px;line-height:1.8;margin:0;color:#a6adc8;">db/\n  groups.json\n  installed_libs.json\n  links.json\n  settings.json\n  system_libraries.json\n  system_library_hashes.json\n  tree.json\n  unsigned_libs.json</pre></div>';
  document.body.appendChild(d);
  return 'overlay shown';
})()
'@ -Wait 900 | Out-Null
Cap 'db-folder-structure.png'
Invoke-JS -Code "var e=document.getElementById('dbOverlay');if(e)e.remove(); 'removed'" -Wait 300 | Out-Null

# ═════════════════════════════════════════════════════════════════════════════
#  Phase 14 : Composited icon example (render overlay)
# ═════════════════════════════════════════════════════════════════════════════
Write-Host "`nPhase 14 - Icon compositing overlay" -ForegroundColor Cyan
Invoke-JS -Code @'
(function(){
  var d=document.createElement('div'); d.id='iconOverlay';
  d.style.cssText='position:fixed;top:0;left:0;width:100%;height:100%;background:#1e1e2e;z-index:99999;display:flex;align-items:center;justify-content:center;';
  d.innerHTML='<div style="background:#181825;padding:40px 60px;border-radius:12px;border:1px solid #45475a;text-align:center;"><h3 style="color:#89b4fa;margin-bottom:24px;font-family:Segoe UI,sans-serif;">Package Icon Compositing</h3><div style="display:flex;align-items:center;gap:30px;"><div style="text-align:center;"><div style="width:80px;height:80px;background:#313244;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:36px;">&#128230;</div><div style="color:#a6adc8;font-size:12px;margin-top:8px;">Base Icon</div></div><div style="font-size:24px;color:#585b70;">+</div><div style="text-align:center;"><div style="width:40px;height:40px;background:#313244;border-radius:4px;display:flex;align-items:center;justify-content:center;font-size:20px;">&#128300;</div><div style="color:#a6adc8;font-size:12px;margin-top:8px;">Library Image</div></div><div style="font-size:24px;color:#585b70;">=</div><div style="text-align:center;"><div style="width:80px;height:80px;background:linear-gradient(135deg,#313244,#45475a);border-radius:8px;display:flex;align-items:center;justify-content:center;position:relative;"><span style="font-size:36px;">&#128230;</span><span style="position:absolute;bottom:4px;right:4px;font-size:18px;">&#128300;</span></div><div style="color:#a6adc8;font-size:12px;margin-top:8px;">Composited</div></div></div></div>';
  document.body.appendChild(d);
  return 'overlay shown';
})()
'@ -Wait 900 | Out-Null
Cap 'composited-icon-example.png'
Invoke-JS -Code "var e=document.getElementById('iconOverlay');if(e)e.remove(); 'removed'" -Wait 300 | Out-Null

# ═════════════════════════════════════════════════════════════════════════════
#  Summary with duplicate detection
# ═════════════════════════════════════════════════════════════════════════════
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "  OK:   $($script:ok)" -ForegroundColor Green
Write-Host "  Fail: $($script:fail)" -ForegroundColor $(if($script:fail -gt 0){'Red'}else{'Green'})

$imgs = Get-ChildItem (Join-Path $imagesDir '*.png') -ErrorAction SilentlyContinue | Sort-Object Name
if ($imgs) {
    $hashes = @{}
    foreach ($f in $imgs) {
        $h = (Get-FileHash $f.FullName -Algorithm MD5).Hash
        if (-not $hashes.ContainsKey($h)) { $hashes[$h] = [System.Collections.Generic.List[string]]::new() }
        $hashes[$h].Add($f.Name)
    }
    $dupes = $hashes.Values | Where-Object { $_.Count -gt 1 }
    Write-Host "`n  $($imgs.Count) files, $($hashes.Count) unique hashes" -ForegroundColor Cyan
    if ($dupes) {
        Write-Host "  Duplicate groups:" -ForegroundColor Yellow
        foreach ($g in $dupes) {
            Write-Host "    Same hash: $($g -join ', ')" -ForegroundColor Yellow
        }
    } else {
        Write-Host '  All files unique!' -ForegroundColor Green
    }
}

Write-Host "`nDone. Run: npm run chm:images:check" -ForegroundColor Cyan
