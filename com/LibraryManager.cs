// SPDX-License-Identifier: Apache-2.0
// ============================================================================
// VenusLibraryManager COM Object  v1.9.8
//
// Copyright (c) 2026 Zachary Milot
// Author: Zachary Milot
//
// COM-visible .NET class library that provides programmatic access to all
// Library Manager operations.  This object invokes the com-bridge.js
// command dispatcher via a child process, passing JSON arguments and receiving
// JSON results on stdout.
//
// Registration (32-bit ONLY - VENUS is x86):
//   C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe /codebase VenusLibraryManager.dll
//
// Deregistration:
//   C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe /unregister VenusLibraryManager.dll
//
// Usage from VBScript / HSL:
//   Set mgr = CreateObject("VenusLibraryManager.LibraryManager")
//   WScript.Echo mgr.ListLibraries()
//
// Usage from C# / .NET:
//   Type t = Type.GetTypeFromProgID("VenusLibraryManager.LibraryManager");
//   dynamic mgr = Activator.CreateInstance(t);
//   string json = mgr.ListLibraries();
// ============================================================================

using System;
using System.IO;
using System.Text;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Diagnostics;

[assembly: AssemblyTitle("VenusLibraryManager")]
[assembly: AssemblyDescription("COM object for Library Manager")]
[assembly: AssemblyCompany("Zachary Milot")]
[assembly: AssemblyProduct("Library Manager")]
[assembly: AssemblyCopyright("Copyright (c) 2026 Zachary Milot")]
[assembly: AssemblyVersion("1.9.8.0")]
[assembly: AssemblyFileVersion("1.9.8.0")]
[assembly: ComVisible(true)]
[assembly: Guid("B3E7F8A1-4C2D-4E6F-9A1B-3D5E7F9A1B3D")]

namespace VenusLibraryManager
{
    // ======================================================================
    // COM Interface - defines the public contract visible to COM clients
    // ======================================================================
    [Guid("C4F8A9B2-5D3E-4F70-AB2C-4E6F8A0B2C4E")]
    [ComVisible(true)]
    [InterfaceType(ComInterfaceType.InterfaceIsDual)]
    public interface ILibraryManager
    {
        // -- Libraries --
        [DispId(10)] string ListLibraries();
        [DispId(11)] string ListLibrariesIncludeDeleted();
        [DispId(12)] string GetLibrary(string nameOrId);
        [DispId(13)] string ImportLibrary(string packagePath);
        [DispId(14)] string ImportLibraryEx(string packagePath, bool force, bool noGroup, bool noCache, string authorPassword);
        [DispId(15)] string ImportArchive(string archivePath);
        [DispId(16)] string ImportArchiveEx(string archivePath, bool force, bool noGroup, bool noCache, string authorPassword);
        [DispId(17)] string ExportLibrary(string nameOrId, string outputPath);
        [DispId(18)] string ExportArchiveAll(string outputPath);
        [DispId(19)] string ExportArchiveByNames(string namesJson, string outputPath);
        [DispId(20)] string DeleteLibrary(string nameOrId);
        [DispId(21)] string DeleteLibraryEx(string nameOrId, bool hard, bool keepFiles);

        // -- Packages --
        [DispId(30)] string CreatePackage(string specPath, string outputPath);
        [DispId(31)] string CreatePackageEx(string specPath, string outputPath, string signKeyPath, string signCertPath, string authorPassword);
        [DispId(32)] string VerifyPackage(string packagePath);

        // -- Versions --
        [DispId(40)] string ListVersions(string libraryName);
        [DispId(41)] string RollbackLibrary(string libraryName, string version);
        [DispId(42)] string RollbackLibraryByIndex(string libraryName, int index);

        // -- Publishers --
        [DispId(50)] string ListPublishers();
        [DispId(51)] string GenerateKeypair(string publisher, string organization, string outputDir);

        // -- System Libraries --
        [DispId(60)] string GetSystemLibraries();
        [DispId(61)] string VerifySyslibHashes();
        [DispId(62)] string GenerateSyslibHashes(string sourceDir, string outputPath);

        // -- Audit & Settings --
        [DispId(70)] string GetAuditTrail();
        [DispId(71)] string GetAuditTrailLast(int count);
        [DispId(72)] string GetSettings();

        // -- Configuration --
        [DispId(92)] string LastError { get; }
    }

    // ======================================================================
    // COM Events Interface
    // ======================================================================
    [Guid("D5A9BAC3-6E4F-4081-BC3D-5F70AB1C3D5F")]
    [ComVisible(true)]
    [InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
    public interface ILibraryManagerEvents
    {
        [DispId(102)] void OperationCompleted(string operation, bool success, string resultJson);
        [DispId(103)] void ErrorOccurred(string operation, string errorMessage);
    }

    // ======================================================================
    // COM Class - the main coclass
    // ======================================================================
    [Guid("A2D6E8F0-3B1C-4D5E-8F0A-2C4D6E8F0A2C")]
    [ComVisible(true)]
    [ClassInterface(ClassInterfaceType.None)]
    [ComDefaultInterface(typeof(ILibraryManager))]
    [ComSourceInterfaces(typeof(ILibraryManagerEvents))]
    [ProgId("VenusLibraryManager.LibraryManager")]
    public class LibraryManager : ILibraryManager
    {
        // -- Private state --
        private string _lastError = "";
        private string _appDir   = null;

        // -- Events --
        public delegate void OperationCompletedHandler(string operation, bool success, string resultJson);
        public delegate void ErrorOccurredHandler(string operation, string errorMessage);

        public event OperationCompletedHandler OperationCompleted;
        public event ErrorOccurredHandler ErrorOccurred;

        // ================================================================
        // Constructor
        // ================================================================
        public LibraryManager()
        {
            _appDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        }

        // ================================================================
        // Properties
        // ================================================================

        public string LastError
        {
            get { return _lastError; }
        }

        // ================================================================
        // Library Operations
        // ================================================================

        public string ListLibraries()
        {
            return RunBridge("list-libraries", "{}");
        }

        public string ListLibrariesIncludeDeleted()
        {
            return RunBridge("list-libraries", "{\"includeDeleted\":true}");
        }

        public string GetLibrary(string nameOrId)
        {
            return RunBridge("get-library", "{\"nameOrId\":" + JsonEscape(nameOrId) + "}");
        }

        public string ImportLibrary(string packagePath)
        {
            return ImportLibraryEx(packagePath, false, false, false, null);
        }

        public string ImportLibraryEx(string packagePath, bool force, bool noGroup, bool noCache, string authorPassword)
        {
            string args = "{\"filePath\":" + JsonEscape(packagePath)
                        + ",\"force\":" + force.ToString().ToLower()
                        + ",\"noGroup\":" + noGroup.ToString().ToLower()
                        + ",\"noCache\":" + noCache.ToString().ToLower();
            if (!string.IsNullOrEmpty(authorPassword))
                args += ",\"authorPassword\":" + JsonEscape(authorPassword);
            args += "}";
            return RunBridge("import-library", args);
        }

        public string ImportArchive(string archivePath)
        {
            return ImportArchiveEx(archivePath, false, false, false, null);
        }

        public string ImportArchiveEx(string archivePath, bool force, bool noGroup, bool noCache, string authorPassword)
        {
            string args = "{\"filePath\":" + JsonEscape(archivePath)
                        + ",\"force\":" + force.ToString().ToLower()
                        + ",\"noGroup\":" + noGroup.ToString().ToLower()
                        + ",\"noCache\":" + noCache.ToString().ToLower();
            if (!string.IsNullOrEmpty(authorPassword))
                args += ",\"authorPassword\":" + JsonEscape(authorPassword);
            args += "}";
            return RunBridge("import-archive", args);
        }

        public string ExportLibrary(string nameOrId, string outputPath)
        {
            string args = "{\"name\":" + JsonEscape(nameOrId)
                        + ",\"output\":" + JsonEscape(outputPath) + "}";
            return RunBridge("export-library", args);
        }

        public string ExportArchiveAll(string outputPath)
        {
            string args = "{\"all\":true,\"output\":" + JsonEscape(outputPath) + "}";
            return RunBridge("export-archive", args);
        }

        public string ExportArchiveByNames(string namesJson, string outputPath)
        {
            string args = "{\"names\":" + (namesJson ?? "[]") + ",\"output\":" + JsonEscape(outputPath) + "}";
            return RunBridge("export-archive", args);
        }

        public string DeleteLibrary(string nameOrId)
        {
            return DeleteLibraryEx(nameOrId, false, false);
        }

        public string DeleteLibraryEx(string nameOrId, bool hard, bool keepFiles)
        {
            string args = "{\"name\":" + JsonEscape(nameOrId)
                        + ",\"hard\":" + hard.ToString().ToLower()
                        + ",\"keepFiles\":" + keepFiles.ToString().ToLower() + "}";
            return RunBridge("delete-library", args);
        }

        // ================================================================
        // Package Operations
        // ================================================================

        public string CreatePackage(string specPath, string outputPath)
        {
            return CreatePackageEx(specPath, outputPath, null, null, null);
        }

        public string CreatePackageEx(string specPath, string outputPath, string signKeyPath, string signCertPath, string authorPassword)
        {
            string args = "{\"specPath\":" + JsonEscape(specPath)
                        + ",\"output\":" + JsonEscape(outputPath);
            if (!string.IsNullOrEmpty(signKeyPath))
                args += ",\"signKey\":" + JsonEscape(signKeyPath);
            if (!string.IsNullOrEmpty(signCertPath))
                args += ",\"signCert\":" + JsonEscape(signCertPath);
            if (!string.IsNullOrEmpty(authorPassword))
                args += ",\"authorPassword\":" + JsonEscape(authorPassword);
            args += "}";
            return RunBridge("create-package", args);
        }

        public string VerifyPackage(string packagePath)
        {
            return RunBridge("verify-package", "{\"filePath\":" + JsonEscape(packagePath) + "}");
        }

        // ================================================================
        // Version Operations
        // ================================================================

        public string ListVersions(string libraryName)
        {
            return RunBridge("list-versions", "{\"name\":" + JsonEscape(libraryName) + "}");
        }

        public string RollbackLibrary(string libraryName, string version)
        {
            string args = "{\"name\":" + JsonEscape(libraryName)
                        + ",\"version\":" + JsonEscape(version) + "}";
            return RunBridge("rollback-library", args);
        }

        public string RollbackLibraryByIndex(string libraryName, int index)
        {
            string args = "{\"name\":" + JsonEscape(libraryName)
                        + ",\"index\":" + index + "}";
            return RunBridge("rollback-library", args);
        }

        // ================================================================
        // Publisher Operations
        // ================================================================

        public string ListPublishers()
        {
            return RunBridge("list-publishers", "{}");
        }

        public string GenerateKeypair(string publisher, string organization, string outputDir)
        {
            string args = "{\"publisher\":" + JsonEscape(publisher)
                        + ",\"organization\":" + JsonEscape(organization)
                        + ",\"outputDir\":" + JsonEscape(outputDir) + "}";
            return RunBridge("generate-keypair", args);
        }

        // ================================================================
        // System Library Operations
        // ================================================================

        public string GetSystemLibraries()
        {
            return RunBridge("get-system-libraries", "{}");
        }

        public string VerifySyslibHashes()
        {
            return RunBridge("verify-syslib-hashes", "{}");
        }

        public string GenerateSyslibHashes(string sourceDir, string outputPath)
        {
            string args = "{\"sourceDir\":" + JsonEscape(sourceDir)
                        + ",\"output\":" + JsonEscape(outputPath) + "}";
            return RunBridge("generate-syslib-hashes", args);
        }

        // ================================================================
        // Audit & Settings
        // ================================================================

        public string GetAuditTrail()
        {
            return RunBridge("get-audit-trail", "{}");
        }

        public string GetAuditTrailLast(int count)
        {
            return RunBridge("get-audit-trail", "{\"limit\":" + count + "}");
        }

        public string GetSettings()
        {
            return RunBridge("get-settings", "{}");
        }

        // ================================================================
        // Private Bridge Invocation
        // ================================================================

        /// <summary>
        /// Execute a command via the com-bridge.js Node.js script.
        /// Spawns a child process, passes the command and JSON arguments,
        /// and returns the JSON result from stdout.
        /// </summary>
        private string RunBridge(string command, string jsonArgs)
        {
            try
            {
                string nodeExe = FindNodeExecutable();
                if (nodeExe == null)
                {
                    _lastError = "Cannot find node.exe. Ensure Node.js is installed or the NW.js runtime is available.";
                    RaiseError(command, _lastError);
                    return MakeError(_lastError);
                }

                string bridgeScript = Path.Combine(_appDir, "com-bridge.js");
                if (!File.Exists(bridgeScript))
                {
                    _lastError = "com-bridge.js not found at: " + bridgeScript;
                    RaiseError(command, _lastError);
                    return MakeError(_lastError);
                }

                var psi = new ProcessStartInfo
                {
                    FileName               = nodeExe,
                    Arguments              = "\"" + bridgeScript + "\" " + command + " \"" + jsonArgs.Replace("\"", "\\\"") + "\"",
                    WorkingDirectory       = _appDir,
                    UseShellExecute        = false,
                    CreateNoWindow         = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true
                };

                using (var process = Process.Start(psi))
                {
                    string stdout = process.StandardOutput.ReadToEnd();
                    string stderr = process.StandardError.ReadToEnd();
                    process.WaitForExit(300000); // 5 minute timeout

                    if (process.ExitCode != 0 && string.IsNullOrEmpty(stdout))
                    {
                        _lastError = string.IsNullOrEmpty(stderr) ? "Bridge process failed with exit code " + process.ExitCode : stderr.Trim();
                        RaiseError(command, _lastError);
                        return MakeError(_lastError);
                    }

                    RaiseCompleted(command, true, stdout);
                    return stdout;
                }
            }
            catch (Exception ex)
            {
                _lastError = ex.Message;
                RaiseError(command, _lastError);
                return MakeError(_lastError);
            }
        }

        // ================================================================
        // Private Helpers
        // ================================================================

        private string FindNodeExecutable()
        {
            // Check for nw.exe in app directory (NW.js runtime)
            string nwPath = Path.Combine(_appDir, "nw.exe");
            if (File.Exists(nwPath))
                return nwPath;

            // Check for node.exe in app directory
            string nodePath = Path.Combine(_appDir, "node.exe");
            if (File.Exists(nodePath))
                return nodePath;

            // Check for node.exe in PATH
            string pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (string dir in pathEnv.Split(';'))
            {
                if (string.IsNullOrWhiteSpace(dir)) continue;
                string candidate = Path.Combine(dir.Trim(), "node.exe");
                if (File.Exists(candidate))
                    return candidate;
            }

            return null;
        }

        private static string JsonEscape(string value)
        {
            if (value == null) return "null";
            return "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r") + "\"";
        }

        private static string MakeResult(bool success, string data)
        {
            return "{\"success\":" + success.ToString().ToLower() + ",\"data\":" + JsonEscape(data) + "}";
        }

        private static string MakeError(string message)
        {
            return "{\"success\":false,\"error\":" + JsonEscape(message) + "}";
        }

        private void RaiseCompleted(string operation, bool success, string result)
        {
            if (OperationCompleted != null)
            {
                try { OperationCompleted(operation, success, result); }
                catch { /* swallow event handler errors */ }
            }
        }

        private void RaiseError(string operation, string message)
        {
            if (ErrorOccurred != null)
            {
                try { ErrorOccurred(operation, message); }
                catch { /* swallow event handler errors */ }
            }
        }
    }
}
