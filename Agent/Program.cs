using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Management.Infrastructure;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace MiniDMAgent
{
    // --- Hardware Data Model ---
    class HardwareInventory
    {
        public string SerialNumber { get; set; } = "Unknown";
        public string Processor { get; set; } = "Unknown";
        public int RamMb { get; set; } = 0;
    }

    // A simple class to hold our working state in memory
    class AgentState
    {
        public string ServerUrl { get; set; }
        public string DeviceId { get; set; }
        public string ClientPrivateKey { get; set; }
        public string ServerPublicKey { get; set; }
    }

    // Define the data model for our cache ledger
    class PendingInstall
    {
        public int CommandId { get; set; }
        public string AppName { get; set; }
        public string FilePath { get; set; }
        public string Arguments { get; set; }
        public string Extension { get; set; }
    }

    class Program
    {
        static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .UseWindowsService(options =>
                {
                    options.ServiceName = "MiniDM Agent";
                })
                .ConfigureServices((hostContext, services) =>
                {
                    services.AddHostedService<MiniDMWorker>();
                });
    }

    public class MiniDMWorker : BackgroundService
    {
        private readonly ILogger<MiniDMWorker> _logger;

        private const string RegistryPath = @"SOFTWARE\MiniDM";
        private static readonly string ProgramDataPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MiniDM");
        private static readonly string StateFilePath = Path.Combine(ProgramDataPath, "state.dat");
        private static readonly string CacheDirPath = Path.Combine(ProgramDataPath, "Cache");
        private static readonly string PendingInstallsFilePath = Path.Combine(ProgramDataPath, "pending_installs.json");

        private const string EventSourceName = "MiniDM-Agent";
        private const string EventLogName = "MiniDM";

        private static readonly HttpClient httpClient = new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = false,
            MaxAutomaticRedirections = 10
        })
        {
            Timeout = TimeSpan.FromMinutes(30)
        };

        public MiniDMWorker(ILogger<MiniDMWorker> logger)
        {
            _logger = logger;
            EnsureEventLogSourceExists();
        }

        private void EnsureEventLogSourceExists()
        {
            try
            {
                if (!EventLog.SourceExists(EventSourceName))
                {
                    _logger.LogInformation("Creating custom Event Log source: " + EventSourceName);
                    EventLog.CreateEventSource(EventSourceName, EventLogName);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"WARNING: Could not create Event Log source. Are you running as Admin? Error: {ex.Message}");
            }
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Starting MiniDM Agent Service...");
            SafeLogEvent("MiniDM Agent Service started.", EventLogEntryType.Information);

            if (!Directory.Exists(ProgramDataPath))
            {
                Directory.CreateDirectory(ProgramDataPath);
            }

            AgentState currentState = null;

            if (File.Exists(StateFilePath))
            {
                _logger.LogInformation("Found state.dat. Booting from secure DPAPI vault...");
                currentState = LoadSecureState();
            }
            else
            {
                _logger.LogInformation("No secure state found. Initiating Bootstrap process...");
                currentState = await BootstrapAgent(stoppingToken);
            }

            if (currentState == null)
            {
                string errorMsg = "CRITICAL: Failed to acquire valid Agent State. Exiting.";
                _logger.LogError(errorMsg);
                SafeLogEvent(errorMsg, EventLogEntryType.Error);
                Environment.Exit(1);
                return;
            }

            // 1. Process any cached Pre-Login installations before talking to the server
            await ProcessCachedInstallsAsync(currentState, stoppingToken);

            // 2. Define the polling interval
            TimeSpan pollingInterval = TimeSpan.FromMinutes(5);
            _logger.LogInformation($"Entering background polling loop. Interval: {pollingInterval.TotalMinutes} minutes.");

            // 3. Fire the initial check-in immediately
            await PerformCheckInAsync(currentState, stoppingToken);

            // 4. The Infinite Polling Loop
            using PeriodicTimer timer = new PeriodicTimer(pollingInterval);
            try
            {
                while (await timer.WaitForNextTickAsync(stoppingToken))
                {
                    if (stoppingToken.IsCancellationRequested) break;
                    await PerformCheckInAsync(currentState, stoppingToken);
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("MiniDM Agent Service is stopping gracefully.");
            }
            catch (Exception ex)
            {
                string crashMsg = $"CRITICAL: Polling loop crashed: {ex.Message}";
                _logger.LogError(crashMsg);
                SafeLogEvent(crashMsg, EventLogEntryType.Error);
            }
        }

        private async Task<AgentState> BootstrapAgent(CancellationToken stoppingToken)
        {
            using RegistryKey key = Registry.LocalMachine.OpenSubKey(RegistryPath, writable: true);
            if (key == null)
            {
                _logger.LogError("CRITICAL: No deployment registry keys found.");
                return null;
            }

            string serverUrl = key.GetValue("ServerUrl")?.ToString();
            string enrollmentKey = key.GetValue("EnrollmentKey")?.ToString();

            if (string.IsNullOrEmpty(serverUrl))
            {
                return null;
            }

            _logger.LogInformation("Generating local RSA 2048-bit key pair...");
            using RSA rsa = RSA.Create(2048);
            string clientPublicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
            string clientPrivateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());

            var payload = new { enrollmentKey, clientPublicKey, deviceName = Environment.MachineName };
            string jsonPayload = JsonSerializer.Serialize(payload);
            var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

            string serverPublicKey = "";
            string deviceId = "";

            try
            {
                _logger.LogInformation($"Sending Enrollment request to {serverUrl}/api/enroll...");
                HttpResponseMessage response = await httpClient.PostAsync($"{serverUrl}/api/enroll", content, stoppingToken);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogError($"CRITICAL: Enrollment failed. Server returned {response.StatusCode}");
                    return null;
                }

                string responseBody = await response.Content.ReadAsStringAsync(stoppingToken);
                using JsonDocument doc = JsonDocument.Parse(responseBody);
                serverPublicKey = doc.RootElement.GetProperty("serverPublicKey").GetString();
                deviceId = doc.RootElement.GetProperty("deviceId").GetString();

                _logger.LogInformation($"Enrollment successful! Assigned Device ID: {deviceId}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"CRITICAL: Network error during enrollment: {ex.Message}");
                return null;
            }

            var state = new AgentState
            {
                ServerUrl = serverUrl,
                ServerPublicKey = serverPublicKey,
                ClientPrivateKey = clientPrivateKey,
                DeviceId = deviceId
            };

            string jsonState = JsonSerializer.Serialize(state);
            byte[] encryptedState = ProtectedData.Protect(Encoding.UTF8.GetBytes(jsonState), null, DataProtectionScope.LocalMachine);
            await File.WriteAllBytesAsync(StateFilePath, encryptedState, stoppingToken);

            _logger.LogInformation($"Secure vault written to {StateFilePath}");

            // --- SECURITY CLEANUP ---
            try
            {
                key.DeleteValue("ServerUrl", throwOnMissingValue: false);
                key.DeleteValue("EnrollmentKey", throwOnMissingValue: false);
                _logger.LogInformation("Bootstrap complete. Deployment registry keys securely removed.");
                SafeLogEvent("Bootstrap complete. Deployment registry keys securely removed.", EventLogEntryType.Information);
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Failed to clean registry keys: {ex.Message}");
            }

            return state;
        }

        private AgentState LoadSecureState()
        {
            try
            {
                byte[] encryptedState = File.ReadAllBytes(StateFilePath);
                byte[] decryptedBytes = ProtectedData.Unprotect(encryptedState, null, DataProtectionScope.LocalMachine);
                return JsonSerializer.Deserialize<AgentState>(Encoding.UTF8.GetString(decryptedBytes));
            }
            catch (Exception ex)
            {
                _logger.LogError($"CRITICAL: Failed to decrypt state.dat. {ex.Message}");
                return null;
            }
        }

        private async Task PerformCheckInAsync(AgentState state, CancellationToken stoppingToken)
        {
            _logger.LogInformation($"--- Initiating Secure Heartbeat to {state.ServerUrl} ---");

            var checkInData = new
            {
                deviceId = state.DeviceId,
                timestamp = DateTime.UtcNow.ToString("o"),
                osVersion = Environment.OSVersion.ToString(),
                inventory = GetHardwareInventory()
            };
            string rawPayload = JsonSerializer.Serialize(checkInData);

            string signatureBase64 = SignData(rawPayload, state.ClientPrivateKey);

            var secureMessage = new
            {
                deviceId = state.DeviceId,
                payload = rawPayload,
                signature = signatureBase64
            };

            var content = new StringContent(JsonSerializer.Serialize(secureMessage), Encoding.UTF8, "application/json");

            try
            {
                HttpResponseMessage response = await httpClient.PostAsync($"{state.ServerUrl}/api/checkin", content, stoppingToken);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning($"Heartbeat Failed. Server returned {response.StatusCode}");
                    return;
                }

                string responseBody = await response.Content.ReadAsStringAsync(stoppingToken);
                using JsonDocument doc = JsonDocument.Parse(responseBody);

                foreach (var commandObj in doc.RootElement.GetProperty("pendingCommands").EnumerateArray())
                {
                    if (stoppingToken.IsCancellationRequested) break;

                    int commandId = commandObj.GetProperty("commandId").GetInt32();
                    string serverRawPayload = commandObj.GetProperty("rawPayload").GetString();
                    string serverSignatureBase64 = commandObj.GetProperty("signature").GetString();

                    if (VerifySignature(serverRawPayload, serverSignatureBase64, state.ServerPublicKey))
                    {
                        _logger.LogInformation($"Verified: Server Signature is valid. Executing command ID {commandId}...");

                        var result = await ExecuteCommandAsync(commandId, serverRawPayload, stoppingToken);

                        await SendTelemetryAsync(state, commandId, result.Status, result.ExitCode, result.Message, stoppingToken);
                    }
                    else
                    {
                        _logger.LogWarning("WARNING: Invalid Server signature detected! Dropping command.");
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Ignoring cancellation during shutdown
            }
            catch (Exception ex)
            {
                _logger.LogError($"Check-in error: {ex.Message}");
            }
        }

        private bool VerifySignature(string data, string signatureBase64, string publicKeyPem)
        {
            try
            {
                using RSA rsa = RSA.Create();
                rsa.ImportFromPem(publicKeyPem.ToCharArray());

                byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                byte[] signatureBytes = Convert.FromBase64String(signatureBase64);

                return rsa.VerifyData(dataBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            catch
            {
                return false;
            }
        }

        private string SignData(string data, string privateKeyBase64)
        {
            try
            {
                using RSA rsa = RSA.Create();
                byte[] privateKeyBytes = Convert.FromBase64String(privateKeyBase64);
                rsa.ImportRSAPrivateKey(privateKeyBytes, out _);

                byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                byte[] signatureBytes = rsa.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                return Convert.ToBase64String(signatureBytes);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Signing failed: {ex.Message}");
                return null;
            }
        }

        private async Task<(string Status, int ExitCode, string Message)> ExecuteCommandAsync(int commandId, string jsonPayload, CancellationToken stoppingToken)
        {
            using JsonDocument doc = JsonDocument.Parse(jsonPayload);
            string action = doc.RootElement.GetProperty("Action").GetString();

            string logMessage = $"Processing command.\nAction: {action}";
            SafeLogEvent(logMessage, EventLogEntryType.Information);

            if (action == "WriteLog")
            {
                string message = doc.RootElement.GetProperty("Message").GetString();
                _logger.LogInformation($"[SERVER COMMAND]: {message}");
                return ("Completed", 0, "Log written successfully.");
            }
            else if (action == "InstallApp")
            {
                string name = doc.RootElement.GetProperty("Name").GetString();
                string url = doc.RootElement.GetProperty("Url").GetString();
                string expectedHash = doc.RootElement.GetProperty("Hash").GetString();
                string arguments = doc.RootElement.GetProperty("Arguments").GetString();

                string installTiming = "Immediate";
                if (doc.RootElement.TryGetProperty("InstallTiming", out JsonElement timingElement))
                {
                    installTiming = timingElement.GetString();
                }

                _logger.LogInformation($"[DEPLOYMENT] Starting installation pipeline for {name} (Timing: {installTiming})...");
                return await HandleAppInstallationAsync(commandId, name, url, expectedHash, arguments, installTiming, stoppingToken);
            }
            else if (action == "SetRegistry")
            {
                string name = doc.RootElement.GetProperty("Name").GetString();
                string keyPath = doc.RootElement.GetProperty("RegistryKey").GetString();
                string valueName = doc.RootElement.GetProperty("ValueName").GetString();
                int value = doc.RootElement.GetProperty("Value").GetInt32();

                _logger.LogInformation($"[POLICY] Enforcing policy: {name}");
                return ApplyRegistryPolicy(name, keyPath, valueName, value);
            }
            else if (action == "SetRegistryComplex")
            {
                string name = doc.RootElement.GetProperty("PolicyName").GetString();
                string keyPath = doc.RootElement.GetProperty("BaseRegistryKey").GetString();
                JsonElement registryEdits = doc.RootElement.GetProperty("RegistryEdits");

                _logger.LogInformation($"[POLICY] Enforcing complex policy: {name}");
                return ApplyComplexRegistryPolicy(name, keyPath, registryEdits);
            }

            return ("Failed", -1, $"Unknown action: {action}");
        }

        private async Task SendTelemetryAsync(AgentState state, int commandId, string status, int exitCode, string message, CancellationToken stoppingToken)
        {
            _logger.LogInformation($"--- Sending Telemetry for Command {commandId} ({status}) ---");

            var telemetryData = new
            {
                commandId = commandId,
                executionStatus = status,
                exitCode = exitCode,
                resultMessage = message
            };
            string rawPayload = JsonSerializer.Serialize(telemetryData);

            string signatureBase64 = SignData(rawPayload, state.ClientPrivateKey);

            var secureMessage = new
            {
                deviceId = state.DeviceId,
                payload = rawPayload,
                signature = signatureBase64
            };

            var content = new StringContent(JsonSerializer.Serialize(secureMessage), Encoding.UTF8, "application/json");

            try
            {
                HttpResponseMessage response = await httpClient.PostAsync($"{state.ServerUrl}/api/telemetry", content, stoppingToken);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning($"WARNING: Failed to send telemetry. Server returned {response.StatusCode}");
                }
                else
                {
                    _logger.LogInformation($"Telemetry acknowledged by server.");
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                _logger.LogError($"Telemetry network error: {ex.Message}");
            }
        }

        private HardwareInventory GetHardwareInventory()
        {
            var inventory = new HardwareInventory();
            try
            {
                using CimSession session = CimSession.Create(null);

                var biosInstances = session.QueryInstances(@"root\cimv2", "WQL", "SELECT SerialNumber FROM Win32_BIOS");
                foreach (var instance in biosInstances)
                {
                    inventory.SerialNumber = instance.CimInstanceProperties["SerialNumber"]?.Value?.ToString()?.Trim() ?? "Unknown";
                    break;
                }

                var cpuInstances = session.QueryInstances(@"root\cimv2", "WQL", "SELECT Name FROM Win32_Processor");
                foreach (var instance in cpuInstances)
                {
                    inventory.Processor = instance.CimInstanceProperties["Name"]?.Value?.ToString()?.Trim() ?? "Unknown";
                    break;
                }

                var ramInstances = session.QueryInstances(@"root\cimv2", "WQL", "SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
                foreach (var instance in ramInstances)
                {
                    if (ulong.TryParse(instance.CimInstanceProperties["TotalPhysicalMemory"]?.Value?.ToString(), out ulong bytes))
                    {
                        inventory.RamMb = (int)(bytes / (1024 * 1024));
                    }
                    break;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"WARNING: Failed to query CIM hardware inventory: {ex.Message}");
            }

            return inventory;
        }

        private async Task<(string Status, int ExitCode, string Message)> HandleAppInstallationAsync(int commandId, string appName, string url, string expectedHash, string arguments, string installTiming, CancellationToken stoppingToken)
        {
            if (!Directory.Exists(CacheDirPath)) Directory.CreateDirectory(CacheDirPath);

            string extension = Path.GetExtension(new Uri(url).AbsolutePath);
            if (string.IsNullOrEmpty(extension)) extension = ".exe";

            string filePath = Path.Combine(CacheDirPath, $"{Guid.NewGuid()}{extension}");

            try
            {
                _logger.LogInformation($"Downloading {appName} from vendor CDN...");

                string currentUrl = url;
                int maxRedirects = 10;
                HttpResponseMessage response = null;

                for (int i = 0; i < maxRedirects; i++)
                {
                    var request = new HttpRequestMessage(HttpMethod.Get, currentUrl);
                    // Explicitly add a User-Agent to bypass 403 Forbidden checks on GitHub/Cloudflare CDNs
                    request.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) MiniDMAgent/1.0");

                    response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, stoppingToken);

                    if (response.StatusCode == System.Net.HttpStatusCode.MovedPermanently ||
                        response.StatusCode == System.Net.HttpStatusCode.Redirect ||
                        response.StatusCode == System.Net.HttpStatusCode.RedirectMethod ||
                        response.StatusCode == System.Net.HttpStatusCode.RedirectKeepVerb ||
                        (int)response.StatusCode == 308) // Handle modern 308 Permanent Redirects
                    {
                        var location = response.Headers.Location;
                        if (location == null) throw new Exception("Received HTTP Redirect but no Location header was provided.");

                        string newUrl = location.IsAbsoluteUri ? location.AbsoluteUri : new Uri(new Uri(currentUrl), location).AbsoluteUri;
                        _logger.LogInformation($"[Redirect {(int)response.StatusCode}] Following redirect to: {newUrl}");

                        currentUrl = newUrl;
                        response.Dispose(); // Clean up the old response
                        continue;
                    }

                    response.EnsureSuccessStatusCode();
                    break; // We have a successful 200 OK response
                }

                if (response == null || !response.IsSuccessStatusCode)
                {
                    throw new Exception($"Download failed. Exceeded maximum redirects or received invalid status code.");
                }

                // Safely stream the payload to disk
                using (var streamToReadFrom = await response.Content.ReadAsStreamAsync(stoppingToken))
                using (var streamToWriteTo = File.Open(filePath, FileMode.Create))
                {
                    await streamToReadFrom.CopyToAsync(streamToWriteTo, stoppingToken);
                }

                // Clean up the final response
                response.Dispose();

                // --- CACHE INTERCEPTION LOGIC ---
                if (installTiming.Equals("OnStartup", StringComparison.OrdinalIgnoreCase))
                {
                    var pendingInstall = new PendingInstall
                    {
                        CommandId = commandId,
                        AppName = appName,
                        FilePath = filePath,
                        Arguments = arguments,
                        Extension = extension
                    };

                    List<PendingInstall> queue = new List<PendingInstall>();
                    if (File.Exists(PendingInstallsFilePath))
                    {
                        queue = JsonSerializer.Deserialize<List<PendingInstall>>(await File.ReadAllTextAsync(PendingInstallsFilePath, stoppingToken)) ?? new List<PendingInstall>();
                    }

                    queue.Add(pendingInstall);
                    await File.WriteAllTextAsync(PendingInstallsFilePath, JsonSerializer.Serialize(queue), stoppingToken);

                    string cacheMsg = $"Downloaded and securely cached {appName}. Execution scheduled for next system startup.";
                    _logger.LogInformation(cacheMsg);
                    SafeLogEvent(cacheMsg, EventLogEntryType.Information);

                    return ("PendingReboot", 0, cacheMsg);
                }

                // --- STANDARD IMMEDIATE EXECUTION ---
                _logger.LogInformation($"Hash verified. Executing silently: {arguments}");

                var processInfo = new ProcessStartInfo
                {
                    FileName = filePath,
                    Arguments = arguments,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                if (extension.Equals(".msi", StringComparison.OrdinalIgnoreCase))
                {
                    processInfo.FileName = "msiexec.exe";
                    string safeArgs = arguments.Replace("/silent", "/qn", StringComparison.OrdinalIgnoreCase)
                                               .Replace("/S", "/qn", StringComparison.OrdinalIgnoreCase);

                    processInfo.Arguments = $"/i \"{filePath}\" {safeArgs}";
                }

                using Process process = Process.Start(processInfo);

                // Create a linked token combining the service shutdown token and our 15 min kill switch
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                cts.CancelAfter(TimeSpan.FromMinutes(15));

                try
                {
                    await process.WaitForExitAsync(cts.Token);
                }
                catch (OperationCanceledException)
                {
                    if (!process.HasExited)
                    {
                        process.Kill(true);

                        // If the shutdown token triggered this, we just exit cleanly
                        if (stoppingToken.IsCancellationRequested)
                        {
                            _logger.LogWarning($"Service is stopping, killing installer for {appName}.");
                            throw;
                        }

                        // Otherwise, it was the 15 minute timeout
                        string timeoutMsg = $"CRITICAL: Installer for {appName} hung indefinitely (likely blocked by a hidden UI prompt). Process forcefully terminated to prevent queue lockup.";
                        _logger.LogError(timeoutMsg);
                        SafeLogEvent(timeoutMsg, EventLogEntryType.Error);

                        if (File.Exists(filePath)) File.Delete(filePath);
                        return ("Failed", 1460, timeoutMsg);
                    }
                }

                string successMsg = $"Successfully installed {appName}. Exit Code: {process.ExitCode}";
                _logger.LogInformation(successMsg);
                SafeLogEvent(successMsg, EventLogEntryType.Information);

                if (File.Exists(filePath)) File.Delete(filePath);

                return ("Completed", process.ExitCode, successMsg);

            }
            catch (OperationCanceledException)
            {
                if (File.Exists(filePath)) File.Delete(filePath);
                throw; // Let the service shutdown cleanly
            }
            catch (Exception ex)
            {
                string errorMsg = $"Deployment failed for {appName}: {ex.Message}";
                _logger.LogError(errorMsg);
                SafeLogEvent(errorMsg, EventLogEntryType.Error);

                if (File.Exists(filePath)) File.Delete(filePath);
                return ("Failed", -1, errorMsg);
            }
        }

        private (string Status, int ExitCode, string Message) ApplyRegistryPolicy(string policyName, string keyPath, string valueName, int value)
        {
            try
            {
                using (RegistryKey baseKey = Registry.LocalMachine.CreateSubKey(keyPath, writable: true))
                {
                    if (baseKey != null)
                    {
                        baseKey.SetValue(valueName, value, RegistryValueKind.DWord);

                        string successMsg = $"Successfully enforced policy '{policyName}'. Set HKLM\\{keyPath}\\{valueName} to {value}.";
                        _logger.LogInformation(successMsg);
                        SafeLogEvent(successMsg, EventLogEntryType.Information);

                        return ("Completed", 0, successMsg);
                    }
                    else
                    {
                        throw new Exception("Failed to open or create the registry key path.");
                    }
                }
            }
            catch (Exception ex)
            {
                string errorMsg = $"Policy enforcement failed for '{policyName}': {ex.Message}";
                _logger.LogError(errorMsg);
                SafeLogEvent(errorMsg, EventLogEntryType.Error);

                return ("Failed", -1, errorMsg);
            }
        }

        private (string Status, int ExitCode, string Message) ApplyComplexRegistryPolicy(string policyName, string baseKeyPath, JsonElement registryEdits)
        {
            try
            {
                using (RegistryKey baseKey = Registry.LocalMachine.CreateSubKey(baseKeyPath, writable: true))
                {
                    if (baseKey == null)
                    {
                        throw new Exception($"Failed to open or create the registry key path: {baseKeyPath}");
                    }

                    int editCount = 0;

                    foreach (JsonElement edit in registryEdits.EnumerateArray())
                    {
                        string valueName = edit.GetProperty("ValueName").GetString();
                        string valueType = edit.GetProperty("ValueType").GetString();

                        if (valueType.Equals("DWORD", StringComparison.OrdinalIgnoreCase))
                        {
                            int val = edit.GetProperty("Value").GetInt32();
                            baseKey.SetValue(valueName, val, RegistryValueKind.DWord);
                            _logger.LogInformation($" -> Set DWORD: {valueName} = {val}");
                        }
                        else
                        {
                            string val = edit.GetProperty("Value").ToString();
                            baseKey.SetValue(valueName, val, RegistryValueKind.String);
                            _logger.LogInformation($" -> Set STRING: {valueName} = {val}");
                        }

                        editCount++;
                    }

                    string successMsg = $"Successfully enforced policy '{policyName}'. Applied {editCount} registry edits to HKLM\\{baseKeyPath}.";
                    _logger.LogInformation(successMsg);
                    SafeLogEvent(successMsg, EventLogEntryType.Information);

                    return ("Completed", 0, successMsg);
                }
            }
            catch (Exception ex)
            {
                string errorMsg = $"Policy enforcement failed for '{policyName}': {ex.Message}";
                _logger.LogError(errorMsg);
                SafeLogEvent(errorMsg, EventLogEntryType.Error);

                return ("Failed", -1, errorMsg);
            }
        }

        private string CalculateSha256(string filePath)
        {
            using var sha256 = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            byte[] hash = sha256.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        private void SafeLogEvent(string message, EventLogEntryType type)
        {
            try
            {
                // Explicitly call the native System.Diagnostics method here
                System.Diagnostics.EventLog.WriteEntry(EventSourceName, message, type);
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Failed to write to Windows Event Log: {message}. Reason: {ex.Message}");
            }
        }

        private async Task ProcessCachedInstallsAsync(AgentState state, CancellationToken stoppingToken)
        {
            if (!File.Exists(PendingInstallsFilePath)) return;

            _logger.LogInformation("--- Processing Cached Pre-Login Installations ---");

            List<PendingInstall> pendingQueue;
            try
            {
                string json = await File.ReadAllTextAsync(PendingInstallsFilePath, stoppingToken);
                pendingQueue = JsonSerializer.Deserialize<List<PendingInstall>>(json) ?? new List<PendingInstall>();
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch
            {
                _logger.LogWarning("WARNING: Failed to read pending_installs.json. Cache may be corrupted.");
                return;
            }

            foreach (var install in pendingQueue.ToList())
            {
                if (stoppingToken.IsCancellationRequested) break;

                _logger.LogInformation($"Executing cached installer: {install.AppName}");
                try
                {
                    var processInfo = new ProcessStartInfo
                    {
                        FileName = install.FilePath,
                        Arguments = install.Arguments,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        WindowStyle = ProcessWindowStyle.Hidden
                    };

                    if (install.Extension.Equals(".msi", StringComparison.OrdinalIgnoreCase))
                    {
                        processInfo.FileName = "msiexec.exe";

                        string safeArgs = install.Arguments.Replace("/silent", "/qn", StringComparison.OrdinalIgnoreCase)
                                                           .Replace("/S", "/qn", StringComparison.OrdinalIgnoreCase);

                        processInfo.Arguments = $"/i \"{install.FilePath}\" {safeArgs}";
                    }

                    using Process process = Process.Start(processInfo);

                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                    cts.CancelAfter(TimeSpan.FromMinutes(15));

                    try
                    {
                        await process.WaitForExitAsync(cts.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        if (!process.HasExited)
                        {
                            process.Kill(true);

                            if (stoppingToken.IsCancellationRequested) throw;

                            string timeoutMsg = $"CRITICAL: Cached installer for {install.AppName} hung indefinitely. Process forcefully terminated.";
                            _logger.LogError(timeoutMsg);
                            SafeLogEvent(timeoutMsg, EventLogEntryType.Error);

                            if (File.Exists(install.FilePath)) File.Delete(install.FilePath);

                            await SendTelemetryAsync(state, install.CommandId, "Failed", 1460, timeoutMsg, stoppingToken);
                            continue;
                        }
                    }

                    string successMsg = $"Successfully installed {install.AppName}. Exit Code: {process.ExitCode}";
                    _logger.LogInformation(successMsg);
                    SafeLogEvent(successMsg, EventLogEntryType.Information);

                    if (File.Exists(install.FilePath)) File.Delete(install.FilePath);

                    await SendTelemetryAsync(state, install.CommandId, "Completed", process.ExitCode, successMsg, stoppingToken);
                }
                catch (OperationCanceledException) { }
                catch (Exception ex)
                {
                    string errorMsg = $"Failed to install cached app {install.AppName}: {ex.Message}";
                    _logger.LogError(errorMsg);
                    SafeLogEvent(errorMsg, EventLogEntryType.Error);

                    await SendTelemetryAsync(state, install.CommandId, "Failed", -1, errorMsg, stoppingToken);
                }
                finally
                {
                    if (File.Exists(install.FilePath)) File.Delete(install.FilePath);
                    pendingQueue.Remove(install);
                }
            }

            if (pendingQueue.Count > 0)
            {
                await File.WriteAllTextAsync(PendingInstallsFilePath, JsonSerializer.Serialize(pendingQueue), stoppingToken);
            }
            else
            {
                File.Delete(PendingInstallsFilePath);
                _logger.LogInformation("Cache cleared successfully.");
            }
        }
    }
}