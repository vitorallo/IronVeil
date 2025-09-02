using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.Text;

namespace IronVeil.PowerShell
{
    public class SessionLogger : IDisposable
    {
        private readonly StreamWriter _logWriter;
        private readonly string _sessionId;
        private readonly string _logFilePath;
        private readonly ILogger? _logger;

        public SessionLogger(string sessionId, ILogger? logger = null)
        {
            _sessionId = sessionId;
            _logger = logger;
            
            // Create timestamp-based log file name
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var logFileName = $"session_{timestamp}_log.txt";
            _logFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, logFileName);
            
            // Initialize file writer with UTF-8 encoding and auto-flush
            _logWriter = new StreamWriter(_logFilePath, false, Encoding.UTF8) { AutoFlush = true };
            
            WriteHeader();
        }

        private void WriteHeader()
        {
            var header = $@"================================================================================
IRONVEIL SECURITY SCANNER - SESSION LOG
================================================================================
Session ID: {_sessionId}
Start Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}
Application: IronVeil Desktop Scanner
PowerShell SDK: {Environment.Version}
OS: {Environment.OSVersion}
Working Directory: {Environment.CurrentDirectory}
Log File: {_logFilePath}
================================================================================

";
            _logWriter.Write(header);
        }

        public void LogInfo(string message, params object[] args)
        {
            var formattedMessage = string.Format(message, args);
            var logEntry = $"[{DateTime.Now:HH:mm:ss.fff}] INFO: {formattedMessage}";
            _logWriter.WriteLine(logEntry);
            _logger?.LogInformation(formattedMessage);
        }

        public void LogWarning(string message, params object[] args)
        {
            var formattedMessage = string.Format(message, args);
            var logEntry = $"[{DateTime.Now:HH:mm:ss.fff}] WARN: {formattedMessage}";
            _logWriter.WriteLine(logEntry);
            _logger?.LogWarning(formattedMessage);
        }

        public void LogError(string message, Exception? exception = null, params object[] args)
        {
            var formattedMessage = string.Format(message, args);
            var logEntry = $"[{DateTime.Now:HH:mm:ss.fff}] ERROR: {formattedMessage}";
            
            if (exception != null)
            {
                logEntry += $"\nException: {exception.GetType().Name}: {exception.Message}\nStack Trace:\n{exception.StackTrace}";
            }
            
            _logWriter.WriteLine(logEntry);
            _logger?.LogError(exception, formattedMessage);
        }

        public void LogDebug(string message, params object[] args)
        {
            var formattedMessage = string.Format(message, args);
            var logEntry = $"[{DateTime.Now:HH:mm:ss.fff}] DEBUG: {formattedMessage}";
            _logWriter.WriteLine(logEntry);
            _logger?.LogDebug(formattedMessage);
        }

        public void LogRuleExecution(string ruleId, string ruleName, string status, double executionTime, string? error = null)
        {
            var logEntry = $@"
================================================================================
RULE EXECUTION: {ruleId} - {ruleName}
================================================================================
Status: {status}
Execution Time: {executionTime:F3}s
Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}";

            if (!string.IsNullOrEmpty(error))
            {
                logEntry += $"\nError Details:\n{error}";
            }

            logEntry += "\n================================================================================\n";

            _logWriter.WriteLine(logEntry);
        }

        public void LogPowerShellScript(string ruleId, string scriptContent)
        {
            var logEntry = $@"
--------------------------------------------------------------------------------
POWERSHELL SCRIPT EXECUTION: {ruleId}
--------------------------------------------------------------------------------
Script Content:
{scriptContent}
--------------------------------------------------------------------------------
";
            _logWriter.WriteLine(logEntry);
        }

        public void LogSection(string sectionName, string content)
        {
            var logEntry = $@"
================================================================================
{sectionName.ToUpper()}
================================================================================
{content}
================================================================================
";
            _logWriter.WriteLine(logEntry);
        }

        public void LogSeparator(string text = "")
        {
            if (string.IsNullOrEmpty(text))
            {
                _logWriter.WriteLine("--------------------------------------------------------------------------------");
            }
            else
            {
                _logWriter.WriteLine($"---------------- {text} ----------------");
            }
        }

        public string LogFilePath => _logFilePath;

        public void Dispose()
        {
            var footer = $@"
================================================================================
SESSION END
================================================================================
End Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}
Session Duration: {DateTime.Now - DateTime.Parse(_logWriter.ToString() ?? DateTime.Now.ToString())}
Log File: {_logFilePath}
================================================================================
";
            _logWriter.Write(footer);
            _logWriter?.Dispose();
        }
    }
}