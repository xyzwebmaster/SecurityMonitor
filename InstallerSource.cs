using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;

[assembly: AssemblyTitle("Whitehat Security Setup")]
[assembly: AssemblyDescription("All-in-One Whitehat Security Tool Installer")]
[assembly: AssemblyCompany("Whitehat Security")]
[assembly: AssemblyProduct("Whitehat Security")]
[assembly: AssemblyVersion("7.1.0.0")]
[assembly: AssemblyFileVersion("7.1.0.0")]

namespace WhitehatSecurity
{
    static class Setup
    {
        static int Main()
        {
            // Find Install.bat next to this EXE, or in current directory
            string exeDir = Path.GetDirectoryName(
                System.Reflection.Assembly.GetExecutingAssembly().Location);
            string batPath = Path.Combine(exeDir, "Install.bat");

            if (!File.Exists(batPath))
            {
                // If Install.bat not found next to EXE, create a temp one
                batPath = Path.Combine(Path.GetTempPath(), "WHS_Install.bat");
                File.WriteAllText(batPath, string.Join("\r\n",
                    "@echo off",
                    "title Whitehat Security - Installer",
                    "echo.",
                    "echo   =============================================",
                    "echo    All-in-One Whitehat Security Tool - Setup",
                    "echo   =============================================",
                    "echo.",
                    "echo   Requesting administrator privileges...",
                    "echo.",
                    "powershell -Command \"Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command \\\"[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; iwr https://raw.githubusercontent.com/xyzwebmaster/All-in-One-Whitehat-Security-Tool/master/Install.ps1 -OutFile $env:TEMP\\WHS_Install.ps1 -UseBasicParsing; & $env:TEMP\\WHS_Install.ps1\\\"' -Verb RunAs\"",
                    ""
                ));
            }

            var psi = new ProcessStartInfo();
            psi.FileName = "cmd.exe";
            psi.Arguments = "/c \"" + batPath + "\"";
            psi.UseShellExecute = true;

            try
            {
                Process.Start(psi);
                return 0;
            }
            catch
            {
                return 1;
            }
        }
    }
}
