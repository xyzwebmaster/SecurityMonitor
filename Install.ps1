#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SecurityMonitor kurulum scripti
.DESCRIPTION
    Izleme scriptini Windows baslangicindan otomatik calistirir
    ve gerekli ayarlari yapar.
#>

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$monitorScript = Join-Path $scriptDir "SecurityMonitor.ps1"

Write-Host "=== SecurityMonitor Kurulum ===" -ForegroundColor Cyan

# 1. Execution policy ayarla (sadece bu script icin)
Write-Host "[1/4] PowerShell calistirma politikasi kontrol ediliyor..."
$currentPolicy = Get-ExecutionPolicy -Scope CurrentUser
if ($currentPolicy -eq "Restricted") {
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force
    Write-Host "  -> ExecutionPolicy RemoteSigned olarak ayarlandi" -ForegroundColor Green
} else {
    Write-Host "  -> Mevcut politika: $currentPolicy (uygun)" -ForegroundColor Green
}

# 2. Zamanlanmis gorev olustur (sistem baslangicinda calisir)
Write-Host "[2/4] Zamanlanmis gorev olusturuluyor..."
$taskName = "SecurityMonitor"
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "  -> Mevcut gorev kaldirildi" -ForegroundColor Yellow
}

$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$monitorScript`" -Silent"

$trigger = New-ScheduledTaskTrigger -AtLogon
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Sistem guvenlik izleme araci" | Out-Null
Write-Host "  -> Zamanlanmis gorev olusturuldu (her oturumda otomatik baslar)" -ForegroundColor Green

# 3. Log dizinlerini olustur
Write-Host "[3/4] Dizinler olusturuluyor..."
$dirs = @("$scriptDir\Logs", "$scriptDir\Baselines")
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}
Write-Host "  -> Log ve Baseline dizinleri olusturuldu" -ForegroundColor Green

# 4. Ilk baseline'i hemen olustur
Write-Host "[4/4] Ilk baseline olusturuluyor..."
Write-Host "  -> Bu islem birkaç dakika surebilir..." -ForegroundColor Yellow
& $monitorScript -Silent 2>$null &
Start-Sleep -Seconds 2

Write-Host ""
Write-Host "=== Kurulum Tamamlandi ===" -ForegroundColor Green
Write-Host ""
Write-Host "Kullanim:" -ForegroundColor Cyan
Write-Host "  Baslatma  : powershell -ExecutionPolicy Bypass -File `"$monitorScript`"" -ForegroundColor White
Write-Host "  Sessiz mod: powershell -ExecutionPolicy Bypass -File `"$monitorScript`" -Silent" -ForegroundColor White
Write-Host "  Kaldirma  : Unregister-ScheduledTask -TaskName 'SecurityMonitor'" -ForegroundColor White
Write-Host ""
Write-Host "Log dosyalari: $scriptDir\Logs\" -ForegroundColor Cyan
Write-Host "Baseline:      $scriptDir\Baselines\" -ForegroundColor Cyan
