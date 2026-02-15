#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SecurityMonitor kurulum scripti
.DESCRIPTION
    Izleme scriptini Windows baslangicindan otomatik calistirir,
    zamanlanmis gorev olusturur ve hemen baslatir.
#>

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$monitorScript = Join-Path $scriptDir "SecurityMonitor.ps1"
$taskName = "SecurityMonitor"

Write-Host "=== SecurityMonitor Kurulum ===" -ForegroundColor Cyan

# 1. Execution policy
Write-Host "[1/5] PowerShell calistirma politikasi kontrol ediliyor..."
$currentPolicy = Get-ExecutionPolicy -Scope CurrentUser
if ($currentPolicy -eq "Restricted") {
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force -ErrorAction SilentlyContinue
    Write-Host "  -> ExecutionPolicy RemoteSigned olarak ayarlandi" -ForegroundColor Green
} else {
    Write-Host "  -> Mevcut politika: $currentPolicy (uygun)" -ForegroundColor Green
}

# 2. Log dizinlerini olustur
Write-Host "[2/5] Dizinler olusturuluyor..."
$dirs = @("$scriptDir\Logs", "$scriptDir\Baselines")
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}
Write-Host "  -> Log ve Baseline dizinleri olusturuldu" -ForegroundColor Green

# 3. Zamanlanmis gorev olustur (oturum acilisinda otomatik baslar)
Write-Host "[3/5] Zamanlanmis gorev olusturuluyor..."
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "  -> Mevcut gorev kaldirildi" -ForegroundColor Yellow
}

$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$monitorScript`" -Silent"

$trigger = New-ScheduledTaskTrigger -AtLogon -User $env:USERNAME
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest -LogonType Interactive
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Days 365)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Sistem guvenlik izleme araci - otomatik baslatma" | Out-Null
Write-Host "  -> Zamanlanmis gorev olusturuldu (her oturumda otomatik baslar)" -ForegroundColor Green

# 4. Hemen baslat
Write-Host "[4/5] Izleme hemen baslatiliyor..."
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 3
$state = (Get-ScheduledTask -TaskName $taskName).State
if ($state -eq "Running") {
    Write-Host "  -> Izleme arka planda calisiyor" -ForegroundColor Green
} else {
    Write-Host "  -> Durum: $state (manuel baslatmayi deneyin)" -ForegroundColor Yellow
}

# 5. Durum ozeti
Write-Host "[5/5] Dogrulama..."
Start-Sleep -Seconds 5
$logExists = Test-Path "$scriptDir\Logs\monitor_$(Get-Date -Format 'yyyy-MM-dd').log"
if ($logExists) {
    Write-Host "  -> Log dosyasi olusturuldu, izleme aktif" -ForegroundColor Green
} else {
    Write-Host "  -> Log dosyasi henuz olusturulmadi, baseline olusturuluyor olabilir" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Kurulum Tamamlandi ===" -ForegroundColor Green
Write-Host ""
Write-Host "Durum:" -ForegroundColor Cyan
Write-Host "  Otomatik baslatma : AKTIF (her oturum acilisinda)" -ForegroundColor White
Write-Host "  Suanki durum      : $state" -ForegroundColor White
Write-Host ""
Write-Host "Komutlar:" -ForegroundColor Cyan
Write-Host "  Durumu gor  : Get-ScheduledTask -TaskName '$taskName'" -ForegroundColor White
Write-Host "  Durdur      : Stop-ScheduledTask -TaskName '$taskName'" -ForegroundColor White
Write-Host "  Baslat      : Start-ScheduledTask -TaskName '$taskName'" -ForegroundColor White
Write-Host "  Kaldir      : Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false" -ForegroundColor White
Write-Host ""
Write-Host "Log dosyalari : $scriptDir\Logs\" -ForegroundColor Cyan
Write-Host "Baseline      : $scriptDir\Baselines\" -ForegroundColor Cyan
