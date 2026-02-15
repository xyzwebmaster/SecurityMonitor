# SecurityMonitor - Sistem Guvenlik Izleme Araci

Donanim ve sistem seviyesinde surekli guvenlik izleme yapan PowerShell tabanli arac.

## Ozellikler

- **Ag Baglantisi Izleme**: Tum dis baglantilari anlik takip eder, bilinmeyen baglantilarda uyari verir
- **Surec Izleme**: Yeni baslayan surecleri yakalar, imzasiz surecleri raporlar
- **Firmware Butunluk Kontrolu**: Surucu ve firmware dosyalarinin SHA-256 hashlerini izler, degisiklik tespit eder
- **Surucu Izleme**: Yeni yuklenen veya kaldirilan suruculer icin uyari uretir
- **Servis Izleme**: Yeni eklenen servisleri tespit eder
- **Kayit Defteri Izleme**: Kritik baslangiç anahtarlarindaki degisiklikleri yakalar
- **Guvenlik Olayi Izleme**: Windows Event Log'dan sifeli giris, basarisiz giris denemeleri, yeni hesap olusturma gibi olaylari izler
- **RDP Izleme**: Uzak Masaustu etkinlestirildiginde aninda uyari verir
- **Hosts Dosyasi Izleme**: DNS yonlendirme degisikliklerini tespit eder
- **Zaman Damgali Loglama**: Tum olaylar mahkemede kanit olarak kullanilabilecek formatta kaydedilir

## Gereksinimler

- Windows 10/11
- PowerShell 5.1+
- Yonetici (Administrator) yetkileri

## Kurulum

```powershell
# Yonetici olarak PowerShell acin
cd C:\Users\<kullanici>\SecurityMonitor
powershell -ExecutionPolicy Bypass -File Install.ps1
```

## Kullanim

```powershell
# Normal mod (konsol ciktisi ile)
powershell -ExecutionPolicy Bypass -File SecurityMonitor.ps1

# Sessiz mod (sadece uyarilarda bildirim)
powershell -ExecutionPolicy Bypass -File SecurityMonitor.ps1 -Silent

# Ozel tarama araligi (5 saniye)
powershell -ExecutionPolicy Bypass -File SecurityMonitor.ps1 -IntervalSeconds 5
```

## Log Dosyalari

| Dosya | Icerik |
|-------|--------|
| `Logs/monitor_YYYY-MM-DD.log` | Genel izleme kayitlari |
| `Logs/alerts_YYYY-MM-DD.log` | Sadece uyari olaylari |
| `Logs/connections_YYYY-MM-DD.log` | Ag baglanti gecmisi |
| `Logs/processes_YYYY-MM-DD.log` | Surec baslama/kapanma kayitlari |

## Baseline Dosyalari

| Dosya | Icerik |
|-------|--------|
| `Baselines/firmware_hashes.json` | Firmware/surucu dosyasi hashleri |
| `Baselines/driver_baseline.json` | Yuklu surucu listesi |
| `Baselines/service_baseline.json` | Servis listesi |

## Kaldirma

```powershell
Unregister-ScheduledTask -TaskName "SecurityMonitor" -Confirm:$false
```

## Lisans

MIT
