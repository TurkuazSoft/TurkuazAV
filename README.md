# 📄 Dosya Yolu: /TurkuazAV/README.md
# 📌 Amac: Guvenilir kural taramasi entegrasyonunu ve urun sinirlarini belgelemek
# 📌 Modul - FileType: Documentation - Markdown
# Version: 0.2.4
# Aciklama: Guvenilir kural taramasi entegrasyonunu ve urun sinirlarini belgelemek
# Bagimli Oldugu Katman: Controller | Service | Repo | Tool | View | Language

# TurkuazAV

TurkuazAV, Windows ve Linux icin gelistirilen deneysel, salt-okunur
dosya analiz projesidir. **Uretim antivirus korumasi saglamaz.**

## 0.2.4

- Ortak .NET 10 dosya envanteri / SHA-256 hesaplama
- YARA-X v1.21.0 Windows x64 / Linux x64 dogrulanmis executable
- RSA-PSS-SHA256 kaynak kurali dogrulama
- Onceden guvenilmis yayinci public key listesi (library bootstrap)
- Imzali ve surumlu manifest, kural SHA-256 denetimi
- Yeni `TrustedRuleScanService`: **dogrula -> snapshot -> gercek
  YARA-X taramasi -> basariliysa surum kaydet**
- Kalici 40-byte anti-rollback state: 8-byte sequence + 32-byte
  imzali manifest fingerprint. Ayni sequence ile degisik imzali paket
  reddedilir, daha eski sequence reddedilir.
- Gercek YARA-X E2E testi: trusted publisher, pozitif/negatif eslesme,
  sequence conflict, rollback, sahte engine, motor hatasi ve bozulmus kural
- Windows/Linux CI dogrulamasi (PR ve main)

## Gelistirme

.NET 10 SDK ile:

```text
dotnet run --project src/TurkuazAV.Cli -- scan .
dotnet run --project tests/TurkuazAV.SmokeTests
pwsh ./tools/install-yarax.ps1
dotnet run --project tests/TurkuazAV.IntegrationTests
```

Son entegrasyon testleri icin `TURKUAZ_YR_PATH` degiskeninin resmi,
dogrulanmis `yr` executable yolunu gostermesi gerekir.
GitHub CI installer bu degiskeni otomatik doldurur.

Gelistirici CLI komutu:

```text
dotnet run --project src/TurkuazAV.Cli -- scan-rules TARGET RULES.YAR RULES.SIG PUBLIC.PEM ABSOLUTE_YR_PATH
```

Bu **gelistirici komutunda** acik anahtar kullanicidan alindigi icin
yayinci guven kokeni bulunmuyor. CLI uretim taramasi gibi
kullanilmamalidir.

**Yeni guvenilir yayinci akisi `TrustedRuleScanService`
kutuphane API'sine baglandi ve gercek YARA-X ile test edilir.**
Genel CLI komutu uretim trust store ile henuz baglanmadi: guvenilir
publisher public key'i/provisioning su anda bulunmuyor. Bu nedenle
uretim seviyesi `scan-trusted` komutu acilmadi.

## State migration

0.2.3'un 8-byte sequence dosyasi, 0.2.4'un sequence + manifest
fingerprint bicimine **otomatik donusturulmez**. Eski veya bozuk state
guvenli sekilde reddedilir. Uretim guncelleyici ayri, dogrulanabilir
bir migrasyon akisi saglamadan eski state'i silip yeniden baslatmayin.

## Bilinen riskler

- Yerel state dosyasinin silinmesi/geri yuklenmesi, privileged saldirgan
  ve guvensiz dizin ACL durumlarinda engellenmez.
- Ayni sequence icin imza farkli olsa da imzali manifest icerigi
  ayniysa (key ID dahil) kabul edilir.
- Guvenilen anahtarlar uygulamaya haricen onayli bootstrap ile
  alinmalidir; test anahtarlari her testte gecici uretilir.
- Tarama motoru hash dogrulamasi sonrasi Process.Start TOCTOU ve
  sandbox eksigi devam ediyor.
- File snapshot olusturma sirasinda eszamanli degisiklik riski var.
- macOS CI, WinUI GUI, karantina ve gercek zamanli koruma yok.
- Public repo kaynak lisansi henuz secilmedi.

Ek bilgi: [Security model](docs/security-model.md).
