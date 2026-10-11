# 📄 Dosya Yolu: /TurkuazAV/README.md
# 📌 Amac: TurkuazAV 0.3.0 GUI ve guvenli tarama test mimarisini tanimlamak
# 📌 Modul - FileType: Documentation - Markdown
# Version: 0.3.0
# Aciklama: WinUI 3 preview ile ortak Windows/Linux tarama altyapisi
# Bagimli Oldugu Katman: Controller | Service | Repo | Tool | View | Language

# TurkuazAV

TurkuazAV, coklu platform icin deneysel dosya analiz ve guvenlik
altyapisi projesidir. **Bu surum tam bir antivirus degildir.**

## Surum 0.3.0 (Windows WinUI 3 test arayuzu)

Windows uygulamasinda:

- Tek dosya secme: Windows dosya secici
- Salt okunur SHA-256 hesaplama (varsayilan dosya limiti: 100 MiB)
- Basarili, atlanan ve hatali tarama raporu
- Hash degerini kopyalamaya uygun, salt okunur rapor kutusu
- Iptal destegi ve tarama sirasinda kilitlenen tekrarli butonlar
- Oturum icinde tarama gecmisi (bellekte, diske kaydedilmez)
- Acik bir deneysel surum/bagimsiz antivirus uyarisı

Windows arayuzu **yalnizca SHA-256 dosya ozeti** hesaplar.
YARA-X ve trusted publisher altyapisi 0.2.x serisinde ortak
Core/CLI uzerinde korunur, GUI'ye henuz acilmamistir.
SHA-256 ozeti tek basina zararlilik karari vermez.

## Gelistirme

.NET 10 SDK gerekir. Windows GUI projesi icin Windows App SDK 2.5.1
kullanilir. Proje WinUI 3 ve **unpackaged / self-contained**
derleme ayarlarina sahiptir. Yalnizca Windows x64 hedeflenir.

```powershell
dotnet restore src/TurkuazAV.Desktop/TurkuazAV.Desktop.csproj -p:Platform=x64
dotnet build src/TurkuazAV.Desktop/TurkuazAV.Desktop.csproj -c Release -p:Platform=x64
```

Windows'ta olusan TurkuazAV.Desktop.exe uygulamasi ile dosya
secebilir ve tek dosya taramasi yapabilirsiniz.
Bu bir *CI derleme dogrulamasi* olup, otomatik GUI calistirma
ve ekrandan test (UI automation) henuz bulunmamaktadir.
Windows GUI ilk dogrulamasi GitHub-hosted Windows 2022 runner
uzerinde; Linux ortak motor CI'si eskisi gibi devam eder.

## CLI ve guvenlik regresyonlari

```text
dotnet run --project src/TurkuazAV.Cli -- scan .
dotnet run --project tests/TurkuazAV.SmokeTests
pwsh ./tools/install-yarax.ps1
dotnet run --project tests/TurkuazAV.IntegrationTests
```

YARA-X entegrasyon testlerinde `TURKUAZ_YR_PATH` dogrulanmis
`yr` programina yonlendirilmelidir (CI'da installer ayarlar).

Gelistirici CLI komutu:

```text
dotnet run --project src/TurkuazAV.Cli -- scan-rules TARGET RULES.YAR RULES.SIG PUBLIC.PEM ABSOLUTE_YR_PATH
```

Bu komutun kullanicidan kabul ettigi public key bir uretim
yayinci guven koku degildir; sadece gelistirme amaclidir.
Publisher-pinned trusted rule scanner su anda sadece Core
kutuphane API'sinde ve Windows/Linux E2E regresyonlarinda
kullanilmaktadir.

## Guvenlik sinirlari

- Henuz gercek zamanli koruma, karantina, driver veya AV verdict yok.
- Program dosya icerigini silmez/degistirmez; sadece salt-okunur acar.
- Yeni GUI'de YARA-X motora erisim verilmez: hash raporu uretilir.
- SHA-256 sonucunun temiz olmasi otomatik olarak guvenilir demek degildir.
- Dosya taranirken disk icerigi degisebilir.
- Windows test arayuzu Linux/macOS ile ayni UI degildir;
  ortak Core degismez. MacOS icin runner henuz yoktur.
- Public repo icin kaynak kod lisansi henuz secilmemistir.

Mimari: Controller -> Service -> Repo/Tool -> View -> Language + Config.

[Guvenlik modeli](docs/security-model.md).
