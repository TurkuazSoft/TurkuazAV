# 📄 Dosya Yolu: /TurkuazAV/README.md
# 📌 Amac: TurkuazAV 0.2.2 kurulumunu, kullanimi ve guvenlik sinirlarini aciklamak
# 📌 Modul - FileType: Documentation - Markdown
# Version: 0.2.2
# Aciklama: Imzali kural tarama ve motor binary butunluk denetimi
# Bagimli Oldugu Katman: Controller | Service | Repo | Tool | View | Language

# TurkuazAV

TurkuazAV, coklu platform hedefli deneysel ve salt-okunur dosya analiz
projesidir. Bu kod henuz antivirus korumasi sunmaz.

## 0.2.2 neler sunuyor?

- Platform bagimsiz .NET 10 SHA-256 dosya envanteri
- RSA-PSS-SHA256 dogrulanmis kaynak YARA-X kurallarini analiz etme
- YARA-X v1.21.0 resmi arsiv paketlerini sabit SHA-256 ile dogrulama
- Windows x64 ve Linux x64 `yr` binary SHA-256 pinleme; her calistirmadan
  once ikili dosyanin hash degerini kontrol etme
- Hedef dosyanin boyut sinirli gecici kopyasini tarama
- Windows ve Linux E2E: zararsiz eslesen/eslesmeyen ornekler,
  bozuk kural imzasi, bozuk motor dosyasi testi

## Gelistirme

.NET 10 SDK ve resmi YARA-X CLI gerekir.

```text
dotnet run --project src/TurkuazAV.Cli -- scan .
dotnet run --project tests/TurkuazAV.SmokeTests
pwsh ./tools/install-yarax.ps1
dotnet run --project tests/TurkuazAV.IntegrationTests
```

CI'da installer `TURKUAZ_YR_PATH` ortam degiskenini ayarlar.
Yerel testte YARA-X programina giden mutlak yolu bu ortam
degiskenine kendiniz atamalisiniz.

Kural tarama komutu:

```text
dotnet run --project src/TurkuazAV.Cli -- scan-rules TARGET RULES.YAR RULES.SIG PUBLIC.PEM ABSOLUTE_YR_PATH
```

`RULES.SIG`, `RULES.YAR` dosyasinin ham baytlarina RSA-PSS-SHA256
imzasi olmalidir. `PUBLIC.PEM` SubjectPublicKeyInfo formatindadir
ve RSA key uzunlugu en az 2048 bittir.

## Guvenlik sinirlari

- **Gelistirici kullanimina ozeldir:** CLI acik anahtari kullanicidan
  kabul ettigi icin henüz bir *yayinci guven kokune* bagli degildir.
  Gecersiz imzayi reddetmesi tek basina uretim guvenligi saglamaz.
- Engine hashleri, belirli YARA-X v1.21.0 Windows x64 ve Linux x64
  dosyalarini kabul eder. Baska surum, mimari ya da degistirilmis
  binary reddedilir. macOS icin henuz guven profili yoktur.
- Hash kontrolu ve Process.Start arasinda dar bir dosya degistirme
  yarisi olabilir. Tam calistirma izolasyonu ve guvenli deployment
  henuz bulunmuyor.
- Hedef snapshot kopyalanirken kaynak dosyanin degistirilmesi
  tamamen engellenmez.
- Kural eslesmesi malware verdict degildir. Karantina, otomatik
  silme, gercek zamanli izleme ve kernel surucusu bulunmaz.
- Ozel imzalama anahtari bu repoya veya CI loglarina eklenmemelidir.
- Public repo kaynak lisansi henuz belirlenmemistir.

## Katmanlar

Controller -> Service -> Repo/Tool -> View -> Language,
ortak ayarlar Config katmaninda.

## Siradaki adim

Uretim kural guven kokunun sahibini belirleme, anahtar rotasyonu,
guvenli motor kurulumu, sandbox, Windows WinUI test arayuzu.
