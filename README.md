# 📄 Dosya Yolu: /TurkuazAV/README.md
# 📌 Amac: 0.2.0 kural tarama kullanimini ve guvenlik sinirlarini belgelemek
# 📌 Modul - FileType: Markdown
# Version: 0.2.0
# Aciklama: 0.2.0 kural tarama kullanimini ve guvenlik sinirlarini belgelemek
# Bagimli Oldugu Katman: Controller | Service | Repo | Tool | View | Language

# TurkuazAV

TurkuazAV coklu platform destekli deneysel dosya tarama ve kural analiz altyapisidir.

## Durum

0.2.0: Salt okunur SHA-256 dosya envanteri ve imzali YARA-X kural eslestirmesi.
**Bu surum tam antivirus urunu degildir.** Eslesme zararlilik kaniti degildir.
Karantina, gercek zamanli koruma, otomatik silme ve EDR yoktur.

## Gereksinimler

- .NET 10 SDK
- Kural taramasi icin resmi `yr` CLI: https://github.com/VirusTotal/yara-x
- RSA-PSS-SHA256 ile imzalanmis kaynak kural dosyasi
- En az 2048-bit RSA PEM public key (SubjectPublicKeyInfo)

## Komutlar

```text
dotnet run --project src/TurkuazAV.Cli -- scan .
dotnet run --project tests/TurkuazAV.SmokeTests
dotnet run --project src/TurkuazAV.Cli -- scan-rules TARGET RULES.YAR RULES.SIG PUBLIC.PEM ABSOLUTE_YR_PATH
```

Imza, ham `RULES.YAR` baytlarina RSA-PSS-SHA256 ile uygulanir.
Imza dogrulanmadan kural dosyasi `yr` icin acilmaz. Dogrulanmis baytlar
gecici kopyadan taranir. `yr` programi bash/shell kullanilmadan
`scan --output-format=ndjson` parametreleriyle calistirilir.

## Guvenlik ve platform sinirlari

- CLI public key dosyasini kullanicidan kabul eder: bu yalnizca gelistirme/test
  kolayligidir. Uretimde yayinci anahtari uygulamada sabitlenmelidir.
- Harici YARA-X executable dosyasi simdilik otomatik imza dogrulamaz.
  Guvenilir resmi kaynaktan edinilmelidir.
- Ornek smoke test bir sahte motorla Service mantigini sinar.
  Gercek YARA-X executable ile E2E test henuz CI icinde bulunmaz.
- Hedef dosya tarama sirasinda degistirilebilir; TOCTOU onlemi henuz yoktur.
- Windows ve Linux CI bulunur. macOS CI planlanmistir.
- Lisans secimi henuz kesinlestirilmemistir. Public olmasi otomatik
  yeniden dagitim veya ticari kullanim izni anlamina gelmez.

## Mimari

Controller -> Service -> Repo/Tool -> View -> Language, merkezi Config.

## Sonraki adimlar

Gercek YARA-X E2E, sabit guven anahtari, ikili dosya dogrulama,
dosya anlik goruntusu ve sonra guvenli karantina prototipi.
