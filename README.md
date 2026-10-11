# 📄 Dosya Yolu: /TurkuazAV/README.md
# 📌 Amac: 0.2.1 gercek YARA-X E2E ve imzali kural sinirlarini anlatmak
# 📌 Modul - FileType: Documentation - Markdown
# Version: 0.2.1
# Aciklama: 0.2.1 gercek YARA-X E2E ve imzali kural sinirlarini anlatmak
# Bagimli Oldugu Katman: Controller | Service | Repo | Tool | View | Language

# TurkuazAV

TurkuazAV Community, platform bagimsiz ve **deneysel** dosya analizi altyapisidir.

## Surum 0.2.1

- Salt okunur SHA-256 dosya envanteri.
- RSA-PSS-SHA256 imzali YARA-X kaynak kurallarini dogrulama.
- Harici `yr scan --output-format=ndjson` motoru ile eslesme raporlama.
- Dogrulanan kural dosyasi ve hedef dosyanin gecici kopyasi uzerinde analiz.
- GitHub-hosted Windows ve Linux CI ile gercek YARA-X 1.21.0 E2E testi.
- Test paketi indirilirken resmi GitHub release SHA-256 ozeti ile karsilastirma.

**Bu surum tam bir antivirus degildir.** Kural eslesmesi, zararlilik karari
anlamina gelmez. Karantina, otomatik silme veya gercek zamanli koruma yoktur.

## Gelistirme

.NET 10 SDK gereklidir. Kural taramasinda `yr` CLI ayrica kurulmalidir.

```text
dotnet run --project src/TurkuazAV.Cli -- scan .
dotnet run --project tests/TurkuazAV.SmokeTests
pwsh ./tools/install-yarax.ps1
dotnet run --project tests/TurkuazAV.IntegrationTests
```

Installer YARA-X programini `artifacts/yarax` altina indirir;
sadece CI'de `TURKUAZ_YR_PATH` ortam degiskenini otomatik ayarlar.
Yerel E2E icin kullanici bu degiskeni gercek `yr` ikili yoluna ayarlamalidir.

Kural taramasi komutu:

```text
dotnet run --project src/TurkuazAV.Cli -- scan-rules TARGET RULES.YAR RULES.SIG PUBLIC.PEM ABSOLUTE_YR_PATH
```

`RULES.SIG`, ham `RULES.YAR` iceriginin RSA-PSS-SHA256 imzasidir.
`PUBLIC.PEM`, en az 2048-bit RSA SubjectPublicKeyInfo acik anahtaridir.
Ozel imza anahtarlari public repoya eklenmemelidir.

## Sinirlamalar

- Kural imzasini dogrulayan anahtar su an **kullanici tarafindan** seciliyor.
  Uretim icin public key pinleme ve rotasyon modeli gereklidir.
- CI binary paketini dogrular; kullanicinin yerel verdigi `yr` dosyasinin
  dijital imzasi veya ozeti henüz servis tarafindan dogrulanmaz.
- Snapshot hedef dosyadaki sonraki degisiklikleri engeller ancak
  snapshot okunurken yapilan eszamanli degisikliklere karsi
  tam dosya butunlugu garantisi vermez.
- YARA-X harici bir islem olarak calisir; sertlestirilmis sandbox yoktur.
- macOS CI henuz eklenmedi. Public depo kaynak lisansi henuz secilmedi.

## Proje katmanlari

Controller -> Service -> Repository/Tool -> View -> Language + Config.
