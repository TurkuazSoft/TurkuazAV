# 📄 Dosya Yolu: /TurkuazAV/README.md
# 📌 Amac: TurkuazAV 0.2.3 ozelliklerini ve sinirlarini aciklamak
# 📌 Modul - FileType: Documentation - Markdown
# Version: 0.2.3
# Aciklama: Deneysel tarama motoru ve imzali yayinci paket guven modeli
# Bagimli Oldugu Katman: Controller | Service | Repo | Tool | View | Language

# TurkuazAV

TurkuazAV, Windows/Linux icin gelistirilen deneysel ve salt-okunur
dosya analiz altyapisidir. **Tam korumali antivirus degildir.**

## 0.2.3 durumu

- .NET 10 ile salt-okunur SHA-256 dosya envanteri
- Gercek YARA-X v1.21.0 motoru: Windows x64 ve Linux x64
- Sabitlenmis resmi motor SHA-256 profilleri
- Gelistirme/test modunda kullanici secimli RSA-PSS imzali kural taramasi
- **Yeni:** Yayinci anahtarlarini uygulamadan bagimsiz dogrulanmis
  konfigurasyondan alan `TrustedRuleKeyring` API'si
- **Yeni:** Surum numarasi, imzalayan key ID ve kural SHA-256
  ozeti iceren imzali manifest modeli
- **Yeni:** Kalici en yuksek paket surumu ve eski surum reddi
- **Yeni:** Izin verilen anahtar listesinin guncellenmesiyle rotasyon/revocation
- Windows/Linux smoke testlerinde bozuk imza, degistirilen kurallar,
  taninmayan anahtar, rollback ve bozuk state senaryolari

## Yerel gelistirme

.NET 10 SDK gerekir. YARA-X CLI dogrulanmis resmi surumden kurulur.

```text
dotnet run --project src/TurkuazAV.Cli -- scan .
dotnet run --project tests/TurkuazAV.SmokeTests
pwsh ./tools/install-yarax.ps1
dotnet run --project tests/TurkuazAV.IntegrationTests
```

CI, `TURKUAZ_YR_PATH` ortam degiskenini ayarlar.
Yerel E2E testte bu degiskeni resmi `yr` programinin
mutlak yoluna ayarlamak gerekir.

**Gelistirme modu komutu:**

```text
dotnet run --project src/TurkuazAV.Cli -- scan-rules TARGET RULES.YAR RULES.SIG PUBLIC.PEM ABSOLUTE_YR_PATH
```

Bu komut kullanicidan public key aldigi icin **guvenilir yayinci
dogrulamasi yapmaz**. Ileride uretim modunda kaldirilacak veya
sadece yetkili gelistirici ortaminda kalacaktir.

## Imzali manifest (yeni kutuphane API'si)

`TrustedRulePackageService`, `TrustedRuleKeyring` ve
`LocalRuleVersionRepository` 0.2.3'te eklendi. Manifeste ait
JSON alanlari `schema`, `sequence`, `keyId`, `rulesSha256`.
Ilgili RSA-PSS-SHA256 imzasi, `TrustedRuleManifestCodec.SignaturePayload`
kanonik baytlari uzerinden uretilir.

Yayinci anahtarlari **yalnizca guvenilir uygulama bootstrap
katmanindan** saglanmali; indirilen manifestten veya kullanicidan
alinan key ile guven kokeni olusturulmamalidir. Iki onayli anahtari
bir sure birlikte tanitmak rotasyona imkan verir; eski anahtar
keyring'den cikarilarak iptal edilir.

**Onemli sinir:** Bu altyapi 0.2.3'te kutuphane API'si olarak sunulur.
Henuz TurkuazAV CLI kural tarama akisi ile baglanmamistir.
Gercek yayinlayici public key'i henuz olusturulup pinlenmedi;
smoke test anahtarlari yalnizca test sirasinda gecici uretilir.

## Guvenlik sinirlari

- Local anti-rollback state dosyasi onayli, servis hesabiyla korunan
  bir dizinde tutulmalidir. Dosyanin silinmesi veya sistemin
  eski yedekten donmesi karsisinda tek basina yeterli degildir.
- Version state'i ayni anda acan baska islem olursa islem
  guvenli tarafta hata verir; fail closed.
- RSA anahtar rotasyonu su an sadece API ile; otomatik imzali
  policy guncelleme protokolu yoktur.
- YARA-X binary hash kontrolu ile Process.Start arasinda kucuk
  bir TOCTOU penceresi bulunur. Izole sandbox mevcut degildir.
- MacOS destegi ve WinUI arayuzu henuz tamamlanmamistir.
- Karantina, gercek zamanli koruma ve zararlilik karari yoktur.
- Public repo icin dagitim lisansi secilmemistir.
