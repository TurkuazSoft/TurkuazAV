# 📄 Dosya Yolu: /TurkuazAV/docs/security-model.md
# 📌 Amac: Guvenilir imzali paketlerin gercek tarama akisindaki guvenlik kurallarini belgelemek
# 📌 Modul - FileType: Security - Markdown
# Version: 0.2.4
# Aciklama: Guvenilir imzali paketlerin gercek tarama akisindaki guvenlik kurallarini belgelemek
# Bagimli Oldugu Katman: Service | Repo | Tool | Config

# TurkuazAV 0.2.4 Security Model

## Uretim guven sorumluluklari

1. Yayinci keyring, imzali installer veya guvenilir uygulama
   bootstrap tarafindan secilir. CLI dosya yolu guven koku degildir.
2. Manifest `schema`, `sequence`, `keyId`, `rulesSha256` alanlari
   katilikla ayrisir; RSA-PSS-SHA256 imzasi kanonik payload icindir.
3. Anahtar key ID yalnizca keyring'de mevcutsa dogrulama yapilir.
4. Kural dosyasi, manifestteki digest ile karsilastirilir.
5. Dogrulanan kurallar ve dosya hedef snapshot ile gercek YARA-X
   motorunda taranir; motor executable digest profili sabitlenmistir.
6. Yalnizca engine taramasi basarili olursa sequence +
   signed-manifest fingerprint kalici state'e islenir.
7. Eski sequence ve ayni sequence ile farkli imzali manifest reddedilir.
   Aynı manifest farkli hedef dosyalarla tekrar kullanilabilir.

## Durum dosyasi

0.2.4 dosya bicimi: little-endian Int64 sequence (8 byte) ve
SHA256(signature-domain + canonical manifest) fingerprint (32 byte).
Tam 40 byte olmayan state veya 0/negatif sequence fail closed.
0.2.3 8-byte state otomatik olarak silinmez veya migrate edilmez.

Disk durumunu sadece servis hesabinin yazabildigi dizinde tutun.
`FileShare.None` ayni dosya uzerindeki eszamanli islemleri engeller;
privileged yerel saldirgan, dosya silme ya da snapshot geri alma
riskini tek basina engellemez.

## Henuz tamamlanmadi

- Uretim yayinci trust root'u ve imzali rotasyon dagitimi
- CLI/GUI icin uretim politikasi ve protected-service provisioning
- YARA-X motor calistirma sandbox, hash-ile-execute TOCTOU sertlestirmesi
- Paketlerin guvenli yukleme atomikligi, disk power-loss testleri
- Kural performansi ve fuzz testleri
- Windows GUI, macOS testleri, karantina ve real-time koruma

Bu kod bir antivirus'un tespit veya engelleme etkinligini kanitlamaz.
