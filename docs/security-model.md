# 📄 Dosya Yolu: /TurkuazAV/docs/security-model.md
# 📌 Amac: Guven koku, yayinci rotasyonu ve rollback risklerini aciklamak
# 📌 Modul - FileType: Security - Markdown
# Version: 0.2.3
# Aciklama: Imzali kurallarin kaynak ve surum guvenligi
# Bagimli Oldugu Katman: Service | Repo | Tool | Config

# TurkuazAV 0.2.3 guven modeli

## Mevcut dogrulama modeli

1. CI resmi YARA-X 1.21.0 arsiv SHA-256 ozetini dogrular.
2. Tarama motoru ikilisi calistirilmadan once bilinen SHA-256 ile karsilastirilir.
3. Guvenilir publisher trust store, **uygulamaya ait guvenilir bootstrap**
   tarafindan onceden verilen key ID -> PEM eslemesini barindirir.
4. `TrustedRulePackageService` manifest JSON alanlarini katilikla ayrisir.
5. Imza, `TurkuazAV.rule-package.v1\n` domain separator ve
   sequence/key ID/digest degerlerini kapsayan kanonik baytlara aittir.
6. RSA-PSS-SHA256 dogrulamasindan sonra kural SHA-256 ozeti karsilastirilir.
7. `LocalRuleVersionRepository` en yuksek kabul edilen sequence degerini
   saklar; eski imzali paketleri reddeder.

## Anahtar rotasyonu

Guvenilen politika iki *onceden onayli* yayinci acik anahtarini
gecici olarak ayni anda kabul edebilir. Yeni anahtarla yuksek
sequence paketi kabul edildikten sonra eski public key yayin
politikasindan cikarilabilir. Key ID paketin icinde imza kapsamina
alindigindan paket kendi key ID degerini degistiremez.

0.2.3'te **hicbir gercek uretim yayinci key'i yer almiyor**.
Testler anlik RSA test anahtarlari ile kosuyor.
Ozel anahtari source control, log veya public CI icine koymayin.

## Rollback sinirlari

State dosyasi yerel diskte ve korunmus ACL altinda bulunmalidir.
Basarili imza dogrulamasi sonrasi sequence diske kaydedilir.
Daha dusuk sequence reddedilir; ayni sequence yeniden kabul edilir.
State bozulursa fail closed.

Bu mekanizma privileged local attacker tarafindan state dosyasinin
silinmesi, snapshot rollback veya tum state dizininin degismesi
riskine karsi tek basina guvenli degildir. Uretimde Windows service
ACL, policy sunucusu, cihaz kaydi ve gerekirse OS protected storage
ile daha guclu monotonicity gerekir.

## Uretime cikmadan once

- TrustedRulePackageService dogrulamasini gercek CLI ve updater'a baglamak
- Trust root provisioning ile key revocation politikasini imzalamak
- Paketlerin anti-rollback state dosyalarina ACL ve cross-process davranis testleri
- Yapilandirilmis manifest fuzz ve property tests
- Kural dosyasinin parser ve motor izolasyonu
- Kullanici dosyasi snapshot ve Process.Start TOCTOU sertlestirmesi
