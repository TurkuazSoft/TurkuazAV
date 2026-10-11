# 📄 Dosya Yolu: /TurkuazAV/docs/security-model.md
# 📌 Amac: Motor ve kural imzasi guven modelini netlestirmek
# 📌 Modul - FileType: Security - Markdown
# Version: 0.2.2
# Aciklama: Tehdit modeli ve kalan guvenlik riskleri
# Bagimli Oldugu Katman: Service | Repo | Tool | Config

# Guvenlik modeli (deneysel)

## Korunan varliklar

- YARA-X tarama motorunun dogrulanmis binary dosyasi
- Imzali kaynak YARA kural baytlari
- Taranacak kullanici dosyalari (salt okunur)
- Raporlama sonuclari

## Dogrulama zinciri

1. CI installer resmi v1.21.0 paketini indirir.
2. Resmi release icin sabitlenmis arsiv SHA-256 ile kontrol eder.
3. Arsivden cikan `yr` dosyasi ikinci SHA-256 pinine gore kontrol edilir.
4. Her taramada Tool katmani motor binary SHA-256 degerini yeniden hesaplar.
5. Repository, kural dosyasini boyut sinirli olarak okur.
6. Service RSA-PSS-SHA256 imzasini kullanici secimli PEM ile dogrular.
7. Dogrulanan kurallar ve boyut sinirli target snapshot ile analiz yapilir.

## Guven konusu

0.2.2 uretim icin gereken *pinned publisher rule key* icermez.
Testte kullanilan anahtar CI icinde gecici uretilir.
Bu nedenle kullanicinin kendi anahtarini ve kurallarini imzalamasi
guvenilir yayinci tespiti olarak yorumlanamaz.

Motor SHA-256 pinleme yalnizca bilinen release dosyasinin degismedigini
kontrol eder; tek basina kod imzasi veya malware davranis izolasyonu degildir.
Dosya konumu hash kontrolunden sonra degistirilebildigi icin kucuk
bir execution TOCTOU penceresi vardir.

## Platformlar

Windows x64 ve Linux x64: onayli binary digest profilleri.
macOS/ARM: guvenilen profil tanimli degil, fail closed.

## Ertelenen kontroller

- Guvenilir yayinci RSA acik anahtari / rotasyon / key ID
- Kurallar icin rollback ve monotonic version policy
- Motor binary calistirma sandbox ve yetki sinirlamasi
- Source snapshot eszamanli degisim algilama
- Kotu niyetli dosyalarla izole fuzz / regresyon
- Windows Security Center entegrasyonu ve gercek zamanli koruma
