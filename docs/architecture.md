# 📄 Dosya Yolu: /TurkuazAV/docs/architecture.md
# 📌 Amac: Imzali kurallar ve platform sinirlarini teknik olarak aciklamak
# 📌 Modul - FileType: Markdown
# Version: 0.2.0
# Aciklama: Imzali kurallar ve platform sinirlarini teknik olarak aciklamak
# Bagimli Oldugu Katman: Controller | Service | Repo | Tool | View | Language

# TurkuazAV 0.2.0 mimari

Controller yalnizca girdi alir, Service'i cagirir.
Service hedef dosya boyutunu, kural imza politikasini ve temp kopyayi yonetir.
Repository ham kural, imza ve public key dosyalarini boyut siniri ile okur.
Tool RSA-PSS dogrulamasini ve `yr` subprocess calismasini uyarlar.
View raporlar; Language kullanici mesajlarini tanimlar.

Gecerli imzali kaynak kural paketleri taranir. Icerigi degistirilen
kural dosyasi imza denetiminden gecemez.
Buradaki public key dosyasi kullanici girdisi oldugu icin
uzaktan dagitilan kurallara kendiliginden guven saglamaz.

YARA-X CLI: `yr scan --output-format=ndjson RULES TARGET`.

Bilinen eksikler: gercek `yr` E2E, engine binari guveni,
target TOCTOU, uretim imza anahtari pinleme, sanal alan izolasyonu.
