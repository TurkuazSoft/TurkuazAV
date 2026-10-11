# 📄 Dosya Yolu: /TurkuazAV/docs/architecture.md
# 📌 Amac: Katmanlari, platform sinirlarini ve sonraki asamalari belgelemek
# 📌 Modul - FileType: Architecture - Markdown
# Version: 0.1.0
# Aciklama: Katmanlari, platform sinirlarini ve sonraki asamalari belgelemek
# Bagimli Oldugu Katman: Controller | Service | Repo | Tool | View | Language

# Ilk mimari

TurkuazAV.Core, Windows ve Linux uzerinde ayni .NET tarama
orkestrasyonunu ve SHA-256 aracini kullanir. TurkuazAV.Cli, platform
bagimsiz giris arayuzudur. Windows WinUI, Linux ve macOS platform
adapterleri sonraki asamalarda ayri moduller olacaktir.

Controller -> Service -> Repository + Tool -> View -> Language akisi
korunur. Config tum varsayilanlari merkezilestirir.

0.1.0 davranislari:
- Verilen dosya veya dizinin normal dosyalarini gez.
- Sembolik baglanti olan dosya ve klasorleri takip etme.
- Boyut limitini asan dosyalari atla.
- Okunabilen dosyalarin SHA-256 degerini raporla.
- Dosyalari degistirme, silme, karantinaya alma veya calistirma.

SHA-256 degeri tek basina zararli tespiti degildir. YARA-X, imzali
kural guncellemeleri ve guvenilirlik kararlari sonraki fazlara aittir.

CI icin GitHub hosted runner kullanilir. Public PR calismalarini
self-hosted FURY runner'da otomatik calistirmak guvenlik riski tasir.

MacOS test runner ve guvenlik API izinleri dogrulanmadan MacOS
destegi tamamlandi olarak duyurulmaz.
