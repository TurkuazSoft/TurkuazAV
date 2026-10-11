# 📄 Dosya Yolu: /TurkuazAV/README.md
# 📌 Amac: TurkuazAV projesinin kapsamini ve gelistirme adimlarini tanimlamak
# 📌 Modul - FileType: Documentation - Markdown
# Version: 0.1.0
# Aciklama: Platform bagimsiz tarama temeli ve guvenli gelistirme ilkeleri
# Bagimli Oldugu Katman: Controller | Service | Repo | Tool | View | Language

# TurkuazAV

TurkuazAV, coklu platform icin tasarlanan moduler guvenlik ve dosya analizi projesidir.

## Durum

0.1.0 gelistirme asamasidir. Ilk prototip **antivirus degildir**:
dosyalari SHA-256 ile ozetler ve raporlar; zararlilari tespit ettigini
veya engelledigini iddia etmez. Gercek zamanli koruma, karantina ve
otomatik silme etkin degildir.

## Mimari

- Controller: Istek kabul eder ve Service cagirir.
- Service: Tarama akisini ve is kurallarini yonetir.
- Repository: Yerel dosya erisimini soyutlar.
- Tool: Dosya ozeti gibi bagimsiz analiz araclarini uyarlar.
- View: Sonuclari gosterir.
- Language: Kullaniciya gosterilen mesajlari tutar.
- Config: Ortak sabitleri ve limitleri tanimlar.

## Baslangic

.NET 10 SDK gereklidir.

```text
dotnet run --project src/TurkuazAV.Cli -- scan .
dotnet run --project tests/TurkuazAV.SmokeTests
```

Ornekler salt-okunur tarama yapar; dosyalari silmez veya karantinaya almaz.

## Yol haritasi

1. 0.1.0: Ortak dosya envanteri, SHA-256 taramasi ve Windows/Linux CI.
2. 0.2.0: YARA-X icin ayrilmis Tool arayuzu, kural imza dogrulamasi.
3. 0.3.0: Kontrollu karantina ve geri yukleme.
4. 0.4.0: Isletim sistemine ozel olay izleme.
5. 0.5.0+: Risk incelemesi tamamlandiktan sonra gercek zamanli koruma.

Lisans secimi ayri bir karardir; bu depo public oldugu icin kodu otomatik
olarak yeniden kullanim hakki vermez.
