# 📄 Dosya Yolu: /TurkuazAV/docs/windows-desktop-preview.md
# 📌 Amac: WinUI 3 deneysel masaustu uygulamasinin derleme ve test ilkelerini aciklamak
# 📌 Modul - FileType: Documentation - Markdown
# Version: 0.3.0
# Aciklama: Windows x64 GUI ilk asama dis politikasi
# Bagimli Oldugu Katman: Controller | Service | Repo | View | Language

# Windows Desktop Preview

TurkuazAV.Desktop yalnizca Windows x64 WinUI 3 uygulamasidir.
Ortak `TurkuazAV.Core` Linux ve Windows'ta ayri test edilir.
GUI `HashScanController` ile `ScanService` is mantigina erisir.

## MVP kisitlari

1. Kullanici tek dosya secer.
2. Tek bir SHA-256 raporu hesaplanir, dosya boyutu ve durum gosterilir.
3. Kullanici iptal eder veya farkli dosya secer.
4. Oturum gecmisi sadece bellektedir; disk/telemetri aktarimi yoktur.

GUI bilerek YARA-X ya da imzali rule tarama yapmaz. Ilk asamada
kullanicidan secilen key ile guvenilir publisher raporu gostermeyi
reddederiz; uretim trust root ve korunan state provisioning
olusturulmadan bunu sunmak guvenli olmaz.

## Guvenlik gereksinimleri

- Tarama esnasinda EXE'leri calistirma, registry'yi degistirme,
  dosyalari karantinaya alma/silme yok.
- Symlink/root reparse point taramalari Core politikalarina baglidir.
- ScanService dosya boyutunu 100 MiB ile sinirlar.
- Hata, Skip ve Hash mesaji "virus var/yok" olarak yorumlanmaz.
- Windows Defender/Kaspersky yerine gecmez.
- GitHub public PR'lari FURY self-hosted runner uzerinde otomatik
  calistirilmaz.

## Sonraki asama

- Isletim sistemi UI acilis ve arayuz smoke testi
- WinUI exe'nin self-contained artifact olarak paketlenmesi ve imzalanmasi
- Guvenilir kural servisi ve uretim publisher trust root bootstrapping
- Manuel tarama ile YARA-X raporlama; otomatik AV verdict olmadan
