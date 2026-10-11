# 📄 Dosya Yolu: /TurkuazAV/docs/architecture.md
# 📌 Amac: Snapshot guvenligi ve gercek YARA-X testlerini belgelemek
# 📌 Modul - FileType: Architecture - Markdown
# Version: 0.2.1
# Aciklama: Snapshot guvenligi ve gercek YARA-X testlerini belgelemek
# Bagimli Oldugu Katman: Controller | Service | Repo | Tool | View | Language

# TurkuazAV 0.2.1 Architecture

Controller yalnizca komut alir ve Service'e iletir.
Service imza dogrulamasi ile snapshot olusturmayi yonetir.
Repository yerel dosyalara ve imzali rule bundle'a erisir.
Tool kriptografiyi ve YARA-X CLI'yi ayri adaptorlerde uygular.
View raporlar, Language mesajlari, Config limitleri saklar.

## Guvenli YARA-X

RSA-PSS-SHA256 dogrulamasi gecmeden kurallar motora verilmez.
`Directory.CreateTempSubdirectory` gecici tarama kopyalarini barindirir.
Snapshot, kaynak hedefin motora tekrar okutulmasini onler. Dosya
kopyalanirken eszamanli yazma olursa butunluk garanti edilmez.
YARA-X subprocess icin timeout ve ciktinin ust limiti bulunur.

CI `config/yara-x-release.psd1` manifestindeki sabit resmi release
URL'si ve SHA-256 ozetiyle hem Windows hem Linux binary'lerini dogrular.
Zararsiz pozitif, negatif ve imza bozulma testleri gercek `yr` ile kosulur.

Uretim eksikleri: yerel motor imza guveni, sabit yayinci anahtari,
yetki ve sandbox izolasyonu, kapsamli fuzz test, macOS runner,
gercek zamanli izleme, degisiklik anindaki dosya butunlugu.
