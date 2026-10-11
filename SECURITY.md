# 📄 Dosya Yolu: /TurkuazAV/SECURITY.md
# 📌 Amac: Acik bildirim politikasini ve guvenli test kurallarini tanimlamak
# 📌 Modul - FileType: Security - Markdown
# Version: 0.2.2
# Aciklama: Guvenlik bildirimi ve beta koruma sinirlari
# Bagimli Oldugu Katman: Service | Tool

# Security Policy

TurkuazAV 0.2.2 deneysel dosya analiz aracidir. Cihazi koruyan
antivirus, EDR veya ransomware engelleme yazilimi olarak
kullanilmamalidir.

Acik ayrintilarini public issue veya PR ile yayinlamayin.
GitHub private vulnerability reporting etkinse o kanali tercih edin.
Henuz etkin degilse hassas istismar ayrintilarini acik depoya yazmayin.

Testlerde gercek zararli dosyalari depoya, CI artifactlerine veya
test loglarina eklemeyin. Zararsiz ornek dosyalar kullanin.

Ileri asamalarda dosya silme, karantina ve surec sonlandirma
eklenmeden once rollback ve yanlis pozitif prosedurleri
ayrica denetlenmelidir.

Guven modeli: [docs/security-model.md](docs/security-model.md).
