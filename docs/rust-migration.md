<!--
Dosya Yolu: REPO_ROOT/docs/rust-migration.md
Amac: TurkuazAV 0.3.1 Rust donusum ve kanit plani
Modul - FileType: Documentation - Markdown
Version: 0.3.1
Aciklama: Gercek testlerle eski uygulamanin Rust'a aktarimi
Bagimli Oldugu Katman: Documentation
-->
# TurkuazAV 0.3.1 - Rust Donusumu

Bu dal native Rust Core, CLI ve desktop icin gecis calismasidir. Main dalindaki .NET 0.3.1, esdegerlik kanitlanana kadar referans olarak kalir. Test artifactlari production release degildir.

## Esdegerlik matrisi

| Eski bilesen | Rust karsiligi | Kanit |
| --- | --- | --- |
| SHA-256 bounded scan | rust/src/scan.rs | Rust unit, folder/skip/cancel |
| CLI scan | rust/src/bin/cli.rs | Smoke/CLI |
| CLI scan-rules | rust/src/rules.rs | RSA-PSS, pinned YARA-X, snapshot |
| Trusted manifest | rust/src/trusted.rs | Strict schema, signature, hash |
| 40-byte state | rust/src/trusted.rs | Same-sequence, conflict, rollback |
| WinUI single-file | rust/src/bin/desktop.rs | Rust GUI, manual E2E pending |
| Copy, cancel, history | rust/src/bin/desktop.rs | GUI manual E2E pending |
| Local diagnostics | rust/src/bin/desktop.rs | Privacy and retention E2E pending |

## Guvenlik sinirlari

* SHA-256 sonucu malware verdict degildir. Gercek zamanli koruma, karantina, silme, driver yoktur.
* GUI yalnizca hash hesaplar; untrusted CLI anahtar dosyasiyla otomatik publisher guveni vermez.
* Core'da trusted keyring yalnizca bagimsiz ve guvenilir bootstrap tarafindan verilir.
* Gelistirici scan-rules CLI'sindeki key parametresi production trust root degildir.
* Rust dis YARA-X executable dogrulamasi eski pinli Windows/Linux x64 SHA-256 ile ayni seviyededir.
* File permission/symlink/TOCTOU ve engine process-tree izolasyonu icin ilave sertlestirme gerekir.
* State dosyasi sadece servis hesabinin yazabildigi korunan dizinde tutulmalidir.
* Platforma ozel Windows/Linux/macOS GUI ve normal kullanici acceptance testleri tamamlanmadan esdegerlik iddiasi kurulamaz.

## Gecis kararlari

1. Rust unit+contract+YARA-X integration, her iki OS'de CI gecmeli.
2. Windows masaustu UI secim, iptal, hash kopyalama, oturum gecmisi ve diagnostics manual smoke ile kanitlanmali.
3. Orijinal .NET testlerini silmeden once Rust testleri ayni guvenlik davranislarini dogrulamali.
4. Ancak kanitlardan sonra eski CSharp, XAML, csproj, Dotnet CI ve packaging kontrollu diff ile kaldirilir.
5. Release / main merge yalnizca ayri explicit talimatla yapilir.

Gelistirme: cargo test --lib --test rust_compat; cargo build --release --bin turkuazav; cargo run --features desktop --bin turkuazav-desktop.
