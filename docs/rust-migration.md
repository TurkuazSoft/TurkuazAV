<!--
Dosya Yolu: REPO_ROOT/docs/rust-migration.md
Amac: TurkuazAV 0.3.1 Rust donusum ve kanit plani
Modul - FileType: Documentation - Markdown
Version: 0.3.1
Aciklama: Eski .NET 0.3.1 ile Rust esdegerlik ve release kapilari
Bagimli Oldugu Katman: Documentation
-->
# TurkuazAV 0.3.1 - Rust Dönüşümü

`feat/rust-native-v0.3.1` dalında v0.3.1 kaynakları Rust ile yeniden yazıldı ve eski C# / WinUI kaynakları **bu dalda** kaldırıldı. `main` dalındaki .NET 0.3.1 referansı ve Git geçmişi korunmaktadır. PR #10 taslaktır; imzasız test artifact'ı production release değildir.

## Eşdeğerlik ve kanıt matrisi

| Eski bileşen | Rust karşılığı | Kanıt |
| --- | --- | --- |
| SHA-256 sınırlı tarama | `rust/src/scan.rs` | Rust birim, akış tabanlı klasör taraması, skip/iptal ve bağlantı testleri |
| CLI `scan` | `rust/src/bin/cli.rs` | Gerçek binary stdout, hash ve exit-code smoke |
| CLI `scan-rules` | `rust/src/rules.rs` | RSA-PSS, pinned YARA-X, snapshot, iptal ve pozitif/negatif E2E |
| Trusted manifest | `rust/src/trusted.rs` | Strict schema, imza ve hash regresyonları |
| 40-byte anti-rollback state | `rust/src/trusted.rs` | Sıra/çakışma/eski state + gerçek YARA-X E2E |
| WinUI tek dosya arayüzü | `rust/src/bin/desktop.rs` | Rust GUI dosya/klasör taraması, ilerleme sayaçları, worker-disconnect ve klasör mantık testleri |
| Kopyala, iptal, geçmiş | `rust/src/bin/desktop.rs` | Kaynak+derleme testi; gerçek UI smoke bekliyor |
| Yerel tanı kayıtları | `rust/src/bin/desktop.rs` | Kod/kategori ile kayıt; yerel gizlilik smoke bekliyor |

## Windows ve Linux doğrulama

```bash
cargo fmt --all -- --check
cargo check --locked --bins
cargo test --locked --lib --test rust_compat --test cli_smoke
cargo clippy --locked --lib --bin turkuazav --tests -- -D warnings
cargo check --locked --features desktop --bin turkuazav-desktop
cargo clippy --locked --features desktop --bin turkuazav-desktop -- -D warnings
cargo test --locked --features desktop --bin turkuazav-desktop
cargo build --locked --release --features desktop --bins
```

Gerçek YARA-X E2E için doğrulanmış motoru yükleyin ve `TURKUAZ_YR_PATH` tanımlayın; ardından:

```bash
cargo test --locked --test yarax_e2e
```

CI `tools/package-rust-preview.ps1` ile test ZIP/TAR.GZ paketini açıp **her kritik dosyayı sayar ve SHA-256 kontrolü** yapar. Ayrı `.sha256` dosyası arşivin tamamını korumak için sağlanır. Ne checksum ne de imzasız paket, kod imzası veya AV sınıflandırması yerine geçer.

## Manuel test kapıları

Windows ve Linux gerçek oturumlarında dosya seçici, uzun taramanın iptali, pencere yeniden boyutlandırma, UTF-8 dosya yolu, kopyala, yeni seçimde eski hash'in temizlenmesi, 20 kayıt limiti, geçmiş temizleme, hata sonrası yeniden deneme ve tanı kayıtlarının gizlilik/7 gün silme davranışı test edilmelidir. CI'da GUI derlemesi / GUI logic testleri, ekrandan testin yerine geçmez.

## Üretim dışı sınırlar

- SHA-256 veya YARA-X kural eşleşmesi antivirüsün temiz/zararlı kararı değildir.
- Gerçek zamanlı koruma, karantina, silme ve kernel sürücüsü v0.3.1 kapsamına dahil değildir.
- Publisher anahtar kökü henüz üretim için güvenli şekilde provision edilmedi; CLI'da verilen PEM güven kökü sayılamaz.
- Özel geçici alana alınmış YARA-X kopyası için dosya bütünlüğü doğrulanır; ancak yönetici ayrıcalığına sahip saldırganlara karşı süreç ve dosya izolasyonu tamamlanmadı. Ayrıcalıklı state rollback'e, dosya snapshot TOCTOU'ya, subprocess sandbox/child-tree temizliğine ve elektrik kesintisi durumlarına ek sertleştirme gerekir.
- macOS engine pin ve macOS CI henüz yoktur; platform destek iddiası olmamalıdır.
- Bu dal production sürüm değildir: `main` birleştirme, imzalama ve release ayrı onay gerektirir.
