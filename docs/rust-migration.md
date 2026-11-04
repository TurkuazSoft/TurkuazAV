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
| Yeni gozlem onizlemesi (v0.3.1'e ilave) | `rust/src/monitor.rs` / `rust/src/native_events.rs` / `rust/src/service.rs` / `rust/src/worker.rs` | Salt okunur polling + native ipucu, tek-slot kuyruk, arka plan iscisi, durdurma, saglik sayaclari, retry, iptal ve platform olay testleri |
| CLI `scan` | `rust/src/bin/cli.rs` | Gerçek binary stdout, hash ve exit-code smoke |
| CLI `scan-rules` | `rust/src/rules.rs` | RSA-PSS, pinned YARA-X, snapshot, iptal ve pozitif/negatif E2E |
| Trusted manifest | `rust/src/trusted.rs` | Strict schema, imza ve hash regresyonları |
| 40-byte anti-rollback state | `rust/src/trusted.rs` | Sıra/çakışma/eski state + eszamanli yazar ve atomik staging testleri + gercek YARA-X E2E |
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

CI `tools/package-rust-preview.ps1` ile test ZIP/TAR.GZ paketini acip **her kritik dosyayi sayar ve SHA-256 kontrolu** yapar. Paket icinden cikartilan gercek CLI, servis ikilisi ve masaustu GUI'nin basliksiz tarama isçisi farkli Unicode calisma dizininden baslatilir; SHA-256 ornegi ve ozet cikti kontrati dogrulanir. `TEST_KILAVUZU_TR.md` ayni SHA-256 manifestine dahil edilerek manuel kabul kapilari kullaniciya verilir. Ayrı `.sha256` dosyası arşivin tamamını korumak için sağlanır. Ne checksum ne de imzasız paket, kod imzası veya AV sınıflandırması yerine geçer.

## Manuel test kapıları

Windows ve Linux gerçek oturumlarında dosya seçici, uzun taramanın iptali, pencere yeniden boyutlandırma, UTF-8 dosya yolu, kopyala, yeni seçimde eski hash'in temizlenmesi, 20 kayıt limiti, geçmiş temizleme, hata sonrası yeniden deneme ve tanı kayıtlarının gizlilik/7 gün silme davranışı test edilmelidir. CI'da GUI derlemesi / GUI logic testleri, ekrandan testin yerine geçmez.

## Üretim dışı sınırlar

- SHA-256 veya YARA-X kural eşleşmesi antivirüsün temiz/zararlı kararı değildir.
- Salt okunur, kullanici talebiyle baslayan `observe` polling komutu eklendi; OS olay kancasi, servis, dosya engelleme veya virus temizleme degildir. Araliklar arasindaki gecici degisiklikler kaybolabilir.
- Tek-slot servis cekirdegi, denetlenen tek arka plan iscisi ve `turkuazav-service` host onizlemesi eklendi. CI icin gecici, izole hosted-runner SCM kaydi/LocalService baslat-durdur, kill-sonrasi restart ve normal STOP ile yeniden baslatmama; Linux systemd baslat-durdur/crash recovery testleri tanimlandi. SCM restart kurtarma kaniti test basarisina baglidir. CI'da bir onceki dogrulanmis binary'ye offline servis konfigurasyonu rollback'i ve SHA-256 uyusmayan aday reddi test kapsamina eklendi; aday ayni surum ikilisinin ayri kopyasidir, gercek farkli surum migrasyonu veya imzali updater testi degildir. Kullanici bilgisayarina kurulum, kalici autostart, production ACL/account provision, prod recovery kabul testi ve OS servis saglik endpoint'i yoktur.
- Gerçek zamanlı koruma, karantina, silme ve kernel sürücüsü v0.3.1 kapsamına dahil değildir.
- `rust/src/update.rs` servis ikilisi icin bagimsiz RSA-PSS-SHA256 imzali manifest, bounded binary snapshot ve read-only anti-rollback kontrolu uygular. Kurulum, anahtar bootstrap, guncelleme rollback journal'i ve state commit'i henuz yoktur.
- `rust/src/update_transaction.rs` imzasi dogrulanmis ikiliyi protected root'ta no-clobber hazirlayip adapter sagligi sonrasi state commit etmeyi modelleyen preview cekirdektir. Test adaptorunde rollback ve hata enjeksiyonu bulunur; kalici crash journal, gercek SCM/systemd adapter ve imzali production installer yoktur.
- Publisher anahtar kökü henüz üretim için güvenli şekilde provision edilmedi; CLI'da verilen PEM güven kökü sayılamaz.
- Özel geçici alana alınmış YARA-X kopyası için dosya bütünlüğü doğrulanır; ancak yönetici ayrıcalığına sahip saldırganlara karşı süreç ve dosya izolasyonu tamamlanmadı. Korumali dizinde 40-byte surum state'i atomik yenilenir; ayricalikli state rollback'e, dosya snapshot TOCTOU'ya, subprocess sandbox/child-tree temizligine ve elektrik kesintisi durumlarina ek sertlestirme gerekir.
- macOS engine pin ve macOS CI henüz yoktur; platform destek iddiası olmamalıdır.
- Bu dal production sürüm değildir: `main` birleştirme, imzalama ve release ayrı onay gerektirir.
