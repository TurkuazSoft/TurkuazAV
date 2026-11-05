// Dosya Yolu: REPO_ROOT/rust/src/bin/desktop.rs
// Amac: Platformlar arasi Rust GUI 0.3.1 hash preview
// Modul - FileType: View - Rust
// Version: 0.3.1
// Aciklama: Dosya seç, iptal, hash raporu, clipboard, bellek gecmisi, gizli tani
// Bagimli Oldugu Katman: View | Controller | Service | Tool | Language

use eframe::egui;
use std::{
    collections::VecDeque,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver},
        Arc,
    },
    thread,
};
use turkuazav::{scan_path_each, FileScanResult, ScanStatus};

const HISTORY_LIMIT: usize = 20;
const COMPACT_NAVIGATION_WIDTH: f32 = 720.0;
const PREVIEW_WARNING: &str =
    "Deneysel tarayıcı — antivirüs koruması sağlamaz. Yalnızca SHA-256 hesaplar.";

#[derive(Default)]
struct ScanProgress {
    hashed: AtomicUsize,
    skipped: AtomicUsize,
    failed: AtomicUsize,
}

impl ScanProgress {
    fn record(&self, status: &ScanStatus) {
        let counter = match status {
            ScanStatus::Hashed => &self.hashed,
            ScanStatus::Skipped => &self.skipped,
            ScanStatus::Failed => &self.failed,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn counts(&self) -> (usize, usize, usize) {
        (
            self.hashed.load(Ordering::Relaxed),
            self.skipped.load(Ordering::Relaxed),
            self.failed.load(Ordering::Relaxed),
        )
    }
}

struct ScanOutcome {
    report: Option<FileScanResult>,
    history: VecDeque<String>,
    traversal_error: Option<String>,
}

struct DesktopApp {
    selected: Option<PathBuf>,
    busy: bool,
    cancel: Arc<AtomicBool>,
    incoming: Option<Receiver<ScanOutcome>>,
    progress: Arc<ScanProgress>,
    status: String,
    report: Option<FileScanResult>,
    history: VecDeque<String>,
    page: Page,
    light_theme: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Page {
    #[default]
    Overview,
    Analysis,
    History,
    Modules,
    Settings,
}

impl Page {
    const NAVIGATION: [(Self, &'static str); 5] = [
        (Self::Overview, "⌂  Genel Bakış"),
        (Self::Analysis, "▤  Dosya Analizi"),
        (Self::History, "◷  Geçmiş"),
        (Self::Modules, "◇  Modüller"),
        (Self::Settings, "⚙  Ayarlar"),
    ];
}

fn compact_navigation(width: f32) -> bool {
    width < COMPACT_NAVIGATION_WIDTH
}

impl Default for DesktopApp {
    fn default() -> Self {
        Self {
            selected: None,
            busy: false,
            cancel: Arc::new(AtomicBool::new(false)),
            incoming: None,
            progress: Arc::new(ScanProgress::default()),
            status: "Tarama için dosya bekleniyor.".into(),
            report: None,
            history: VecDeque::new(),
            page: Page::Overview,
            light_theme: false,
        }
    }
}

impl DesktopApp {
    fn choose(&mut self, path: PathBuf) {
        self.selected = Some(path);
        self.report = None; // Old digest must never survive selecting a new target.
        self.status = "Seçim yapıldı. Taramaya hazır.".into();
    }

    fn pick(&mut self) {
        if let Some(file) = rfd::FileDialog::new().pick_file() {
            self.choose(file);
        }
    }

    fn pick_folder(&mut self) {
        if let Some(folder) = rfd::FileDialog::new().pick_folder() {
            self.choose(folder);
        }
    }

    fn start(&mut self) {
        let Some(path) = self.selected.clone() else {
            return;
        };
        if self.busy {
            return;
        }
        self.cancel = Arc::new(AtomicBool::new(false));
        self.progress = Arc::new(ScanProgress::default());
        let cancelled = Arc::clone(&self.cancel);
        let progress = Arc::clone(&self.progress);
        let (tx, rx) = mpsc::channel();
        self.incoming = Some(rx);
        self.report = None;
        self.busy = true;
        self.status = "SHA-256 taraması yapılıyor...".into();
        thread::spawn(move || {
            // No unbounded result Vec or per-file message queue.
            let mut report = None;
            let mut history = VecDeque::with_capacity(HISTORY_LIMIT);
            let outcome = scan_path_each(&path, &cancelled, |result| {
                progress.record(&result.status);
                let name = result
                    .path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy();
                history.push_front(format!(
                    "{} | {} | {:?}",
                    chrono::Local::now().format("%Y-%m-%d %H:%M"),
                    name,
                    result.status
                ));
                history.truncate(HISTORY_LIMIT);
                report = Some(result);
                Ok(())
            });
            let _ = tx.send(ScanOutcome {
                report,
                history,
                traversal_error: outcome.err().map(|error| error.to_string()),
            });
        });
    }

    fn poll(&mut self) {
        let received = self.incoming.as_ref().map(|rx| rx.try_recv());
        if matches!(received, Some(Err(mpsc::TryRecvError::Disconnected))) {
            self.busy = false;
            self.incoming = None;
            self.report = None;
            if self.cancel.load(Ordering::Relaxed) {
                self.status = "Tarama iptal edildi.".into();
            } else {
                log_event("SCAN_FAILED", "WorkerDisconnected");
                self.status = "Tarama tamamlanamadı. Yeniden deneyin.".into();
            }
            return;
        }
        if let Some(Ok(outcome)) = received {
            self.busy = false;
            self.incoming = None;
            if self.cancel.load(Ordering::Relaxed) {
                // Incomplete scans never surface a previous/partial successful hash.
                self.status = "Tarama iptal edildi.".into();
                self.report = None;
            } else if outcome.traversal_error.is_some() {
                log_event("SCAN_FAILED", "TraversalError");
                self.status = "Tarama tamamlanamadı. Yeniden deneyin.".into();
                self.report = None;
            } else {
                let (hashed, skipped, failed) = self.progress.counts();
                self.status = format!(
                    "Tarama tamamlandı: {} işlendi, {} atlandı, {} hata. Sonuç antivirüs temizliği kanıtı değildir.",
                    hashed, skipped, failed
                );
                for item in outcome.history.into_iter().rev() {
                    self.history.push_front(item);
                }
                self.history.truncate(HISTORY_LIMIT);
                if failed > 0 {
                    log_event("SCAN_FAILED", "ScanError");
                }
                self.report = outcome.report;
            }
        }
    }
}

// @dev-id TAV-HORIZON-UI-001
// @purpose Provide a navigable native dashboard for the existing read-only SHA-256 worker.
// @reason A polished preview must never imply actual malware protection.
const TEAL: egui::Color32 = egui::Color32::from_rgb(20, 204, 197);
const WARNING: egui::Color32 = egui::Color32::from_rgb(237, 178, 69);

fn section_title(ui: &mut egui::Ui, title: &str, description: &str) {
    ui.heading(egui::RichText::new(title).size(25.0).strong());
    ui.label(egui::RichText::new(description).size(14.0).weak());
    ui.add_space(14.0);
}

fn dashboard_card(ui: &mut egui::Ui, title: &str, detail: &str) {
    egui::Frame::group(ui.style())
        .inner_margin(egui::Margin::same(14))
        .show(ui, |ui| {
            ui.set_min_width(170.0);
            ui.label(egui::RichText::new(title).strong().size(15.0));
            ui.add_space(6.0);
            ui.label(detail);
        });
}

fn metric_card(ui: &mut egui::Ui, title: &str, value: usize, accent: egui::Color32) {
    egui::Frame::group(ui.style())
        .inner_margin(egui::Margin::same(14))
        .show(ui, |ui| {
            ui.set_min_width(136.0);
            ui.label(egui::RichText::new(title).size(13.0));
            ui.label(
                egui::RichText::new(value.to_string())
                    .size(27.0)
                    .strong()
                    .color(accent),
            );
        });
}

impl DesktopApp {
    fn sidebar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("horizon_navigation")
            .resizable(false)
            .default_width(184.0)
            .show(ctx, |ui| {
                ui.add_space(15.0);
                ui.heading(
                    egui::RichText::new("TurkuazAV")
                        .color(TEAL)
                        .size(22.0)
                        .strong(),
                );
                ui.label(egui::RichText::new("Horizon • Deneysel").weak().size(12.0));
                ui.add_space(26.0);
                for (page, caption) in Page::NAVIGATION {
                    let button = egui::Button::new(egui::RichText::new(caption).size(15.0))
                        .min_size(egui::vec2(ui.available_width(), 38.0))
                        .selected(self.page == page);
                    if ui.add(button).clicked() {
                        self.page = page;
                    }
                    ui.add_space(6.0);
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.label(egui::RichText::new("SHA-256 önizleme").weak().size(11.0));
                });
            });
    }

    fn compact_nav(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            for (page, caption) in Page::NAVIGATION {
                if ui
                    .add(
                        egui::Button::new(caption)
                            .selected(self.page == page)
                            .min_size(egui::vec2(112.0, 36.0)),
                    )
                    .clicked()
                {
                    self.page = page;
                }
            }
        });
        ui.separator();
    }

    fn surface(&self, ui: &egui::Ui) -> egui::Frame {
        let (fill, outline) = if self.light_theme {
            (egui::Color32::WHITE, egui::Color32::from_gray(210))
        } else {
            (
                egui::Color32::from_rgb(16, 43, 58),
                egui::Color32::from_rgb(39, 84, 99),
            )
        };
        egui::Frame::group(ui.style())
            .fill(fill)
            .stroke(egui::Stroke::new(1.0, outline))
            .inner_margin(egui::Margin::same(16))
    }

    fn top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("horizon_header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new(format!("TurkuazAV v{}", env!("CARGO_PKG_VERSION")))
                        .strong()
                        .size(16.0),
                );
                ui.separator();
                ui.colored_label(WARNING, "Deneysel sürüm");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let caption = if self.light_theme {
                        "Koyu tema"
                    } else {
                        "Açık tema"
                    };
                    if ui.button(caption).clicked() {
                        self.light_theme = !self.light_theme;
                    }
                });
            });
            ui.add_space(4.0);
        });
    }

    fn warning_banner(&self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(WARNING, "ⓘ");
                ui.label(PREVIEW_WARNING);
            });
        });
    }

    fn target_picker(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    !self.busy,
                    egui::Button::new(
                        egui::RichText::new("Dosya seç")
                            .color(egui::Color32::from_rgb(5, 24, 32))
                            .strong(),
                    )
                    .fill(TEAL)
                    .min_size(egui::vec2(120.0, 40.0)),
                )
                .clicked()
            {
                self.pick();
            }
            if ui
                .add_enabled(
                    !self.busy,
                    egui::Button::new("Klasör seç").min_size(egui::vec2(120.0, 40.0)),
                )
                .clicked()
            {
                self.pick_folder();
            }
        });
        ui.add_space(8.0);
        ui.label(egui::RichText::new("Analiz hedefi").strong());
        let target = self
            .selected
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "Henüz bir dosya veya klasör seçilmedi.".to_owned());
        ui.add(egui::Label::new(target).wrap());
        ui.add_space(10.0);
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    !self.busy && self.selected.is_some(),
                    egui::Button::new(
                        egui::RichText::new("SHA-256 analizini başlat")
                            .color(egui::Color32::from_rgb(5, 24, 32))
                            .strong(),
                    )
                    .fill(TEAL)
                    .min_size(egui::vec2(234.0, 44.0)),
                )
                .clicked()
            {
                self.start();
            }
            if ui
                .add_enabled(
                    self.busy,
                    egui::Button::new("İptal").min_size(egui::vec2(96.0, 44.0)),
                )
                .clicked()
            {
                self.cancel.store(true, Ordering::Relaxed);
                self.status = "İptal istendi...".into();
            }
            if self.busy {
                ui.spinner();
            }
        });
        ui.add_space(8.0);
        ui.label(&self.status);
        if self.busy {
            ui.label("Analiz devam ediyor. İşlem sayıları canlı olarak güncellenir.");
        }
    }

    fn progress_cards(&self, ui: &mut egui::Ui) {
        let (hashed, skipped, failed) = self.progress.counts();
        ui.horizontal_wrapped(|ui| {
            metric_card(ui, "İşlenen dosya", hashed, TEAL);
            metric_card(ui, "Atlanan dosya", skipped, WARNING);
            metric_card(ui, "Hata", failed, egui::Color32::from_rgb(239, 96, 105));
        });
        if self.busy {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Dosyalar analiz ediliyor...");
            });
            ui.small("Toplam dosya sayısı önceden bilinmediği için yüzde gösterilmiyor.");
        }
    }

    fn report_card(&mut self, ui: &mut egui::Ui) {
        ui.heading("Son analiz raporu");
        if let Some(report) = &self.report {
            ui.label(format!(
                "Durum: {:?} {}",
                report.status,
                report.details.as_deref().unwrap_or("")
            ));
            ui.label(format!(
                "Dosya boyutu: {}",
                report
                    .size_bytes
                    .map(|n| format!("{n} bayt"))
                    .unwrap_or_else(|| "-".into())
            ));
            if let Some(digest) = &report.sha256 {
                ui.label(egui::RichText::new(digest).monospace());
                if ui.button("SHA-256 kopyala").clicked() {
                    if arboard::Clipboard::new()
                        .and_then(|mut clipboard| clipboard.set_text(digest.clone()))
                        .is_ok()
                    {
                        self.status = "Hash panoya kopyalandı.".into();
                    } else {
                        log_event("COPY_FAILED", "ClipboardError");
                        self.status = "Panoya kopyalanamadı.".into();
                    }
                }
            }
        } else {
            ui.label("Henüz tamamlanmış analiz raporu yok.");
        }
        ui.small("SHA-256 sonucu bir dosyanın güvenli olduğunu kanıtlamaz.");
    }

    fn history_card(&mut self, ui: &mut egui::Ui) {
        ui.heading("Oturum geçmişi");
        ui.label("Son 20 kayıt • Yalnızca bellekte tutulur.");
        if ui.button("Oturum geçmişini temizle").clicked() {
            self.history.clear();
            self.status = "Oturum geçmişi temizlendi.".into();
        }
        egui::ScrollArea::vertical()
            .max_height(210.0)
            .show(ui, |ui| {
                if self.history.is_empty() {
                    ui.label("Bu oturumda kayıt bulunmuyor.");
                }
                for item in &self.history {
                    ui.label(item);
                }
            });
    }

    fn overview(&mut self, ui: &mut egui::Ui) {
        section_title(
            ui,
            "Dosya Analiz Aracı",
            "SHA-256 hesaplama ve dosya inceleme önizlemesi",
        );
        self.warning_banner(ui);
        ui.add_space(14.0);
        self.surface(ui).show(ui, |ui| {
            ui.heading("Yeni analiz başlat");
            ui.add_space(8.0);
            self.target_picker(ui);
            ui.add_space(14.0);
            self.progress_cards(ui);
        });
        ui.add_space(14.0);
        self.surface(ui).show(ui, |ui| self.report_card(ui));
        ui.add_space(12.0);
        self.surface(ui).show(ui, |ui| self.history_card(ui));
    }

    fn modules(&self, ui: &mut egui::Ui) {
        section_title(
            ui,
            "Koruma modülleri",
            "Mevcut özellikler ile planlananları açıkça ayırıyoruz.",
        );
        dashboard_card(
            ui,
            "SHA-256 dosya analizi",
            "Kullanılabilir • Dosya bütünlük özeti üretir.",
        );
        ui.add_space(8.0);
        dashboard_card(
            ui,
            "Gerçek zamanlı koruma",
            "Mevcut değil • Dosyaları otomatik izlemiyor.",
        );
        ui.add_space(8.0);
        dashboard_card(
            ui,
            "Karantina ve tehdit engelleme",
            "Mevcut değil • Dosyaları engellemiyor veya taşımıyor.",
        );
        ui.add_space(8.0);
        dashboard_card(
            ui,
            "Zararlı yazılım tespiti",
            "Bu GUI önizlemesinde etkin değil.",
        );
    }

    fn settings(&mut self, ui: &mut egui::Ui) {
        section_title(ui, "Ayarlar", "Masaüstü görünümü ve sürüm bilgileri");
        ui.checkbox(&mut self.light_theme, "Açık tema kullan");
        ui.add_space(10.0);
        ui.label(format!("Uygulama sürümü: {}", env!("CARGO_PKG_VERSION")));
        ui.label("Arayüz: TurkuazAV Horizon (deneysel)");
        ui.label("Geçmiş: Yalnızca bellek • en fazla 20 kayıt");
        ui.add_space(12.0);
        self.warning_banner(ui);
    }
}

impl eframe::App for DesktopApp {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        self.poll();
        if self.busy {
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }
        let mut visuals = if self.light_theme {
            egui::Visuals::light()
        } else {
            egui::Visuals::dark()
        };
        if !self.light_theme {
            visuals.panel_fill = egui::Color32::from_rgb(7, 23, 34);
            visuals.window_fill = egui::Color32::from_rgb(12, 34, 47);
        }
        visuals.selection.bg_fill = TEAL;
        ctx.set_visuals(visuals);

        self.top_bar(ctx);
        let use_compact_navigation = compact_navigation(ctx.available_rect().width());
        if !use_compact_navigation {
            self.sidebar(ctx);
        }
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                if use_compact_navigation {
                    self.compact_nav(ui);
                }
                ui.add_space(12.0);
                match self.page {
                    Page::Overview => self.overview(ui),
                    Page::Analysis => {
                        section_title(
                            ui,
                            "Dosya Analizi",
                            "Bir dosya veya klasörün SHA-256 özetini hesaplayın.",
                        );
                        self.warning_banner(ui);
                        ui.add_space(12.0);
                        self.target_picker(ui);
                        ui.add_space(12.0);
                        self.progress_cards(ui);
                        ui.separator();
                        self.report_card(ui);
                    }
                    Page::History => {
                        section_title(ui, "Geçmiş", "Bu uygulama oturumunda tamamlanan analizler.");
                        self.history_card(ui);
                    }
                    Page::Modules => self.modules(ui),
                    Page::Settings => self.settings(ui),
                }
                ui.add_space(20.0);
                ui.small(
                    "Gerçek zamanlı koruma, karantina ve tehdit engelleme bu sürümde mevcut değildir.",
                );
            });
        });
    }
}

/// No paths, hashes, message bodies, command lines or user identifiers are logged.
fn log_event(code: &str, kind: &str) {
    let _ = (|| -> std::io::Result<()> {
        let Some(local) = dirs::data_local_dir() else {
            return Ok(());
        };
        let folder = local.join("TurkuazAV").join("diagnostics");
        fs::create_dir_all(&folder)?;
        let now = chrono::Utc::now();
        let file = folder.join(format!("desktop-{}.log", now.format("%Y%m%d")));
        writeln!(
            OpenOptions::new().create(true).append(true).open(file)?,
            "{} | {} | {}",
            now.to_rfc3339(),
            code,
            kind
        )?;
        if let Ok(entries) = fs::read_dir(&folder) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !name.starts_with("desktop-") || !name.ends_with(".log") {
                    continue;
                }
                if let Ok(age) = entry.metadata().and_then(|m| m.modified()) {
                    if age
                        .elapsed()
                        .is_ok_and(|duration| duration.as_secs() > 7 * 24 * 3600)
                    {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }
        Ok(())
    })();
}

/// @dev-id TAV-DESKTOP-SMOKE-010
/// @purpose Run the shipped desktop scan worker without opening a window.
/// @reason CI must execute the packaged GUI binary, not only compile it.
/// @contract Local harmless sample, bounded wait, exact SHA-256 assertion.
/// This does not validate native window rendering, pickers or clipboard.
fn run_headless_self_test() -> std::io::Result<()> {
    let fixture = tempfile::tempdir()?;
    let sample = fixture.path().join("harmless-sample.txt");
    fs::write(&sample, b"abc")?;
    let mut app = DesktopApp::default();
    app.choose(sample);
    app.start();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while app.busy && std::time::Instant::now() < deadline {
        app.poll();
        if app.busy {
            thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    if app.busy {
        return Err(std::io::Error::other("Desktop scan worker timed out"));
    }
    let expected = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
    let correct = app.progress.counts() == (1, 0, 0)
        && app.report.as_ref().is_some_and(|report| {
            report.status == ScanStatus::Hashed
                && report.size_bytes == Some(3)
                && report.sha256.as_deref() == Some(expected)
        })
        && app.status.contains("1 işlendi");
    if !correct {
        return Err(std::io::Error::other(
            "Desktop scan worker contract mismatch",
        ));
    }
    println!(
        "RUST_DESKTOP_HEADLESS_SMOKE=PASS version={}",
        env!("CARGO_PKG_VERSION")
    );
    Ok(())
}

fn main() -> eframe::Result<()> {
    // The test mode is opt-in; normal users still launch the native window.
    if std::env::args_os()
        .skip(1)
        .any(|arg| arg == "--headless-self-test")
    {
        if let Err(error) = run_headless_self_test() {
            eprintln!("RUST_DESKTOP_HEADLESS_SMOKE=FAIL: {error}");
            std::process::exit(1);
        }
        return Ok(());
    }
    log_event("APP_START", "Startup");
    eframe::run_native(
        &format!(
            "TurkuazAV v{} - Deneysel Dosya Analizi",
            env!("CARGO_PKG_VERSION")
        ),
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1120.0, 770.0])
                .with_min_inner_size([600.0, 480.0]),
            ..Default::default()
        },
        Box::new(|_| Ok(Box::new(DesktopApp::default()))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_navigation_keeps_all_pages_available_in_small_windows() {
        assert!(compact_navigation(600.0));
        assert!(compact_navigation(COMPACT_NAVIGATION_WIDTH - 1.0));
        assert!(!compact_navigation(COMPACT_NAVIGATION_WIDTH));
        assert!(!compact_navigation(1120.0));
        assert_eq!(Page::NAVIGATION.len(), 5);
    }

    #[test]
    fn headless_self_test_runs_real_desktop_scan_worker() {
        run_headless_self_test().unwrap();
    }

    #[test]
    fn disconnected_worker_restores_controls_and_clears_report() {
        let (sender, receiver) = mpsc::channel();
        drop(sender);
        let mut app = DesktopApp {
            busy: true,
            incoming: Some(receiver),
            ..DesktopApp::default()
        };
        app.poll();
        assert!(!app.busy);
        assert!(app.incoming.is_none());
        assert!(app.report.is_none());
        assert!(app.status.contains("Yeniden deneyin"));
    }

    #[test]
    fn folder_worker_streams_results_and_limits_history() {
        let temp = tempfile::tempdir().unwrap();
        for index in 0..30 {
            fs::write(temp.path().join(format!("file-{index:02}.txt")), b"abc").unwrap();
        }
        let mut app = DesktopApp {
            selected: Some(temp.path().to_path_buf()),
            ..DesktopApp::default()
        };
        app.start();
        for _ in 0..300 {
            app.poll();
            if !app.busy {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!app.busy, "folder scan worker did not finish");
        assert_eq!(app.progress.counts(), (30, 0, 0));
        assert_eq!(app.history.len(), HISTORY_LIMIT);
        assert!(app.report.is_some());
        assert!(app.status.contains("30 işlendi"));
    }

    #[test]
    fn disconnected_after_cancellation_is_not_reported_as_scan_success() {
        let (sender, receiver) = mpsc::channel();
        drop(sender);
        let mut app = DesktopApp {
            busy: true,
            incoming: Some(receiver),
            ..DesktopApp::default()
        };
        app.cancel.store(true, Ordering::Relaxed);
        app.poll();
        assert!(!app.busy);
        assert!(app.report.is_none());
        assert_eq!(app.status, "Tarama iptal edildi.");
    }
}
