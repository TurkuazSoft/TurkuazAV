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

impl eframe::App for DesktopApp {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        self.poll();
        if self.busy {
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading(format!("TurkuazAV v{}", env!("CARGO_PKG_VERSION")));
            ui.strong("DOSYA ANALİZİ / RUST PREVIEW");
            ui.separator();
            ui.colored_label(egui::Color32::YELLOW, PREVIEW_WARNING);
            ui.add_space(15.0);
            ui.group(|ui| {
                ui.heading("Dosya veya klasör seçimi");
                ui.label(
                    self.selected
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "Henüz dosya veya klasör seçilmedi.".into()),
                );
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(!self.busy, egui::Button::new("Dosya seç"))
                        .clicked()
                    {
                        self.pick();
                    }
                    if ui
                        .add_enabled(!self.busy, egui::Button::new("Klasör seç"))
                        .clicked()
                    {
                        self.pick_folder();
                    }
                    if ui
                        .add_enabled(
                            !self.busy && self.selected.is_some(),
                            egui::Button::new("SHA-256 tara"),
                        )
                        .clicked()
                    {
                        self.start();
                    }
                    if ui
                        .add_enabled(self.busy, egui::Button::new("İptal"))
                        .clicked()
                    {
                        self.cancel.store(true, Ordering::Relaxed);
                        self.status = "İptal istendi...".into();
                    }
                    if self.busy {
                        ui.spinner();
                    }
                });
                ui.label(&self.status);
                if self.busy {
                    let (hashed, skipped, failed) = self.progress.counts();
                    ui.label(format!(
                        "İlerleme: {} işlendi, {} atlandı, {} hata.",
                        hashed, skipped, failed
                    ));
                }
            });
            ui.add_space(12.0);
            ui.group(|ui| {
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
                        ui.monospace(digest);
                        if ui.button("SHA-256 kopyala").clicked() {
                            if arboard::Clipboard::new()
                                .and_then(|mut c| c.set_text(digest.clone()))
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
                    ui.label("Rapor yok.");
                }
                ui.small("SHA-256 bir güvenlik hükmü değildir.");
            });
            ui.add_space(12.0);
            ui.group(|ui| {
                ui.heading("Bu oturumdaki taramalar");
                ui.label("Geçmiş sadece bellektedir; diske kaydedilmez.");
                if ui.button("Oturum geçmişini temizle").clicked() {
                    self.history.clear();
                    self.status = "Oturum geçmişi temizlendi.".into();
                }
                egui::ScrollArea::vertical()
                    .max_height(150.0)
                    .show(ui, |ui| {
                        for item in &self.history {
                            ui.label(item);
                        }
                    });
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

fn main() -> eframe::Result<()> {
    log_event("APP_START", "Startup");
    eframe::run_native(
        &format!(
            "TurkuazAV v{} - Deneysel Dosya Analizi",
            env!("CARGO_PKG_VERSION")
        ),
        eframe::NativeOptions::default(),
        Box::new(|_| Ok(Box::new(DesktopApp::default()))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
