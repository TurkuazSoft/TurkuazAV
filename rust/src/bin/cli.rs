// Dosya Yolu: REPO_ROOT/rust/src/bin/cli.rs
// Amac: 0.3.1 CLI komutlarini Rust ile sagla
// Modul - FileType: Controller - Rust
// Version: 0.3.1
// Aciklama: Scan ve developer-only scan-rules kontrati
// Bagimli Oldugu Katman: Controller | Service | View

use anyhow::Context;
use std::{env, path::Path, process::ExitCode, sync::atomic::AtomicBool, thread, time::Duration};
use turkuazav::{
    scan_path_each, scan_rules, ChangeKind, DirectoryObserver, NativeChangeWakeup, ScanCoordinator,
    ScanStatus,
};

fn usage() {
    println!("Usage: turkuazav scan <file-or-directory> OR turkuazav scan-rules <target> <rules.yar> <rules.sig> <public.pem> <absolute-yr-path> OR turkuazav observe <directory> <cycles:1..20> <interval-seconds:1..60> OR turkuazav observe-events <directory> <cycles:1..20> <max-interval-seconds:1..60>");
}

fn run(args: &[String]) -> anyhow::Result<u8> {
    match args {
        [verb, path] if verb == "scan" => {
            let (mut hashed, mut skipped, mut failed) = (0, 0, 0);
            scan_path_each(Path::new(path), &AtomicBool::new(false), |r| {
                let path = r.path.display();
                match r.status {
                    ScanStatus::Hashed => {
                        hashed += 1;
                        println!(
                            "OK | {} | {} | {} bytes",
                            path,
                            r.sha256.unwrap_or_default(),
                            r.size_bytes.unwrap_or(0)
                        );
                    }
                    ScanStatus::Skipped => {
                        skipped += 1;
                        println!("SKIP | {} | {}", path, r.details.unwrap_or_default());
                    }
                    ScanStatus::Failed => {
                        failed += 1;
                        println!("ERROR | {} | {}", path, r.details.unwrap_or_default());
                    }
                }
                Ok(())
            })?;
            println!(
                "Summary: hashed={}, skipped={}, failed={}",
                hashed, skipped, failed
            );
            Ok(if failed > 0 { 1 } else { 0 })
        }
        [verb, root, cycles, interval] if verb == "observe" || verb == "observe-events" => {
            let cycles: u32 = cycles.parse().context("Invalid observe cycle count")?;
            let interval: u64 = interval.parse().context("Invalid observe interval")?;
            anyhow::ensure!(
                (1..=20).contains(&cycles) && (1..=60).contains(&interval),
                "Observe cycles or interval outside safe bounds"
            );
            let cancel = AtomicBool::new(false);
            let mut coordinator =
                ScanCoordinator::new(DirectoryObserver::new(Path::new(root), &cancel)?);
            let mut wakeup = if verb == "observe-events" {
                Some(NativeChangeWakeup::new(coordinator.root())?)
            } else {
                None
            };
            println!("BASELINE | {} tracked files", coordinator.tracked_files());
            let mut total = 0usize;
            for _ in 0..cycles {
                if let Some(watcher) = &mut wakeup {
                    let _ = watcher.wait(&cancel, Duration::from_secs(interval))?;
                } else {
                    thread::sleep(Duration::from_secs(interval));
                }
                coordinator.signal().request();
                let changes = coordinator
                    .run_pending(&cancel)?
                    .context("Missing queued reconciliation")?;
                for change in &changes {
                    let label = match change.kind {
                        ChangeKind::Added => "ADDED",
                        ChangeKind::Modified => "MODIFIED",
                        ChangeKind::Removed => "REMOVED",
                    };
                    println!(
                        "{} | {} | {}",
                        label,
                        change.path.display(),
                        change.sha256.as_deref().unwrap_or("-")
                    );
                }
                total += changes.len();
            }
            println!("Observe: changes={total}, cycles={cycles}");
            Ok(0)
        }
        [verb, target, rules, signature, key, engine] if verb == "scan-rules" => {
            let result = scan_rules(
                Path::new(target),
                Path::new(rules),
                Path::new(signature),
                Path::new(key),
                Path::new(engine),
            )?;
            if result.rule_identifiers.is_empty() {
                println!("NO_RULE_MATCH | {}", result.file_path.display());
            } else {
                for id in &result.rule_identifiers {
                    println!("RULE_MATCH | {} | {}", result.file_path.display(), id);
                }
            }
            Ok(0)
        }
        _ => {
            usage();
            Ok(2)
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("Scan error: {e:#}");
            ExitCode::from(1)
        }
    }
}
