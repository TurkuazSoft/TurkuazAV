// Dosya Yolu: REPO_ROOT/rust/src/bin/cli.rs
// Amac: 0.3.1 CLI komutlarini Rust ile sagla
// Modul - FileType: Controller - Rust
// Version: 0.3.1
// Aciklama: Scan ve developer-only scan-rules kontrati
// Bagimli Oldugu Katman: Controller | Service | View

use std::{env, path::Path, process::ExitCode, sync::atomic::AtomicBool};
use turkuazav::{scan_path, scan_rules, ScanStatus};

fn usage() {
    println!("Usage: turkuazav scan <file-or-directory> OR turkuazav scan-rules <target> <rules.yar> <rules.sig> <public.pem> <absolute-yr-path>");
}

fn run(args: &[String]) -> anyhow::Result<u8> {
    match args {
        [verb, path] if verb == "scan" => {
            let results = scan_path(Path::new(path), &AtomicBool::new(false))?;
            let (mut hashed, mut skipped, mut failed) = (0, 0, 0);
            for r in results {
                let path = r.path.display();
                match r.status {
                    ScanStatus::Hashed => {
                        hashed += 1;
                        println!("OK | {} | {} | {} bytes", path, r.sha256.unwrap_or_default(), r.size_bytes.unwrap_or(0));
                    },
                    ScanStatus::Skipped => {
                        skipped += 1;
                        println!("SKIP | {} | {}", path, r.details.unwrap_or_default());
                    },
                    ScanStatus::Failed => {
                        failed += 1;
                        println!("ERROR | {} | {}", path, r.details.unwrap_or_default());
                    }
                }
            }
            println!("Summary: hashed={}, skipped={}, failed={}", hashed, skipped, failed);
            Ok(if failed > 0 { 1 } else { 0 })
        },
        [verb, target, rules, signature, key, engine] if verb == "scan-rules" => {
            let result = scan_rules(Path::new(target), Path::new(rules), Path::new(signature), Path::new(key), Path::new(engine))?;
            if result.rule_identifiers.is_empty() {
                println!("NO_RULE_MATCH | {}", result.file_path.display());
            } else {
                for id in &result.rule_identifiers {
                    println!("RULE_MATCH | {} | {}", result.file_path.display(), id);
                }
            }
            Ok(0)
        },
        _ => { usage(); Ok(2) }
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
