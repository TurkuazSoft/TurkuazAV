// Dosya Yolu: REPO_ROOT/rust/src/config.rs
// Amac: 0.3.1 CSharp limit ve guven koklerini korur
// Modul - FileType: Config - Rust
// Version: 0.3.1
// Aciklama: Degerler mevcut v0.3.1 uygulama sozlesmesinden aktarildi
// Bagimli Oldugu Katman: Config

pub const MAX_FILE_SIZE: u64 = 104_857_600;
pub const MAX_RULE_BYTES: usize = 524_288;
pub const MAX_SIGNATURE_BYTES: usize = 8_192;
pub const MAX_PUBLIC_KEY_BYTES: usize = 16_384;
pub const MAX_MANIFEST_BYTES: usize = 16_384;
pub const MAX_OUTPUT_BYTES: usize = 262_144;
pub const MAX_ENGINE_BYTES: u64 = 268_435_456;
pub const BUFFER_SIZE: usize = 81_920;
pub const ENGINE_TIMEOUT_SECONDS: u64 = 30;
pub const PACKAGE_SCHEMA: &str = "turkuazav.rule-package.v1";
pub const SIGNATURE_DOMAIN: &str = "TurkuazAV.rule-package.v1";
pub const WINDOWS_X64_ENGINE_SHA256: &str =
    "883c56964e0ffbe25eb0daf5b443914bea9db45d8dc4b6be7abbe59ff6797557";
pub const LINUX_X64_ENGINE_SHA256: &str =
    "a4b6fec172c813cdfc099a4a392939cfc2c555e9e7745fb4b5ed369ab1edf93b";

pub fn engine_digest() -> anyhow::Result<&'static str> {
    if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        Ok(WINDOWS_X64_ENGINE_SHA256)
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Ok(LINUX_X64_ENGINE_SHA256)
    } else {
        anyhow::bail!("YARA-X executable trust profile unsupported on this platform")
    }
}
