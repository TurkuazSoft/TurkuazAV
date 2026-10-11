# 📄 Dosya Yolu: /TurkuazAV/config/yara-x-release.psd1
# 📌 Amac: Guvenilen YARA-X surumunu ve resmi Windows Linux SHA256 degerlerini tutmak
# 📌 Modul - FileType: Config - PowerShellData
# Version: 0.2.1
# Aciklama: Guvenilen YARA-X surumunu ve resmi Windows Linux SHA256 degerlerini tutmak
# Bagimli Oldugu Katman: Config

@{
    Version = 'v1.21.0'
    Windows = @{
        Url = 'https://github.com/VirusTotal/yara-x/releases/download/v1.21.0/yara-x-v1.21.0-x86_64-pc-windows-msvc.zip'
        Sha256 = '0e2fc4d2f64df3eaa22129ad5bd074c968a5d80766ddec6183b73175e5c9da25'
        Executable = 'yr.exe'
    }
    Linux = @{
        Url = 'https://github.com/VirusTotal/yara-x/releases/download/v1.21.0/yara-x-v1.21.0-x86_64-unknown-linux-gnu.tar.gz'
        Sha256 = '01585181e8979e36ac10ab123fcf8921cf8ba879bf942916413e091e18d64852'
        Executable = 'yr'
    }
}
