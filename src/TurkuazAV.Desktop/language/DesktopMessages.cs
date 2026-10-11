// # 📄 Dosya Yolu: /TurkuazAV/src/TurkuazAV.Desktop/language/DesktopMessages.cs
// # 📌 Amac: Kullaniciya gosterilen bilgi, kopyalama ve gecmis metinlerini saklamak
// # 📌 Modul - FileType: CSharp
// # Version: 0.3.1
// # Aciklama: Kullaniciya gosterilen bilgi, kopyalama ve gecmis metinlerini saklamak
// # Bagimli Oldugu Katman: Language

namespace TurkuazAV.Desktop.Language;

public static class DesktopMessages
{
    public const string NoFileSelected = "Henüz dosya seçilmedi.";
    public const string Ready = "Dosya seçildi. SHA-256 taraması başlatılabilir.";
    public const string Reading = "Dosya salt okunur modda inceleniyor…";
    public const string Cancelled = "Tarama iptal edildi.";
    public const string SelectError = "Dosya seçimi tamamlanamadı: ";
    public const string ScanError = "Tarama başarısız: ";
    public const string Success = "SHA-256 hesaplandı. Zararlılık değerlendirmesi yapılmadı.";
    public const string Finished = "Tarama tamamlandı.";
    public const string Skipped = "Dosya taranmadı: ";
    public const string Failed = "Dosya okunamadı: ";
    public const string CancelRequested = "İptal isteği gönderildi.";
    public const string Unsupported = "Geçersiz dosya.";
    public const string UnknownSize = "—";
    public const string ByteUnit = " bayt";
    public const string HistorySeparator = " | ";
    public const string Copied = "SHA-256 panoya kopyalandı.";
    public const string CopyFailed = "Kopyalama başarısız: ";
    public const string HistoryCleared = "Oturum geçmişi temizlendi.";
    public const string NoResult = "Rapor yok.";
}
