<!--
Dosya Yolu: REPO_ROOT/TEST_KILAVUZU_TR.md
Amac: Rust native test paketini kullanmak icin son kullanici kilavuzu
Modul - FileType: Documentation - Markdown
Version: 0.3.1
Aciklama: Imzasiz portable test paketi, SHA256 kontrolu ve manuel kabul adimlari
Bagimli Oldugu Katman: Documentation | Tool
-->
# TurkuazAV Rust 0.3.1 — Test Kılavuzu

**Bu sürüm antivirüs değildir.** Sadece salt okunur dosya/klasör SHA-256 analizi yapar. Zararlı yazılım teşhisi, gerçek zamanlı koruma, karantina, silme, otomatik başlatma veya sistem servisi kurulumu sağlamaz. İmzasız geliştirme paketidir; mevcut antivirüsünüzü devre dışı bırakmayın.

## Windows'ta çalıştırma

1. GitHub'daki **PR #10** Rust CI çalışmasının **Artifacts** alanından `TurkuazAV-0.3.1-RUST-UNSIGNED-TEST-win-x64` paketini indirin.
2. İndirilen GitHub artifact ZIP'ini bir klasöre açın. İçindeki `TurkuazAV-0.3.1-RUST-UNSIGNED-LOCAL-TEST-win-x64.zip` dosyası asıl uygulama arşividir. Aynı yerdeki `.zip.sha256` dosyası arşivin özetidir.
3. İsterseniz PowerShell ile, dosyaların bulunduğu klasörde, `Get-FileHash -Algorithm SHA256 .\TurkuazAV-0.3.1-RUST-UNSIGNED-LOCAL-TEST-win-x64.zip` komutunun sonucunu `.zip.sha256` dosyasındaki ilk 64 karakterle karşılaştırın. **Eşleşmiyorsa çalıştırmayın.** SHA-256 karşılaştırması bir yayıncı dijital imzası değildir.
4. Asıl uygulama ZIP'ini ayrı bir test klasörüne açın; **`turkuazav-desktop.exe`** dosyasını normal kullanıcı olarak çalıştırın. Yönetici yetkisi gerekmez. Kurulum veya kaldırma yapılmaz: test klasörünü silebilirsiniz.
5. **Dosya seç** veya **Klasör seç**, ardından **SHA-256 analizini başlat** seçeneğine basın. Ekrandaki özet bir dosyanın temiz olduğunu kanıtlamaz.

## İsteğe bağlı kullanıcı kurulumu (Windows x64)

Taşınabilir kullanım için kurulum gerekmez. İsterseniz asıl ZIP arşivini açtığınız klasörde `TurkuazAV-Preview-Setup.ps1` dosyasıyla **mevcut Windows kullanıcısı için** test kurulumu yapabilirsiniz. PowerShell betik çalıştırma ilkeleri buna izin vermelidir; güvenlik ilkesini bütün sistem için kapatmayın.

```powershell
pwsh -NoProfile -File .\TurkuazAV-Preview-Setup.ps1 -Action Verify
pwsh -NoProfile -File .\TurkuazAV-Preview-Setup.ps1 -Action Install
```

Kurulum `$env:LOCALAPPDATA\Programs\TurkuazAV-Preview` klasörüne yapılır, Başlat Menüsüne **TurkuazAV Preview** kısayolu eklenir. Bu yalnızca **imzasız test kurulumudur**; antivirüs servisi kaydetmez, yönetici yetkisi istemez, diğer kullanıcıları etkilemez ve Windows Uygulamalar listesine kayıt yapmaz. Var olan kurulum üzerine yazılmaz.

Kaldırmak için kurulan betiği çalıştırın:

```powershell
pwsh -NoProfile -File "$env:LOCALAPPDATA\Programs\TurkuazAV-Preview\TurkuazAV-Preview-Setup.ps1" -Action Uninstall
```

Kaldırıcı yalnızca kendi tanımlı dosyalarını temizler; tanımadığı/kullanıcıya ait dosyaları korur. Kaldırmadan önce masaüstü uygulamasını kapatın. Bu akış Windows CI'da geçici dizinle sınanır; gerçek bilgisayarda kısayol ve arayüz kabulü ayrıca gereklidir.

İsteğe bağlı başsız kontrol (PowerShell, uygulamanın açıldığı klasörde):

```powershell
.\turkuazav-desktop.exe --headless-self-test
```

Başarılıysa `RUST_DESKTOP_HEADLESS_SMOKE=PASS version=0.3.1` çıktısı alınır. Bu kontrol pencereyi, dosya seçiciyi, panoyu veya ekran görünümünü test etmez.

## Linux'ta çalıştırma

Linux x64 artifact'ını ve içindeki `.tar.gz` arşivini açın. Masaüstü oturumunda `./turkuazav-desktop` uygulamasını çalıştırın. Gerekli grafik kitaplıkları bilgisayarda bulunmalıdır. `./turkuazav-desktop --headless-self-test` komutu aynı başsız taramayı kontrol eder. Sistem servisi otomatik kurulmaz.

## Manuel kabul kontrol listesi

- [ ] Pencere açılıyor ve sürüm **v0.3.1** olarak görünüyor.
- [ ] Test dosyası seçiliyor; SHA-256 ve dosya boyutu gösteriliyor. İşlem kapsamı **SHA-256 hesaplandı**, tehdit değerlendirmesi **Yapılmadı**, kategori **Belirlenmedi** olarak görünüyor.
- [ ] Klasör seçimiyle ilerleme sayaçları çalışıyor; uzun tarama **İptal** ile durdurulabiliyor.
- [ ] Yeni bir hedef seçilince önceki dosyanın SHA-256 sonucu siliniyor.
- [ ] **SHA-256 kopyala** panoya doğru özeti aktarıyor.
- [ ] Türkçe karakterli klasör/dosya adı sorunsuz çalışıyor.
- [ ] Pencere yeniden boyutlandırılabiliyor; düğmeler ve uyarı okunabilir kalıyor.
- [ ] Oturum geçmişi en fazla 20 öğe tutuyor; temizleme düğmesi çalışıyor.
- [ ] Hata/atlama durumunda geçersiz veya önceki SHA-256 değeri gösterilmiyor/kopyalanmıyor; yeniden deneme mümkün.
- [ ] Yerel tanılama kayıtlarında dosya yolu veya hash gibi kişisel bilgiler bulunmuyor.

CI, Windows/Linux'ta ikilileri derleyip paketi açarak başsız testleri çalıştırır. **Bu liste gerçek bir kullanıcı oturumunda ayrıca test edilmelidir.** Testte sorun olursa PR #10 üzerine işletim sistemi, commit SHA'sı, hata metni ve mümkünse gizli bilgi içermeyen ekran görüntüsü ekleyin. Özel dosya yolları ve hassas dosyaları paylaşmayın.

Bu Rust test paketi otomatik üretim güncellemesi değildir. Yalnızca isteğe bağlı kullanıcı kurulumu vardır; korumalı sistem servisi kurulumu, üretim imzası, gerçek zamanlı koruma ve zararlı yazılım temizleme özellikleri sunulmamaktadır.
