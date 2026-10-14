<!--
Dosya Yolu: REPO_ROOT/AGENTS.md
Amac: TurkuazAV icin DevStandards v3.0.0 gelistirme protokolu
Modul - Documentation Markdown
Version: 3.0.0
Aciklama: Merkezi standart pinli, mevcut proje yapisina uyumlu
Bagimli Oldugu Katman: Documentation
-->

# TurkuazAV - Project Agent Contract

**BURAK DEV STANDARD v3.0.0:** active, commit `72f6f642128fa29ec9a68b18881e9aa225739c9d`.
**Source:** https://github.com/TurkuazSoft/DevStandards/tree/72f6f642128fa29ec9a68b18881e9aa225739c9d
**Teknoloji:** .NET security; profil `platforms/dotnet.md`.
**Proje roadmap'i:** Mevcut README, docs, issue ve PR'lar.

## Zorunlu kurallar

- Once mevcut AGENTS, kaynak/branch, roadmap, acik PR ve CI'yi kontrol et; "Devam et" son dogrulanmis adimdir.
- Guvenlik/veri ve calisan davranisi koru; kapsam disi refactor, onaysiz DB degisikligi veya release yapma.
- Controller request/response, Service is kurali, Repository/Model veri, Tool/Adapter entegrasyon, View arayuz, Language yerellestirmedir. Platform dosya yapisini koru.
- Yeni veya degisen teknik dosyalarda format izin veriyorsa Dosya Yolu, Amac, Modul - FileType, Version, Aciklama ve Bagimli Oldugu Katman bilgilerini kullan. JSON, binary ve yorum yasaklayan formatlari bozma.
- Uydurma mutlak yol yerine `REPO_ROOT/goreli-yol` yaz; magic string, inline secret ve izinsiz config override yapma.
- Gerekli build, unit, contract, integration ve smoke testlerini dogru ortamda kos; test edilmemis sonucu PASS sayma. Test artifactini release olarak sunma.
- Public fork PR kodunu kisisel self-hosted runner'a baglama. Baska repo scope'una otomatik yazma.
- Merkezi repo private oldugundan dis katkicilar erisemeyebilir; bu yerel temel kurallar bagimsiz uygulanir.

## .NET security odak kurallari

Tarama motoru/servis guvenligi, windows installer ve AV false positive davranisini ayri test et.

Standart degisiklikleri bu repoya gelecekte ancak kontrollu ayri PR ile tasinir.
