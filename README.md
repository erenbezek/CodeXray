# CodeXray

Taint-tracking tabanlı, modüler bir statik güvenlik tarama aracı (SAST).

Kodu çalıştırmadan okur; kullanıcı girdisinin (`source`) sanitize
edilmeden tehlikeli bir fonksiyona (`sink`) ulaşıp ulaşmadığını AST
üzerinde takip eder ve her bulguyu resmi CWE standardına eşleyerek
raporlar.

Bilişim güvenliği stajı kapsamında geliştirilen bir portföy projesidir.
Ticari SAST araçlarının (Semgrep, Checkmarx, Snyk) yerini almayı değil,
çalışma prensibini küçük ölçekte, savunulabilir şekilde yeniden inşa
etmeyi hedefler.

## Durum

M5 tamamlandı: paketleme/test altyapısı düzeltildi, birim test kapsamı genişletildi,
sanitizer eşleşme semantiği pattern seviyesine indirgendi ve Python + Flask için
reflected/server-side XSS kuralı eklendi (bkz. `docs/roadmap.md`).

## Şu an ne çalışıyor

- **SQL Injection (CWE-89)** için uçtan uca taint tracking: source →
  propagation (atama, string concat, f-string) → sanitizer → sink →
  bulgu. `escape_sql` gibi bir sanitizer'dan geçen değerler için alarm
  üretilmiyor; geçmeyenler için tam veri akışı izi (`request.args →
  username → query → cursor.execute`) ile raporlanıyor.
- **XSS (CWE-79)** için reflected/server-side taint tracking: Flask request
  input'ları → HTML text sanitizer → `Response`, `make_response` veya `Markup`.

## Neden bu proje

Amaç terimleri ezberlemek değil, tespit eden bir sistem kurmak. Mimari
bilerek modüler: yeni bir zafiyet kategorisi eklemek `rules/` altına
yeni bir dosya eklemek demek, çekirdek motora (`src/codexray/`)
dokunmadan.

## Kurulum

```bash
pip install -e .
pip install pytest
```

## Test

```bash
pytest
```

## Detaylı dokümantasyon

- [docs/project-context.md](docs/project-context.md) — proje amacı,
  kapsam, mimari (yeni katılan biri veya bir LLM için başlangıç noktası)
- [docs/architecture.md](docs/architecture.md) — teknik mimari
- [docs/design-decisions.md](docs/design-decisions.md) — alınan kararlar
  ve gerekçeleri
- [docs/roadmap.md](docs/roadmap.md) — milestone planı
- [AGENTS.md](AGENTS.md) — bu depoda çalışan LLM'ler için kurallar
