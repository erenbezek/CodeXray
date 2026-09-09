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

Dört taint kategorisi çalışıyor (SQL Injection, XSS, Path Manipulation,
Sensitive Data Exposure), çalıştırılabilir bir CLI tarayıcı var ve motor
gerçek kod üzerinde denendi.

Mimarinin maliyeti ölçüldü ve sınırı nettir. **Mevcut bir kaynak ailesi
içinde** yeni kategori eklemek çekirdeğe hiç dokunmuyor: Path Manipulation
`taint_engine.py`'de **sıfır satır** değiştirdi; genişleme yalnızca kurala
özgü olmayan veri-akışı katmanında (`call_model.py`, 7 satır) oldu.

**Yeni bir kaynak ailesi** eklemek ise bedelli: Sensitive Data Exposure
`taint_engine.py`'de **25 satıra** mal oldu, çünkü kuralların birbirinin
sink'ini tetiklediği ortaya çıktı ve motora kural izolasyonu eklemek
gerekti. Neyi zorladığı adım adım kayıtlı.

Yani mimari kategori eklemeye açık, kaynak ailesi eklemeye kısmen açık —
ölçülmüş bir sınır, slogan değil.

AST-yapısal kurallar (M8), presence-check (M9) ve LLM triage katmanı (M11)
**ertelendi** — gerekçeleri `docs/design-decisions.md` içinde kayıtlı.

Milestone planı için `docs/roadmap.md`.

## Şu an ne çalışıyor

- **SQL Injection (CWE-89)** için uçtan uca taint tracking: source →
  propagation (atama, string concat, f-string) → sanitizer → sink →
  bulgu. `escape_sql` gibi bir sanitizer'dan geçen değerler için alarm
  üretilmiyor; geçmeyenler için tam veri akışı izi (`request.args →
  username → query → cursor.execute`) ile raporlanıyor.
- **XSS (CWE-79)** için reflected/server-side taint tracking: Flask request
  input'ları → HTML text sanitizer → `Response`, `make_response` veya `Markup`.
- **Path Manipulation (CWE-22)** için Flask request input'larının güvenli
  basename sanitizer'ları olmadan dosya sink'lerine ulaşması.
- **Sensitive Data Exposure (CWE-200)** için hassas kaynakların konsol, log
  veya HTTP yanıtlarına ifşa edilmesi.

## Neden bu proje

Amaç terimleri ezberlemek değil, tespit eden bir sistem kurmak. Mimari
bilerek modüler: yeni bir zafiyet kategorisi eklemek `codexray/rules/` altına
yeni bir dosya eklemek demek, çekirdek motora (`src/codexray/`)
dokunmadan.

## Kurulum

```bash
pip install -e .
pip install pytest
```

## CLI tarayıcı

Kurulumdan sonra bir dosyayı veya dizini tarayabilirsiniz:

```bash
codexray scan examples/vulnerable
python -m codexray scan examples/vulnerable
```

Her bulgu için iki satır: konum + severity + kural + CWE + kaynak ailesi,
ve altında **tam veri akışı izi**. Bu iz, aracı bir desen eşleştiriciden
ayıran şey.

```text
examples/vulnerable/path_manipulation.py:5  HIGH  path-manipulation  CWE-22  [user-input]
    request.args -> path -> open
examples/vulnerable/sensitive_data.py:5  MEDIUM  sensitive-data-exposure  CWE-200  [sensitive]
    os.environ -> secret -> print
examples/vulnerable/sql_injection.py:4  CRITICAL  sql-injection  CWE-89  [user-input]
    request.args -> username -> query -> cursor.execute
examples/vulnerable/xss.py:4  HIGH  xss  CWE-79  [user-input]
    request.args -> value -> body -> Response
4 bulgu / 4 dosya tarandı
```

Güvenli örnekler bulgu üretmiyor:

```bash
$ codexray scan examples/safe
Bulgu yok / 4 dosya tarandı
```

### Exit kodları

| Kod | Anlamı |
|---|---|
| 0 | Bulgu yok |
| 1 | En az bir bulgu |
| 2 | Kullanım hatası ya da yol bulunamadı |

CI'da doğrudan kapı olarak kullanılabilir.

### Bağımlılık denetimi

Bağımlılık taraması ayrı bir alt komuttur ve `Finding`/taint çıktısından
bağımsızdır:

```bash
python -m pip install pip-audit
codexray audit examples/requirements.txt
codexray audit examples/requirements.txt --json
```

`examples/requirements.txt` bilerek eski sürümler sabitler — kod tarayıcı
için `examples/vulnerable/` ne ise, bağımlılık tarayıcı için o:

```text
flask 0.12.2  PYSEC-2019-179  -> 1.0
    CVE-2019-1010083, GHSA-5wv5-4vpf-pj6m
flask 0.12.2  PYSEC-2018-66  -> 0.12.3
    CVE-2018-1000656, GHSA-562c-5r94-xh97
...
10 zafiyet / 6 paket
```

Her satır: paket, kurulu sürüm, zafiyet kimliği ve düzeltildiği sürüm;
altında CVE / GHSA alias'ları.

Rapor edilen paket sayısı dosyadaki satır sayısından fazla olabilir:
`pip-audit` bağımlılıkları da çözer, yani iki sabitlenmiş paket altı pakete
açılır. Zafiyet sayısı da zafiyet veritabanı büyüdükçe artar.

`pip-audit` **runtime bağımlılığı değildir** — CLI onu `sys.executable -m
pip_audit` ile dış araç olarak çağırır. `--no-deps` bayrağı çözümlemeyi
dosyada sabitlenene yakın tutmak için veriliyor; `pip-audit 2.10.1` ile
bayraksız çalışma da ölçüldü ve aynı sonucu veriyor. Araç kurulu değilse
CLI çökmez, ne yapılacağını söyler ve `2` ile çıkar:

```text
codexray audit: pip-audit kurulu değil. Kurmak için: python -m pip install pip-audit
```

### Gerçek dünyada doğrulama

Motor yalnızca kendi örnekleri üzerinde değil, dışarıdaki depolarda da
denendi. `we45/Vulnerable-Flask-App` içinde gerçek bir SQL injection buldu:

```text
app/app.py:265  CRITICAL  sql-injection  CWE-89  [user-input]
    request.json -> content -> search_term -> str_query -> db.engine.execute
```

Dört sıçramalık veri akışı — `request.json`'dan `%` formatlamayla kurulan
sorguya, oradan `db.engine.execute`'a.

Taranan hedefler: 4 depo, 182 dosya, ~48 000 satır. **1 doğru pozitif,
0 yanlış pozitif.** Flask + Werkzeug + Jinja2'nin 45 137 satırlık üretim
kodunda hiç alarm üretmedi.

Kaçırılan kalıplar ve sebepleri (üçü de önceden ilan edilmiş sınırlar:
inter-procedural analiz, literal receiver eşleştirme, konteyner semantiği)
`docs/design-decisions.md` → "Gerçek uygulama taraması" içinde ölçümleriyle
kayıtlı.

### JSON çıktısı

`--json` yapısal çıktı verir. Bulgu nesir içermez — motor olgu üretir,
cümle kurmak sunum katmanının işidir:

```bash
codexray scan examples/vulnerable/sql_injection.py --json
```

```json
{
  "findings": [
    {
      "file": "examples/vulnerable/sql_injection.py",
      "line": 4,
      "rule_id": "sql-injection",
      "cwe": "CWE-89",
      "severity": "CRITICAL",
      "kind": "user-input",
      "taint_path": ["request.args", "username", "query", "cursor.execute"]
    }
  ],
  "summary": {"files_scanned": 1, "findings": 1, "skipped_files": 0}
}
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
