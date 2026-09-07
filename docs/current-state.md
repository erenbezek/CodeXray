# CodeXray — Current State

## Current Milestone

**Motor sağlamlaştırma tamamlandı.** Kategori #3'e (Path Manipulation) geçmeden
önce taint motorundaki genel bilgi kayıpları kapatıldı. Sırayla:

| Adım | Ne yapıldı | Durum |
|---|---|---|
| M5.1 | Generic call-return propagation (`CallModel`) | tamamlandı |
| M5.5 | Shared call-argument binding + parameter modeli | tamamlandı |
| M5.6 | Traversal statement kapsamı + argüman "tam bir kez" sözleşmesi | tamamlandı |
| M5.7 | `BoolOp` / `IfExp` propagation | tamamlandı |
| M5.8 | Receiver analizi + receiver propagation, genişletilmiş request source'ları | tamamlandı |

**Sıradaki iş sırası** (karara bağlandı):

| Adım | Ne | Durum |
|---|---|---|
| M5.9 | Statement header slotları (`if`/`while` test, `for` iter, `with` context) | sırada |
| M5.10 | Variadic argument model (`os.path.join`, `tpl.format` — keyfi arity) | M5.9'dan sonra |
| M6 | Path Manipulation | M5.10'dan sonra |
| — | Literal receiver / shape-based matching | ertelendi |

Sırayı belirleyen ölçümler:

| Kalıp | Bugün |
|---|---|
| `with open(kirli) as f:` | 0 bulgu |
| `for row in cursor.execute(q):` | 0 bulgu |
| `if` / `while cursor.execute(q):` | 0 bulgu |
| `os.path.join("/base", kirli)` | 0 bulgu |
| `os.path.join(kirli, 'a', 'b')` | 0 bulgu |
| `tpl.format('s', kirli)` | 0 bulgu |
| `sep.join([kirli])` | 0 bulgu — konteyner semantiği, M5.10 kapsamı dışı |
| `"SELECT {}".format(kirli)` | 0 bulgu — literal receiver, M5.10 kapsamı dışı |
| `return Response(kirli)` | 1 bulgu |
| `return kirli` (çıplak) | 0 bulgu — return sink abstraction hâlâ yok |
| if / for / try **gövdesi** içindeki sink | 1 bulgu |

Gerekçeler için `docs/roadmap.md` → "M5.9 / M5.10 neden M6'dan önce".

M5.10'un `rest()` selector'ı karara bağlandı: `*args` ve `**mapping` görünen
birer ifadedir ve katkılarına mevcut handler'lar karar verir; adlandırılmış
keyword argümanlar kapsam içindedir (parameter modeliyle tutarlılık). Gerekçe
ve ölçümler için `docs/design-decisions.md` → "M5.10 karar".

## Working

- Python AST parsing
- `TaintState`
- `TaintAnalyzer`
- `RuleEngine`
- `RuleMatch`
- Intra-procedural taint propagation
- Variable assignment propagation
- Multi-hop propagation
- `BinOp` propagation
- Python f-string (`JoinedStr`) propagation
- Source detection
- Sanitizer handling
- Sink detection
- Taint path generation
- CWE / severity metadata
- SQL Injection rule
- Reflected/server-side XSS rule (Python + Flask)
- Generic `CallModel` / `CallModelRegistry` (explicit call-return propagation)
- Shared call-argument binding (parametre başına tek selector, pozisyonel + keyword)
- Statement kapsamı: `return`, `AugAssign`, `AnnAssign`, `raise`, `assert`
- Comprehension ve konteyner literali alt ifadelerinin sink için analizi
- `BoolOp` (`a or b`) ve `IfExp` (ternary) propagation
- Receiver analizi (`Response(v).upper()` içindeki sink görünür)
- Receiver propagation (`v.upper()`, `request.args.get('q')`, metot zincirleri)
- Her çağrı argümanı ve receiver'ı **tam olarak bir kez** analiz edilir
- Vulnerable / safe examples
- Automated tests
- GitHub Actions CI (`.github/workflows/ci.yml`)

## Test Status

153 passed

## Current SQL Injection Flow

request.args["username"]
        ↓
     username
        ↓
      query
        ↓
cursor.execute(query)

If tainted data reaches the SQL sink without the required SQL sanitization:

Finding → CWE-89

## Current Architecture

Python Source Code
        ↓
       AST
        ↓
 TaintAnalyzer
        ↓
    TaintState
        ↓
    RuleEngine
        ↓
Source / Sanitizer / Sink
        ↓
     Finding

## Important Components

### `src/codexray/rule_model.py`

Contains:

- `Rule`
- `SourcePattern`
- `SanitizerPattern`
- `SinkPattern`
- `RuleMatch`
- `RuleEngine`
- Qualified-name resolution and matching

### `src/codexray/call_arguments.py`

Contains:

- `ArgumentSelector`
- `parameter()` / `positional()` / `keyword()` selector constructors
- `CallArgumentBinder`

Resolves an `ast.Call`'s arguments through one shared abstraction, used by the
`CallModel`, sink, and sanitizer layers alike. One selector names one
*parameter*, which may be addressable positionally, by keyword, or both.

### `src/codexray/call_model.py`

Contains:

- `CallModel`
- `CallModelRegistry`
- The default set of explicitly modelled library calls

### `src/codexray/taint_engine.py`

Contains:

- `TaintState`
- `Finding`
- `TaintAnalyzer`
- Taint propagation
- Sanitizer handling
- Sink checking
- Taint path generation

### `rules/`

Contains vulnerability-specific rules.

Currently implemented:

- SQL Injection
- XSS (reflected/server-side)

### `tests/`

| Dosya | Kapsam |
|---|---|
| `test_rule_model.py` | `RuleEngine` sınıflandırma, qualified-name eşleştirme |
| `test_taint_engine.py` | Propagation, sanitizer, sink, `BinOp`, `JoinedStr` |
| `test_sql_injection.py` | SQL Injection uçtan uca |
| `test_xss.py` | XSS uçtan uca, örnek dosyalar |
| `test_call_model.py` | `CallModel`, receiver propagation, modellenmiş metotlar |
| `test_call_arguments.py` | Selector/binder, keyword argümanlar, çift raporlama |
| `test_statement_traversal.py` | Statement kapsamı, konteynerler, `BoolOp`/`IfExp` |

### `examples/`

Contains vulnerable and safe example Python code.

## Not Implemented Yet

- CLI scanner
- Path Manipulation
- Sensitive Data Exposure
- AST structural rules
- Presence-check rules
- Dependency scanning
- Inter-procedural analysis
- Control-flow analysis
- Type inference
- Multi-source provenance
- `UNKNOWN` taint state
- LLM triage

## Important Architectural Rules

- Keep security-rule-specific logic out of the taint traversal.
- Prefer adding a new `Rule` over modifying the core engine.
- Keep `TaintState` immutable.
- MVP remains intra-procedural.
- Do not introduce regex-based vulnerability detection as the primary matching mechanism.
- Do not expand project scope without an explicit architectural decision.
- Existing behavior must remain covered by tests.

## Current Limitations

### Qualified-name matching

The MVP does not perform full type inference.

Different objects with similarly named methods may therefore be matched by the same qualified-name heuristic.

### Single-source provenance

When multiple tainted values are merged, provenance is currently simplified to one primary source.

### Unsupported AST expressions

Handler'ı olmayan bir ifade `CLEAN` kabul edilir — "bilmiyorum" değil "temiz".
Bilinçli olarak açık bırakılan slotlar:

```text
UnaryOp (-x, not x)      Subscript slice (d[kirli:])
Lambda gövdesi           NamedExpr / walrus (x := kirli)
Await (await kirli)      str.format()             str.join()
```

`Await` ölçüldü: `x = await Response(kirli)` -> 0 bulgu. Semantiği tartışmasız
(bir coroutine'i beklemek sonucunu verir), bu yüzden M5.9 ile birlikte
kapatılacak — bir header slotu değil ama async kapsamı aynı pakette açılıyor.

Ayrıca:

- **Literal receiver eşleşmez.** `'sabit'.replace('x', kirli)` hiçbir modele
  ulaşmaz çünkü literal'in nitelikli adı yoktur. Değişkene atanınca çalışır.
- **Konteyner-vs-eleman tutarsızlığı.** `v.split(',')` tainted bir liste
  döndürür ama `[v]` literali `CLEAN` kalır. İki farklı yön; konteyner
  semantiği tasarlanana kadar görünür bir tutarsızlık.
- **`*args` sink tarafında false negative.** `Response(*args)` bulgu üretmez.
  Propagation için muhafazakâr, sink için müsamahakâr olan bilinçli bir seçim.

### Statement header slotları (ayrı kök neden)

`if` / `while` test'i, `for` iter'i ve `with` context'i yukarıdaki listede
değil, çünkü eksik olan bir *expression handler* değil bir *statement
visitor*. `generic_visit()` bu düğümlerin çocuklarını geziyor ama başlık
ifadesini hiç `analyze_expression()`'a vermiyor; sonuç taint kaybı değil,
doğrudan **bulgu kaybı** — başlıkta duran sink hiç görülmüyor:

```text
with open(kirli) as f:          -> 0 bulgu
for row in cursor.execute(q):   -> 0 bulgu
```

Gövdeler etkilenmiyor (`if True: cursor.execute(q)` -> 1 bulgu). Görünür
asimetri: ternary'nin (`IfExp`) test'i M5.7'de analiz ediliyor, `if`
statement'ının test'i edilmiyor. M5.9 bunu kapatacak.

### No control-flow analysis

Branches and multiple execution paths are not fully modeled.

### No inter-procedural propagation

Taint is currently tracked within a function and is not propagated across function boundaries.

## M5 Milestone Completion

**XSS (reflected/server-side)**

### Goal

Add the first additional taint-based vulnerability rule without introducing SQL-specific logic into the core taint engine.

### Definition of Done

- XSS rule exists
- Source / sanitizer / sink definitions remain separate from traversal logic
- Existing SQL Injection tests remain green
- XSS tests are added
- `pytest` passes
- No unnecessary core-engine changes are introduced

## Current Project Status

CodeXray currently has a working intra-procedural taint-analysis core with functioning SQL Injection and reflected/server-side XSS rules.

It is not yet a complete SAST tool.

The current focus is to validate that the taint engine can support additional vulnerability rules without requiring rule-specific changes to the core engine.
