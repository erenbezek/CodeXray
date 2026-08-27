# Mimari

## Uçtan uca akış

```
Hedef kod deposu
       |
       v
AST ayrıştırıcı (ast.parse)
       |
       v
Kural motoru (RuleEngine + rules/)
   taint | ast-structural | presence-check
       |
       v
LLM triage (bonus, opsiyonel)
       |
       v
Rapor ve CI çıktısı (CLI, HTML, GitHub Actions)
```

## Kural motorunun iç yapısı

`RuleEngine`, her AST düğümünü üç paralel motora göre değerlendirebilir:

- **Taint motoru** — source → sanitizer → sink veri akışı takibi
  (şu an implemente edilen: `src/codexray/taint_engine.py`)
- **AST yapısal kontrol** — tek düğüm/desen eşleştirme (Empty Catch
  Block, Insecure Randomness, Hardcoded Password için planlanan —
  henüz implemente edilmedi)
- **Yokluk kontrolü** — bir korumanın eksikliğini arama (CSRF için
  planlanan — henüz implemente edilmedi)

Üç motor de kayıt tablosu (registry) deseniyle bağlanacak şekilde
tasarlandı; dördüncü bir tip (örn. `dependency-check`) gerektiğinde
mevcut motorlara dokunmadan eklenebilir.

## Taint motoru — veri modeli

```
TaintState (immutable):
  tainted: bool
  source: str | None
  kind: str | None
  path: tuple[str, ...]          # source'tan itibaren tüm propagation izi
  sanitized_for: tuple[str, ...] # örn. ("sql",) — hangi bağlamlar için güvenli
```

`path` ayrı tutuluyor ki bulgu raporunda tam iz gösterilebilsin
(`request.args → username → query → cursor.execute`). `sanitized_for`
bir SQL sanitizer'ının HTML sink'i için otomatik güvenli sayılmamasını
sağlıyor.

## Kural şeması

```
Rule
├── sources: SourcePattern[]     — hangi ifadeler "kirli" kabul edilir
├── sanitizers: SanitizerPattern[] — hangi çağrılar kirliliği temizler
└── sinks: SinkPattern[]         — hangi çağrılara kirli veri ulaşırsa alarm

CallTarget(qualified_name, module)  — eşleştirme birimi
```

E�leştirme **qualified-name tabanlı** (`resolve_qualified_name()` AST'de
`Attribute`/`Name`/`Call`/`Subscript` zincirini `"cursor.execute"` gibi
bir string'e çevirir), regex tabanlı değil. Gerekçe: `docs/design-decisions.md`.

## Traversal sözleşmesi

```
Expression  -> analyze_expression(node) -> TaintState
Statement   -> visit_Assign / visit_Expr -> env günceller / Finding üretir
```

`env: dict[str, TaintState]` her değişkenin o anki taint durumunu
tutar. Traversal, hangi düğümün source/sanitizer/sink olduğuna asla
kendisi karar vermez — her seferinde `RuleEngine.classify(node)`'a
sorar.

## Desteklenen AST senaryoları (SQL Injection üzerinden doğrulandı)

| Senaryo | AST düğümü |
|---|---|
| `a = source` | `Assign` |
| `b = a` | `Assign` (value: `Name`) |
| `c = a + b` / f-string | `BinOp` / `JoinedStr` |
| `foo(a)` (sink olmayan çağrı) | `Call` — env değişmez (bilinçli bilgi kaybı) |
| `safe = sanitize(a)` | `Call` (sanitizer eşleşmesi) |
| `sink(a)` | `Call` (sink eşleşmesi) → `Finding` |
