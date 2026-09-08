# Mimari

## Uçtan uca akış

```
CLI scanner (`codexray scan <path>`)
       |
       v
Hedef kod deposu
       |
       v
AST ayrıştırıcı (ast.parse)
       |
       v
Kural motoru (RuleEngine + codexray/rules/)
   taint | ast-structural | presence-check
       |
       v
LLM triage (bonus, opsiyonel)
       |
       v
Rapor ve CI çıktısı (insan metni / JSON, GitHub Actions)
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

`Finding` ayrıca `filename` taşır; böylece CLI bulgusu kendi başına dosya ve
satır konumunu bildirir. JSON raporunda dosya `file`, satır `line`, taint izi
ise `taint_path` anahtarlarıyla açıkça ayrılır. Bu şema M11 triage katmanının
girdisi olarak korunacaktır.

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

## Çağrı argümanlarının çözümlenmesi

`CallModel`, sink ve sanitizer katmanlarının üçü de aynı soruyu sorar:
"bu çağrı, benim ilgilendiğim argüman olarak hangi ifadeyi geçiriyor?"
Cevap tek bir ortak abstraction'da toplanmıştır:

```
ast.Call
  ├── positional arguments
  └── keyword arguments
          |
          v
  CallArgumentBinder          (src/codexray/call_arguments.py)
          |
          v
  ArgumentSelector            — bir selector = bir PARAMETRE
     ├── parameter(index, name)   — her iki yazım
     ├── positional(index)        — düz int de kabul edilir
     ├── keyword(name)
     └── rest(from_index)         — kalan TÜM parametreler (yalnızca CallModel)
          |
          v
  CallModel / SinkPattern / SanitizerPattern
```

Bağlama sırası: önce pozisyonel, sonra keyword, **ilk eşleşen kazanır,
asla merge edilmez** — gerçek bir çağrıda bir parametre tek yolla geçilir.
Böylece tuple uzunluğu seçilen parametre sayısına eşittir.

Binder muhafazakârdır: çözülemeyen bir selector tahmin üretmez, hiçbir
şeye bağlanmaz. `**kwargs` içeriği ve `*args` sonrası pozisyonlar
bilinmezdir — ve bilinmeyen, tainted değildir.

`rest(from_index)` tek bir parametre değil, kalan **tüm** parametreleri
adlandırır: `from_index`'ten itibaren görünür pozisyonel ifadelerin tamamı
(`Starred` düğümünün kendisi dahil) artı tüm keyword değerleri (`**mapping`
dahil). Bunların katkısına ilgili expression handler karar verir — bugün
`_analyze_Starred` ve `_analyze_Dict` `CLEAN` döndüğü için `f(*parts)` ve
`f(**{...})` taint taşımaz. Bir `Starred` `from_index`'ten önce duruyorsa
indeks hassasiyeti gerçekten kaybolur ve hiçbir pozisyonel bağlanmaz.

`rest()` çoklu bağlama yaptığı için yalnızca `bind_all()` ile kullanılır;
`bind()`'a verilirse `TypeError` yükselir. Sink ve sanitizer katmanları tek
parametre sözleşmesini korur.

Gerekçe: `docs/design-decisions.md` → "Shared Call-Argument Binding",
"Parameter Modeli" ve "M5.10 karar".

## Traversal sözleşmesi

```
Expression  -> analyze_expression(node) -> TaintState
Statement   -> ilgili expression slotları visitor tarafından analiz edilir;
               env güncellenir / Finding üretilir
```

`env: dict[str, TaintState]` her değişkenin o anki taint durumunu
tutar. Traversal, hangi düğümün source/sanitizer/sink olduğuna asla
kendisi karar vermez — her seferinde `RuleEngine.classify(node)`'a
sorar.

Kapsanan govdesiz statement'lar: `Assign`, `Expr`, `Return`, `AugAssign`,
`AnnAssign`, `Raise` ve `Assert`. `AugAssign` ve değerli `AnnAssign` yalnızca
`Name` hedefini `env`'de günceller; `AnnAssign` değer ifadesi hedef
`Attribute`/`Subscript` olsa da önce analiz edilir. Bu hedefler object/container
state modeli gerektirdiği için `env` güncellemesi kapsam dışıdır.

`List`, `Tuple`, `Set` ve `Dict` literal'lerinin alt ifadeleri sink tespiti
için analiz edilir; `Dict` için key ve value birlikte taranır. `Starred`
`node.value` üzerinden aynı sözleşmeyi izler. Container değerinin kendisi
`CLEAN` kalır. `ListComp`, `SetComp`, `DictComp` ve `GeneratorExp` de kendi
yielded expression, generator `iter` ve `if` slotlarını analiz eder.
Konteyner-vs-eleman propagation ve for/with target binding ertelenmiştir.

`If`, `While`, `For`, `AsyncFor`, `With` ve `AsyncWith` için visitor bulunur ve
yalnızca **başlık ifadesini** analiz eder: `test`, `iter`, ve `items` içindeki
her `context_expr`. Dönen state bağlanmaz — başlıkta duran sink görünür olsun
diye analiz edilir. Her visitor sonunda `self.generic_visit(node)` çağırır;
bu çağrı atlanırsa gövde hiç ziyaret edilmez ve mevcut sink tespiti bozulur.

`generic_visit()` başlık ifadesine tekrar iner ama bu iniş inerttir —
`ast.Call` gibi düğümler için `visit_X` yoktur, dolayısıyla
`analyze_expression()` ikinci kez çağrılmaz ve başlık sink'i çift raporlanmaz.

`Try` ve `FunctionDef` için visitor **yoktur**: analiz edilecek bir başlık
ifadesi taşımazlar, gövdelerini `generic_visit()` zaten gezer.

`for` target ve `with ... as` optional target **bağlanmaz** — konteynerden
elemana taint türetme semantiği ertelenmiştir.

`Await` bir expression handler'dir ve `node.value`'nun state'ini döndürür —
bir coroutine'i beklemek onun sonucunu verir. Statement header slotlarından
ayrı bir kök nedendir; async kapsamı aynı pakette (M5.9) açıldığı için birlikte
kapatılmıştır.

`return value` bir sink değildir. Her `Call` düğümünün receiver'ı
(`node.func.value`) ve positional, keyword, `*args` ve `**kwargs` değerleri
Python değerlendirme sırasıyla tam olarak bir kez analiz edilir; sink,
sanitizer ve CallModel yolları bu hazır state'leri kullanır. CallModel'de
`receiver_is_input=True` receiver state'ini return girdisi yapar; receiver
argument selector'larından ayrıdır. Bilinmeyen veya modellenmemiş çağrıların
return değeri `CLEAN` kalır.

## Desteklenen AST senaryoları (SQL Injection üzerinden doğrulandı)

| Senaryo | AST düğümü |
|---|---|
| `a = source` | `Assign` |
| `b = a` | `Assign` (value: `Name`) |
| `c = a + b` / f-string | `BinOp` / `JoinedStr` |
| `c = a or b` / `a and b` | `BoolOp` — tüm operand state'leri merge edilir |
| `c = a if test else b` | `IfExp` — `body` / `orelse` merge edilir; `test` yalnızca nested sink için analiz edilir |
| `foo(a)` (sink olmayan çağrı) | `Call` — env değişmez (bilinçli bilgi kaybı) |
| `safe = sanitize(a)` | `Call` (sanitizer eşleşmesi) |
| `sink(a)` | `Call` (sink eşleşmesi) → `Finding` |
| `r = str(a)` / `json.dumps(a)` | `Call` (CallModel eşleşmesi) → return'e taint |
| `r = a.upper()` / `a.lower().strip()` | `Call` — receiver CallModel ile return'e taint |
| `r = a.get("k", fallback)` / `"x".replace("x", y)` | `Call` — receiver ve seçili argümanlar merge edilir |
| `sink(body=a)` / `escape(s=a)` | `Call` (keyword selector) |
| `sink(**payload)` / `f(*args)` | `Call` — bağlanmaz (bilinçli bilgi kaybı) |
