# Tasarım Kararları

Kronolojik karar günlüğü — "neden böyle" sorusuna cevap vermek için.

## Proje kapsamı: mini SAST + taint tracking

Sadece terim ezberlemek değil, terimleri tespit eden bir sistem kurulması hedeflendi. Kapsam bilerek geniş değil (15 kategorinin hepsi değil) — kalite, kapsamdan önceliklendirildi.

## LLM katmanı: triage, tespit motoru değil

Kendi ML modelini sıfırdan eğitmek reddedildi — yeterli etiketli veri seti toplamak süre kısıtında gerçekçi değil ve sonucu muhtemelen taint tracking'ten daha zayıf olurdu.

Bunun yerine kural motorunun bulduğu sonuçları ikinci kez değerlendiren, yanlış pozitifleri azaltan ve insan diline çeviren bir LLM triage katmanı (bonus, tespit motoru değil) tercih edildi.

## Dil: Node.js → Python

İlk tasarım Node.js/Babel üzerineydi. Python'a geçildi çünkü:

1. En akıcı olunan dil Python; Node.js tarafında aynı akıcılık yok.
2. Python'un `ast` modülü standart kütüphanede yerleşik, harici parser gerekmiyor.
3. Gerçek dünya emsali güçlü: Bandit ve PyT.

Önceden tasarlanan `TaintState` / source-sanitizer-sink modeli dilden bağımsız olduğu için geçişte kayıp olmadı.

## MVP kapsamı: intra-procedural

Fonksiyonlar arası taint propagation (call graph, parametre/return takibi, recursive call'lar, aliasing) MVP'ye dahil edilmedi.

Bunu eklemek taint motoru geliştirmekten çok daha geniş bir program analiz framework'ü geliştirmeye dönüşebilirdi.

Bu nedenle inter-procedural analysis v0.2 / stretch goal olarak bırakıldı ve MVP'de bilinen ve dokümante edilen bir bilgi kaybı olarak kabul edildi.

## TaintState modeli: sadece bool değil, zengin state

`Set<string>` (kirli değişkenler kümesi) yerine zenginleştirilmiş bir `TaintState` modeli tercih edildi.

Model temel olarak `source`, `path`, `kind` ve `sanitized_for` bilgilerini taşıyor.

Böylece bulgu raporunda yalnızca "tehlikeli" demek yerine tam veri akışı izi gösterilebiliyor:

```text
request.args → username → query → cursor.execute
```

`TaintState` immutable (`frozen=True`) tutuluyor. Böylece `b = a` sonrasında `b` üzerinde yapılan değişiklik `a`'nın state'ini etkilemiyor.

## `sanitized ≠ clean`

Bir SQL sanitizer'ından geçen değer otomatik olarak HTML için de güvenli sayılmamalı.

Bu nedenle `sanitized_for` tek bir boolean yerine hangi güvenlik bağlamları için sanitization uygulandığını taşıyan bir alan olarak tasarlandı.

`merge_states()` içinde (`BinOp` / `JoinedStr`) `sanitized_for` için union değil **kesişim** alınıyor.

Bir ifadenin bir parçası belirli bir bağlam için güvenli, diğer parçası güvenli değilse birleşik değer yanlışlıkla güvenli sayılmamalı.

## Eşleştirme: qualified-name, regex değil

`sources` / `sanitizers` / `sinks` listelerini regex string'leri haline getirmek bilinçli olarak reddedildi.

Böyle bir yaklaşım taint motorunu giderek bir "regex eşleştirme motoru"na dönüştürür ve projenin asıl değerini, yani veri akışını gerçekten anlamasını, sulandırır.

Bunun yerine `resolve_qualified_name()` AST üzerinde `Attribute` / `Name` / `Call` / `Subscript` zincirini gezip `"cursor.execute"` gibi bir string'e çeviriyor ve kural bu string ile eşleştiriliyor.

Kabul edilen sınır: Bu tam type inference değildir. Farklı bir sınıfın aynı isimli metodu yanlışlıkla eşleşebilir.

`module` alanı bu ayrımı ileride güçlendirmek için şemada bulunmaktadır; MVP'de eşleştirmede belirleyici değildir.

## Kural / traversal ayrımı

`RuleEngine` ile traversal (`taint_engine.py`) kesin olarak ayrıldı.

Traversal kurala özgü ifadeler taşımamalı; örneğin `if function_name == "execute"` gibi SQL'e özel kontroller bulunmamalı.

Traversal yalnızca `RuleEngine.classify(node)` gibi mekanizmalar üzerinden güvenlik anlamını sorgular.

Yeni kategori eklemek mümkün olduğunca `rules/` altına yeni bir Rule eklemek anlamına gelmelidir.

`RuleMatch` (`rule + role + pattern`) kullanılır. Çıplak tuple kullanılmamasının nedeni sink ve sanitizer tarafında pattern'e ait `dangerous_arguments`, `sanitizes_for` ve benzeri alanlara doğrudan erişilebilmesidir.

## Python'a özgü not: f-string'ler ayrı ele alınmalı

Python f-string'leri (`f"...{username}..."`) AST'de `BinOp` değil, `JoinedStr` olarak temsil edilir.

Bu nedenle taint propagation için `BinOp` ve `JoinedStr` ayrı ayrı analiz edilir.

## M3 sonrası repo review'da bulunan ve düzeltilen sorunlar

### Test altyapısı

Temiz checkout'ta `pytest` collection sırasında `codexray` bulunamıyordu.

Sebep `src/` layout ile test ortamının import path'inin uyuşmamasıydı. `tests/conftest.py` içindeki manuel path yaklaşımı da yeterli değildi.

Çözüm olarak `pyproject.toml` içine:

```toml
[tool.pytest.ini_options]
pythonpath = ["src", "."]
```

eklendi ve gereksiz `conftest.py` path hack'i kaldırıldı.

Ardından:

```text
pytest
15 passed
```

durumu doğrulandı.

### Sink sanitizer eşleşmesi

Önceki yaklaşım bir Rule içindeki tüm sanitizer kategorilerini rule-wide union mantığıyla ele alıyordu.

Bu, aynı Rule içinde farklı bağlamlara ait sanitizer'lar olduğunda yanlış bir soyutlamaydı.

Çözüm olarak `SinkPattern` içine:

```text
requires_sanitization_for
```

alanı eklendi.

Böylece her sink kendi gerekli sanitization bağlamını açıkça tanımlayabiliyor.

### Test kapsamı

Önceki tek entegrasyon testine ek olarak birim seviyesinde testler eklendi.

Kapsam:

- RuleEngine classification
- Source detection
- Çok adımlı taint propagation
- `BinOp`
- `JoinedStr`
- Sanitizer davranışı
- `sanitized_for`
- Sink detection
- Tainted / clean / unknown değerler için temel davranış

Toplam mevcut test sonucu:

```text
15 passed
```

## M5 XSS kapsam kararı

M5'in ilk XSS kapsamı **reflected / server-side XSS** ile sınırlandırıldı.

Amaç, mevcut taint motorunun SQL Injection dışındaki ikinci gerçek taint kuralını çekirdek motoru değiştirmeden destekleyebildiğini göstermek.

### M5 Source kapsamı

İlk sürümde Flask request yüzeyinin temel kullanıcı kontrollü girişleri hedeflenecek:

```text
request.args
request.form
request.values
request.json
```

Daha geniş request metadata'ları ve diğer giriş yüzeyleri sonraki aşamalara bırakılabilir.

### M5 Sanitizer kapsamı

İlk sürümde HTML text bağlamı için:

```text
html.escape
markupsafe.escape
Markup.escape
```

gibi açıkça HTML escaping amacı taşıyan işlemler hedeflenecek.

Sanitization context:

```text
html-text
```

olarak modellenir.

SQL için sanitization sağlayan işlemler otomatik olarak XSS sanitizer'ı kabul edilmez.

### M5 Sink kapsamı

İlk sürüm için aday sink'ler:

```text
Response
make_response
Markup
```

olarak belirlenmiştir.

`return tainted_value` gibi generic return sink'leri mevcut engine'e bu milestone içinde özel bir XSS mantığı olarak eklenmeyecektir.

### M5 kapsam dışı

Şimdilik:

- Stored XSS
- DOM-based XSS
- Jinja template context analizi
- SSTI
- HTML context'inin ayrıntılı analizi
- Inter-procedural taint propagation
- Control-flow analysis

M5 kapsamı dışındadır.

### M5 mimari kararı

XSS kuralı mümkün olduğunca mevcut `taint_engine.py` değiştirilmeden `rules/` ve test katmanlarında uygulanmalıdır.

Eğer mevcut abstractions bunun için yetersiz görünürse, core engine'e doğrudan özel-case eklemek yerine önce yeni bir mimari karar kayda geçirilmelidir.

## Açık tasarım borcu (bilinçli olarak ertelendi)

- **Multi-source provenance yok** — `merge_states()` birden fazla tainted parçayı birleştirirken source/kind bilgisini ilk parçadan alıyor, diğer source bilgileri kaybolabiliyor.
- **`analyze_expression` fallback'i CLEAN, UNKNOWN değil** — desteklenmeyen bir AST düğümü "bilmiyorum" yerine "temiz" sayılabiliyor; bu false negative riski oluşturuyor.
- **Control flow modellenmiyor** — `if` / `try` / `except` gibi farklı dallanmalar tam data-flow modeliyle analiz edilmiyor.
- **Return sink abstraction yok** — tainted bir return değerini generic sink olarak modelleyen ayrı bir abstraction henüz bulunmuyor.
- **Keyword argument sink/sanitizer desteği sınırlı** — mevcut model ağırlıklı olarak pozisyonel argümanları kontrol ediyor.
- **Tam type inference yok** — `module` alanı şemada bulunsa da MVP eşleştirmesinde henüz gerçek tip çözümlemesi yapılmıyor.
