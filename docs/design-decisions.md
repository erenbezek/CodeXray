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


## Generic Call-Return Propagation

CodeXray'in mevcut taint engine'inde en önemli generic false-negative kaynağının, modellenmemiş fonksiyon çağrılarının dönüş değerinin `CLEAN` kabul edilmesi olduğu M5-03 validation sonrasında tespit edildi.

Örneğin:

    user_input = request.args["q"]
    result = str(user_input)
    Response(result)

mevcut engine'de `user_input` tainted olmasına rağmen `str(user_input)` çağrısından sonra taint kaybolmaktadır.

### Karar

Generic taint engine'e explicit intraprocedural call-return propagation abstraction eklenecek.

Bu abstraction, yalnızca açıkça modellenmiş fonksiyonların seçilmiş input argümanlarından return değerine taint aktarılmasına izin verecek.

Önerilen model:

    CallModel
    ├── target
    ├── input_selectors
    ├── output = return
    ├── preserves_taint
    └── preserves_sanitization

Örneğin:

    str(user_input)
        → tainted return

    json.dumps(user_input)
        → tainted return

    len(user_input)
        → clean return

Bilinmeyen fonksiyon çağrıları otomatik olarak tainted kabul edilmeyecek.

### Rule ve CallModel ayrımı

`Rule` güvenlik anlamını tanımlar:

    Rule
      → source
      → sanitizer
      → sink

`CallModel` ise fonksiyon veya kütüphane çağrısının veri akışı semantiğini tanımlar:

    CallModel
      → hangi argümanlardan
      → hangi çıktıya
      → hangi taint davranışıyla

CallModel vulnerability-specific olmayacak. SQL Injection veya XSS rule'larının içine generic propagation mantığı eklenmeyecek.

### TaintState

Mevcut `TaintState` modeli korunacak.

Aşağıdaki alanların değiştirilmesi zorunlu görülmedi:

- `tainted`
- `source`
- `kind`
- `path`
- `sanitized_for`

Call-return propagation sırasında mevcut provenance korunacak ve çağrı path'e dahil edilecek.

`sanitized_for` bilgisi yalnızca CallModel açıkça sanitization bilgisinin korunacağını belirtiyorsa taşınacak.

Örneğin:

    safe = html.escape(user_input)
    result = unknown_helper(safe)
    Response(result)

ifadesinde `unknown_helper` için açık bir model bulunmadığından `result` otomatik olarak HTML-safe kabul edilmeyecek.

### Neden bu karar alındı?

Bu yaklaşım:

- mevcut intra-procedural kapsamı korur,
- kullanıcı tanımlı fonksiyonlar için henüz inter-procedural analiz gerektirmez,
- mevcut SQL Injection ve XSS rule'larını değiştirmeden generic engine'i güçlendirir,
- gelecekte keyword argument, sanitizer argument ve function summary abstraction'ları için temel oluşturur,
- bilinmeyen fonksiyonları otomatik olarak tainted kabul ederek false positive üretme riskini azaltır.

### Kapsam

Bu karar yalnızca explicit intraprocedural call-return propagation içindir.

Aşağıdakiler bu değişikliğin kapsamına dahil değildir:

- Kullanıcı tanımlı fonksiyonlar arası taint propagation
- Call graph
- Recursive function analysis
- Control-flow analysis
- Full type inference
- Import alias resolution
- Stored XSS
- Jinja/template analysis
- DOM XSS
- UNKNOWN state

Bu konular ileride ayrı tasarım kararlarıyla ele alınabilir.

### Beklenen test davranışı

En azından aşağıdaki iki davranış birlikte doğrulanmalıdır:

    result = str(user_input)
    sink(result)

→ taint korunmalı ve finding üretilebilmelidir.

    result = len(user_input)
    sink(result)

→ taint return değerine taşınmamalı ve finding üretilmemelidir.

Ayrıca:

- mevcut SQL Injection testleri korunmalı,
- mevcut XSS testleri korunmalı,
- mevcut sanitizer davranışı korunmalı,
- mevcut positional sink davranışı korunmalı,
- CallModel bulunmayan çağrılarda mevcut davranış korunmalıdır.

### Mimari sınır

Bu değişiklik, CodeXray'i henüz inter-procedural bir analiz aracına dönüştürmez.

Amaç, AST içindeki `Call` expression'larının dönüş değerini daha doğru modelleyerek source ile sink arasındaki veri akışında gereksiz taint kaybını azaltmaktır.

Bu karar, M5-03 validation sonucunda tespit edilen generic engine sınırlamalarına dayanır.




## Shared Call-Argument Binding

Generic Call-Return Propagation sonrasında, `ast.Call` argümanlarının yalnızca positional index üzerinden modellenmesinin önemli bir generic sınırlama olduğu tespit edildi.

Mevcut durumda:

- `CallModel` yalnızca positional selector kullanıyor.
- Sink'ler yalnızca positional `dangerous_arguments` kullanıyor.
- Sanitizer analizi yalnızca ilk positional argümanı inceliyor.
- `ast.Call.keywords` generic olarak analiz edilmiyor.

Bu durum gerçek Python kullanım biçimlerinde false negative üretebiliyor:

    json.dumps(obj=user_input)
    Response(response=user_input)
    html.escape(s=user_input)

### Karar

`ast.Call` içindeki positional ve keyword argümanları ortak şekilde çözümleyebilen bir argument-binding abstraction geliştirilecek.

Önerilen yapı:

    ast.Call
      ├── positional arguments
      └── keyword arguments
              ↓
      CallArgumentBinder
              ↓
      ArgumentSelector
         ├── positional(index)
         └── keyword(name)
              ↓
      CallModel / Sink / Sanitizer

### CallModel

Mevcut `CallModel` kaldırılmayacak.

Mevcut positional selector davranışı geriye dönük korunacak:

    input_selectors=(0,)

Buna keyword selector desteği eklenecek.

Örneğin:

    json.dumps(obj=user_input)

ifadesinde `obj` keyword argümanı seçilebilir hale gelecek.

### Sink

Mevcut:

    dangerous_arguments=(0,)

davranışı korunacak.

Sink argument seçiminin ileride aynı shared argument-binding abstraction'ını kullanabilmesi sağlanacak.

Böylece:

    Response(response=user_input)

gibi keyword sink kullanımları generic mekanizma üzerinden analiz edilebilecek.

### Sanitizer

Sanitizer argument seçimi de aynı abstraction üzerinden modellenebilecek.

Örneğin:

    html.escape(s=user_input)

ifadesinde `s` keyword argümanı açıkça seçilebilecek.

Sanitization davranışı değişmeyecek:

- Sanitizer yalnızca açıkça seçilen input üzerinde çalışır.
- `sanitized_for` yalnızca tanımlanan sanitizer semantiğine göre korunur.
- Bilinmeyen çağrılar otomatik olarak sanitizer kabul edilmez.

### `**kwargs`

`**kwargs` için agresif varsayımlar yapılmayacak.

Bir selector'ın belirli bir keyword'e bağlanması mümkün değilse, engine bilinmeyen bir argümanı otomatik olarak seçilmiş kabul etmeyecek.

### Bilinmeyen Çağrılar

Bu karar bilinmeyen function call'ları otomatik olarak tainted hale getirmez.

Unknown-call politikası değişmeyecek.

### Mimari Sınır

Bu abstraction yalnızca çağrı argümanlarının çözümlemesini genelleştirir.

Aşağıdakiler bu kararın kapsamına dahil değildir:

- User-defined function summaries
- Inter-procedural analysis
- Call graph
- Control-flow analysis
- Type inference
- Import alias resolution
- Receiver/side-effect output modeling
- Automatic unknown-call propagation
- Varargs için agresif taint varsayımları

### Uyumluluk

Aşağıdaki mevcut davranışlar korunmalıdır:

- SQL Injection source/sink analizi
- XSS source/sink analizi
- Mevcut positional CallModel'ler
- `str()` taint propagation
- `json.dumps()` taint propagation
- `len()` non-propagation
- Sanitization preservation/reset davranışı
- Unknown-call davranışı

### Test Gereksinimleri

En az aşağıdaki durumlar doğrulanmalıdır:

    json.dumps(obj=user_input)

→ modeled keyword argument üzerinden taint return'e ulaşmalıdır.

    Response(response=user_input)

→ keyword sink argument üzerinden finding üretmelidir.

    html.escape(s=user_input)

→ keyword sanitizer argument üzerinden sanitization uygulamalıdır.

Ayrıca:

- positional selector backward compatibility
- positional + keyword selector kombinasyonu
- eksik keyword selector
- birden fazla seçilmiş argümanın merge edilmesi
- `**kwargs` davranışı
- unknown-call davranışı

test edilmelidir.

### Neden bu karar alındı?

Amaç belirli bir vulnerability rule'ına yeni özel durumlar eklemek değildir.

Amaç:

> `ast.Call` argümanlarının generic ve yeniden kullanılabilir biçimde modellenmesini sağlamak.

Aynı argument-binding mekanizmasının `CallModel`, sink ve sanitizer katmanlarında kullanılabilmesi, CodeXray'in farklı güvenlik kurallarında aynı veri-akışı mantığını yeniden kullanmasını sağlar.

Bu nedenle keyword argument desteği ayrı ayrı vulnerability rule'larına eklenmeyecek; ortak generic abstraction üzerinden uygulanacaktır.