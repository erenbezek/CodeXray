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
- ~~**Keyword argument sink/sanitizer desteği sınırlı**~~ — Shared Call-Argument Binding ile kapatıldı (bkz. aşağıdaki karar ve uygulama notu).
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

### Uygulama notu

Karar uygulandı. Uygulama sırasında netleştirilen noktalar:

**Abstraction'ın yeri.** `ArgumentSelector` ve `CallArgumentBinder` yeni bir modüle (`src/codexray/call_arguments.py`) konuldu; `rule_model.py` içine değil. İki gerekçe:

1. Argument binding güvenlik anlamı taşımaz — `rule_model.py`'nin sorumluluğu source/sanitizer/sink semantiğidir.
2. `call_model.py` zaten `rule_model.py`'yi import ediyor; ortak abstraction'ı üçüncü ve bağımsız bir modüle koymak dairesel import riskini tamamen ortadan kaldırıyor.

**Geriye dönük uyumluluk.** `int` kısayolu korundu: `as_selector(0) == positional(0)`. Mevcut `dangerous_arguments=(0,)` ve `input_selectors=(0,)` tanımlarının hiçbiri değiştirilmek zorunda kalmadı.

**`SanitizerPattern.input_selectors`.** Sanitizer'ın hangi argümanı temizlediğini şimdiye kadar hiçbir yerde tanımlamıyorduk; traversal sabit olarak ilk pozisyonel argümanı okuyordu. Bu bilgi artık pattern'in kendi alanı, varsayılanı `(0,)` — yani önceki davranış.

**`*args` politikası.** Karar metni yalnızca `**kwargs` için "agresif varsayım yapma" diyordu; aynı ilke varargs için de simetrik olarak uygulandı. Bir `*args` unpacking'i kendisinden sonraki tüm pozisyonları bilinmeyen bir miktarda kaydırdığı için, `*args`'ın bulunduğu veya sonrasındaki pozisyonel selector'lar hiçbir şeye bağlanmaz. Öncesindeki pozisyonlar hâlâ çözülebilir.

Bu politikanın **sink tarafında bir false negative olduğu açıkça kayda geçmelidir.** İki katmanın risk profili zıttır:

- *Propagation* için bağlamamak muhafazakârdır — bilinmeyen veriyi tainted saymayız, false positive üretmeyiz.
- *Sink* için bağlamamak **müsamahakârdır** — gerçek bir zafiyeti kaçırırız.

Ölçüldü:

```text
x = request.args["q"]
args = [x]
Response(*args)     -> 0 bulgu
```

Bu davranış değişiklikten önce de aynıydı (regresyon değil), ancak "muhafazakâr seçim" olarak sunulması yanlıştır. Tek bir bağlama kuralının zıt risk profilli iki katmana aynen uygulanmasının sonucudur ve bilinçli olarak kabul edilen bir bilgi kaybıdır. Sink tarafında varargs'ı ele almak ayrı bir tasarım kararı gerektirir.

**Negatif index artık bağlanmıyor.** Değişiklikten önce `_check_sinks` yalnızca üst sınırı kontrol ediyordu (`if arg_index >= len(node.args)`), dolayısıyla `dangerous_arguments=(-1,)` Python'un negatif indekslemesiyle "son argüman" olarak **çalışıyordu**. `_apply_call_model` ise zaten `0 <= index` ile korumalıydı — yani iki katman tutarsızdı. Yeni binder her iki katmanda da negatif index'i bağlamıyor.

Repoda kullanan bir tanım yoktu ve tutarsızlığın giderilmesi doğrudur, ancak bu kod tarafından belgelenmiş bir davranışın değişmesidir. "Son argüman" semantiği ileride gerekirse açık bir selector olarak modellenmelidir, negatif index'in yan etkisi olarak değil.

**Bağlanamayan sanitizer.** Bir sanitizer eşleşip hiçbir selector'ı bağlanamıyorsa (`sanitize(other=x)`), çağrı sanitize edilmiş sayılmaz; `_apply_sanitizers` `None` döner ve akış normal call-model yoluna düşer. Göremediğimiz bir input'u temizlediğimizi iddia etmemek, bilinmeyen çağrı politikasıyla tutarlı olan taraftır. Sonuç: false negative, false positive değil.

**Sink argümanları merge edilmez.** Her seçili tehlikeli argüman ayrı ayrı değerlendirilir; `sink(user_input, body=user_input)` iki ayrı bulgu üretir. İki farklı argümandan gelen iki veri akışı iki ayrı bulgudur — bu önceki davranışın korunmasıdır.

**`sanitized_for` artık sıralı.** Sanitizer yolundaki `tuple(set(...))` deterministik olmayan bir sıra üretiyordu. `merge_states()` ile tutarlı olacak şekilde `sorted()` eklendi. Tek kategorili mevcut testler etkilenmedi.

**Selector kazanan tanımlar.** Gerçek imzalara göre `json.dumps` → `obj`, `html.escape` → `s` (markupsafe.escape / Markup.escape dahil), `Response` → `response` eklendi. Bu tanımların güncel biçimi için aşağıdaki "Parameter Modeli" kararına bakınız.

`cursor.execute` CPython'da positional-only olduğu için SQL Injection kuralı değiştirilmedi — bu aynı zamanda geriye dönük uyumluluğun repo içindeki kanıtı.

**Bilinen sınır.** `dangerous_arguments` tek bir `SinkPattern`'deki tüm target'lar için ortaktır. XSS sink pattern'i `Response` / `make_response` / `Markup` hedeflerini paylaştığı için `keyword("response")` üçü için de denenir. Pratikte zararsız (`make_response`'ın `response` adlı bir parametresi yok, dolayısıyla böyle bir çağrı zaten yazılmaz), ancak hedefe özgü selector gerekirse doğru çözüm pattern'i bölmektir.

Güncel test sayısı için `docs/current-state.md`.

## Parameter Modeli (Argument Selector v2)

Shared Call-Argument Binding uygulandıktan sonra `ArgumentSelector`'ın yanlış kavramı modellediği tespit edildi.

Selector "bir argüman"ı adlandırıyordu. Kuralların ihtiyacı olan ise "bir **parametre**" — pozisyonel indeksle, isimle veya her ikisiyle adreslenebilen tek bir şey. Sonuç: aynı sözdizimi iki farklı anlama geliyordu ve okuyan ayırt edemiyordu.

    input_selectors=(0, keyword("s"))       # html.escape -> TEK parametre, iki yazım
    input_selectors=(0, keyword("extra"))   # combine     -> İKİ ayrı parametre

Ölçüldü: `html.escape(y, s=x)` çağrısında iki selector de bağlanıp merge ediliyordu. Geçerli Python'da bir parametre tek yolla geçildiği için gerçek kodda davranış doğruydu; sorun doğruluk değil, modelin alanı yanlış bölmesiydi.

### Neden şimdi

Maliyet kural sayısıyla artıyor — her yeni kural bu belirsiz sözdizimini kopyalar. Üçüncü kural (Path Manipulation) yazılmadan düzeltmek bir dosyaya, sonra düzeltmek üçüne dokunmak demektir.

### Karar

`ArgumentSelector` bir parametreyi temsil eder ve hem index hem name taşıyabilir:

    parameter(0, "s")   # pozisyonel 0 varsa ona, yoksa keyword "s"e bağlanır
    positional(0)       # = parameter(index=0)
    keyword("s")        # = parameter(name="s")
    0                   # = parameter(index=0)   (kısayol korunur)

Bağlama sırası: **önce pozisyonel, sonra keyword, ilk eşleşen kazanır. Asla merge edilmez.** Geçerli Python'da bir parametre tek yolla geçilir, dolayısıyla tam olarak biri bağlanır. Her iki yazım da mevcutsa (geçersiz Python) pozisyonel kazanır ve keyword yok sayılır.

Pozisyon `*args` nedeniyle çözülemiyorsa keyword yazımı denenir — `f(*rest, s=b)` çağrısında `s` hâlâ belirsizlik taşımaz.

Ne index ne name taşıyan bir selector `ValueError` yükseltir; sessizce hiçbir şeye bağlanan bir tanım kural yazım hatasıdır, çalışma zamanı davranışı değil.

`positional()` ve `keyword()` kaldırılmadı — `parameter()` bunların üstüne eklenen bir kümedir, yerine geçen değil. Shared Call-Argument Binding kararının öngördüğü kelime dağarcığı korunur.

### Kazanç

Tuple uzunluğu artık seçilen **parametre sayısına** eşittir:

    input_selectors=(parameter(0, "s"),)                     # TEK
    input_selectors=(parameter(0), parameter(name="extra"))  # İKİ

Ölçülen davranış değişikliği: `Response(v, response=v)` artık iki değil **bir** bulgu üretir — tek parametre, tek veri akışı.

### Geri alınan karar

`str` → `keyword("object")` kaldırıldı. Shared Call-Argument Binding kararı yalnızca `json.dumps(obj=…)` istiyordu; `str(object=x)` gerçek kodda yok denecek kadar nadir ve bu ekleme onaylanmamış bir genişletmeydi. `str` tekrar yalnızca pozisyonel.

### Kapsam dışı

- `*args` / `**kwargs` politikası değişmez
- Bilinmeyen çağrı politikası değişmez
- Type inference, import alias resolution, inter-procedural analiz
- Sink tarafında varargs ele alınması (ayrı karar)

## M5.6 — Traversal statement kapsamı

### Kök neden

Traversal sözleşmesi yalnızca `visit_Assign` ve `visit_Expr` içinden
`analyze_expression()` çağırıyordu. `Return`, `Raise`, `Assert`, annotated
assignment ve augmented assignment gibi statement'lar expression slotlarındaki
sink'leri ya da taint durumunu sessizce kaybediyordu.

### Karar

`Return`, `Raise` (exception ve cause), `Assert` (test ve message), `AugAssign`
ve değerli `AnnAssign` için minimal visitor'lar eklendi. `x += value`,
`x = x + value` ile aynı olmak üzere mevcut `env[x]` durumu ile value durumu
`merge_states()` kullanılarak birleştirilir. `AnnAssign` value'yu hedef türü
kontrolünden önce analiz eder; böylece `Attribute`/`Subscript` hedeflerinde
nested sink kaybolmaz. `env` yalnızca value taşıyan `Name` hedefleri için
güncellenir.

`List`, `Tuple`, `Set` ve `Dict` literal'lerinin alt ifadeleri nested sink
tespiti için analiz edilir; container sonucunun kendisi `CLEAN` kalır.
`Dict` için hem key hem value, `Starred` için `node.value` analiz edilir.
Bu, container'ın taint durumunu elemanlarından türetmeden iç içe sink'leri
görünür kılar.

Comprehension expression slotları (`elt`, dict `key`/`value`, generator `iter`
ve `ifs`) de aynı amaçla analiz edilir; comprehension sonucu `CLEAN` kalır.

Bir `Call` düğümünün tüm doğrudan argümanları (positional, keyword, `*args`
ve `**kwargs` değerleri) `_analyze_Call` başında tam olarak bir kez analiz
edilir ve AST expression düğümüyle anahtarlanan bir cache'te tutulur.
Sink, sanitizer ve CallModel yolları bu hazır state'leri kullanır; nested
sink'ler outer çağrının rule/call-model eşleşmesine bağlı değildir.
Bilinmeyen çağrının return değeri yine `CLEAN` kalır.

### Gövdeli statement tuzağı

`If`, `While`, `For`, `With`, `Try` ve `FunctionDef` için visitor eklenmedi.
Bu düğümler `generic_visit()` ile gövdelerini zaten geziyor; eksik bir
`visit_X` uygulaması gövdeyi ziyaret etmeden mevcut sink tespitini bozabilir.

### Ertelenen semantikler

- `Attribute` / `Subscript` augmented ve annotated assignment hedefleri
- Konteyner-vs-eleman taint propagation (`List`, `Tuple`, `Set`, `Dict` ve
  `Starred` için de geçerli)
- For/with target binding
- Return sink abstraction

## M5.7 — BoolOp ve IfExp expression propagation

### Kök neden

Handler'ı olmayan expression düğümleri `analyze_expression()` fallback'inde
sessizce `CLEAN` dönüyordu. Bu, Flask uygulamalarında yaygın olan
`request.args.get("q") or "default"` benzeri boolean fallback kalıplarında
ve conditional expression'larda, source modeli tarafından tainted olarak
bilinen operandın taint'inin kaybolmasına yol açıyordu. `request.args.get()`
method source modellemesi bu karardan ayrı, rule-level bir konudur.

### Karar

`BoolOp` için tüm operand state'leri `merge_states()` ile birleştirilir.
Boolean expression çalışma zamanında operandlardan birini döndürdüğü için,
herhangi bir tainted operand sonucu tainted yapar. `sanitized_for` için mevcut
kesişim davranışı korunur: bir operand sanitize, diğeri değilse sonuç o
bağlamda sanitize sayılmaz.

`IfExp` için yalnızca `body` ve `orelse` state'leri birleştirilir. `test`
ayrıca analiz edilir; böylece koşul içindeki nested sink görünür olur. Ancak
test'in state'i sonuç state'ine katılmaz. Koşuldan sonuç değerine taint taşımak
implicit flow modellemek olur ve control-flow analysis gerektirir; bu MVP'nin
kapsamı dışındadır.

### Bilinen boşluklar

Aşağıdaki expression/statement slotları bilinçli olarak ertelenmiştir:

- `UnaryOp`
- `Subscript` slice
- `Lambda` gövdesi
- `NamedExpr` (walrus)
- `if` / `while` test'i
- `for` iter'i
- `with` context'i

## M5.8 - Receiver propagation and call evaluation

### Exactly-once receiver contract

For every `Call`, the receiver (`node.func.value` when `node.func` is an
`ast.Attribute`) is analyzed exactly once, before positional and keyword
arguments, matching Python evaluation order. Sink, sanitizer, and CallModel
paths consume the cached receiver state and never analyze it again. This keeps
nested findings deterministic and prevents duplicate reports.

### Receiver as a separate CallModel input

`CallModel.receiver_is_input` is separate from `input_selectors`: selectors
address call parameters, while the receiver is the object on which the method
is invoked and is not an argument. A receiver-only model therefore uses
`input_selectors=()` and `receiver_is_input=True`. If such a model is matched
against a bare function name through suffix matching, it is not applied because
there is no receiver.

### Modeled methods

Value-preserving string/request methods (for example `upper`, `strip`,
`getlist`, `get`, and `replace`) merge the receiver and explicitly selected
argument states, preserve taint, and reset sanitization unless a future model
opts in to preserve it. Predicate/count methods (`startswith`, `isdigit`,
`count`, and similar) remain non-propagating and return `CLEAN`. `format` and
`join` remain out of scope because they require receiver plus variable-arity
argument semantics.

Qualified-name suffix matching is safe for these models with respect to taint:
a clean receiver cannot become tainted merely because its method name matches;
only a tainted receiver or selected tainted argument supplies taint.

### Known inconsistency

`v.split(',')` can return a tainted list through a receiver model, while the
literal `[v]` remains `CLEAN`. These represent opposite propagation directions
(deriving a container from a value versus deriving a container from elements),
but the difference is intentional and visible until container semantics are
designed. Container-vs-element propagation for list/tuple/set/dict literals
remains deferred.

### Known gaps

`format` and `join` are deferred along with the previously documented
`UnaryOp`, subscript slices, lambda bodies, walrus expressions, conditional and
loop tests, and with-context expressions.
