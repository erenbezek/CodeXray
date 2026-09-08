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

Yeni kategori eklemek mümkün olduğunca `codexray/rules/` altına yeni bir Rule eklemek anlamına gelmelidir.

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

XSS kuralı mümkün olduğunca mevcut `taint_engine.py` değiştirilmeden `codexray/rules/` ve test katmanlarında uygulanmalıdır.

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

### Literal receivers cannot be matched

Matching is qualified-name based, and a literal contributes no name:
`resolve_qualified_name()` builds a dotted string out of `Name`/`Attribute`
links, so `'clean'.replace('x', tainted)` resolves to `None` and reaches no
model at all. Binding the literal to a name first (`t = 'clean'` then
`t.replace('x', tainted)`) works normally.

This is a property of qualified-name matching rather than of receiver
propagation, and it applies equally to `[1, 2].pop()` and similar literal
receivers. Closing it would require matching on expression shape instead of
name — a separate decision, not taken here.

### Known gaps

`format` and `join` are deferred along with the previously documented
`UnaryOp`, subscript slices, lambda bodies, walrus expressions, conditional and
loop tests, and with-context expressions.


## M5.9 / M5.10 sıra kararı ve M5.6'nın bayatlamış gerekçesi

### Kök neden

`roadmap.md` M5.6'yı "Return sink abstraction" olarak adlandırıyor ve
gerekçesini `return Response(tainted)` → 0 bulgu ölçümüne dayandırıyordu.
`current-state.md` ise aynı numarayı traversal statement kapsamı için
kullanıyordu: iki doküman aynı numarayı iki farklı işe veriyordu ve roadmap'in
ölçümü, M5.6 uygulandıktan sonra güncellenmemişti.

Yeniden ölçüldü:

    return Response(tainted)   -> 1 bulgu    (visit_Return ile kapandi)
    return tainted             -> 0 bulgu    (asil acik olan bu)

Açık tasarım borcundaki "Return sink abstraction yok" maddesi geçerliliğini
koruyor; kapsamı çıplak `return tainted`.

### Karar: sıradaki iş ölçüme göre üçe bölündü

Aday olarak duran "format / join" tek bir iş değil, iki ayrı karar:

1. **Variadic argument model (M5.10).** Bir selector'ın "kalan tüm
   argümanları" adlandırabilmesi. Kazanç keyfi sayıda argüman üzerinde
   pozisyondan bağımsız taint: `os.path.join("/base", kirli)`,
   `os.path.join(kirli, "a", "b")` ve `tpl.format("s", kirli)` bugün 0 bulgu
   üretiyor, üçü de tek bir tanımla kapanır.

   `join` bu kapsamda **değil** — ilk sınıflandırmam yanlıştı, ölçümle
   düzeltildi. `join` tam olarak tek argüman alır (bir iterable), dolayısıyla
   boşluğu variadic arity değil konteyner-vs-eleman semantiğidir:
   `sep.join(kirli_string)` düz bir `CallModel` ile kapanır, `sep.join([kirli])`
   ve `sep.join(parts)` variadic ile de kapanmaz. Konteyner ertelemesine ait.
2. **Literal receiver eşleştirme (ertelendi).** `"SELECT {}".format(kirli)`
   bununla kapanmaz. `resolve_qualified_name` literal receiver için `None`
   döner, dolayısıyla çağrı hiçbir modele ya da kurala *ulaşmaz*. Kapatmak
   nitelikli-ad yerine ifade şekli üzerinden eşleştirme gerektirir — M5.8'de
   "Literal receivers cannot be matched" olarak kayda geçmişti ve ayrı bir
   karar olarak ertelenmeye devam ediyor.

Bu ikisinin önüne **M5.9 — statement header slotları** alındı. Ölçülen körlük:

    with open(kirli) as f:          -> 0 bulgu
    for row in cursor.execute(q):   -> 0 bulgu

Kök neden eksik bir expression handler değil: `generic_visit()` bu düğümlerin
gövdelerini geziyor ama başlık ifadesini `analyze_expression()`'a hiç
vermiyor. Sonuç taint kaybı değil, doğrudan bulgu kaybı. `with open(...)`
Path Manipulation'ın en yaygın yazımı olduğu için M5.9 M6'nın ön koşuludur:
M6 bugün yazılsaydı amiral kalıbını kaçıran bir kural olarak yayınlanırdı.

Sıra: **M5.9 → M5.10 → M6.**

### M5.10 ve `*args`: ikilem geçersizdi

"Variadic selector `*args` varken ne yapmalı" sorusu yanlış kurulmuş bir
ikilemdi. Mevcut pozisyonel kısıtlamanın gerekçesi **indeks hassasiyeti**:
`f(*rest, x)` çağrısında 1. pozisyonun hangi ifadeye denk geldiği bilinemez.
"N'den itibaren kalan tüm parametreler" ise indeks hassasiyetine dayanmaz —
unpacking olsa da olmasa da iyi tanımlı bir *görünür ifade kümesi*.

Karar: variadic selector, N'den itibaren **görünen tüm argüman ifadelerini**
bağlar; `Starred` düğümünün kendisi de görünür bir ifadedir ve ne katkı
vereceğine `_analyze_Starred` karar verir. Bugün `CLEAN` dönüyor — konteyner
ertelemesiyle tutarlı — ve konteyner semantiği tasarlandığında bu kendiliğinden
iyileşir. Yalnızca bir `Starred` selector'ın indeksinden *önce* duruyorsa
indeks hassasiyeti gerçekten kaybolur; o durumda selector hiçbir şey bağlamaz.

Yeni bir politika icat edilmiyor; mevcut parçalar besteleniyor. Prototiple
ölçüldü:

    os.path.join("/base", kirli)      -> 1 bulgu
    os.path.join(kirli, "a", "b")     -> 1 bulgu
    os.path.join("/base", "/c")       -> 0 bulgu
    os.path.join("/base", *parts)     -> 0 bulgu

Son satır dokümante edilmiş konteyner ertelemesiyle **aynı** false negative,
yeni bir kayıp değil.

### M5.10 karar: `rest()` adlandırılmış keyword argümanları kapsar

Belirleyici gerekçe `format` kalıbı değil, **parameter modeli**.

M5.5 kararı şunu kurdu: bir selector bir *parametreyi* adlandırır ve bir
parametre pozisyonel, keyword veya her ikisiyle adreslenebilir. O karar tam
olarak pozisyonel/keyword ayrımını ortadan kaldırmak için alındı. `rest()`
"kalan tüm parametreler" demektir; keyword'le geçilen bir parametre hâlâ o
parametredir. Pozisyonel-only bir `rest()` M5.5'in kaldırdığı ayrımı geri
getirirdi ve "neden `rest()` tek başına pozisyonel düşünmeye dönüyor"
sorusunun ayrı bir gerekçesi olması gerekirdi — yok. Mevcut mimariyle tutarlı
tek seçenek.

Model başına opt-in bayrak reddedildi: kapsamdaki iki hedef de aynı cevabı
istiyor, dolayısıyla bayrağın ayırt edici bir vakası yok. Repoda emsal var —
M3 review'unda sink'lerin farklı sanitizer bağlamları gerektiği ortaya
çıkınca rule-wide bir knob eklenmedi, `requires_sanitization_for`
`SinkPattern`'e taşındı; yani pattern bölündü. Spekülatif knob yerine pattern
bölmek bu repoda kurulu desen.

Ölçüldü:

    tpl.format(kirli)          -> 1
    tpl.format(n=kirli)        -> 1
    tpl.format("s", n=kirli)   -> 1
    tpl.format(n="s")          -> 0

### `**mapping` bu kararın istisnası değil

AST'de `**d` bir `keyword(arg=None)`'dır — ismi yoktur, içeriği bilinmez.
Yani "adlandırılmış keyword" değil, `Starred` ile birebir simetriktir:

    f(a, *rest, n=c)  ->  args=[Name, Starred]   keywords=[('n', Name)]
    f(**d)            ->  args=[]                keywords=[(None, Name)]

`rest()` ona `Starred` ile aynı muameleyi yapar: **değer ifadesini bağlar, ne
olacağına handler karar verir.** Yeni politika icat edilmiyor.

Sonucun "her zaman temiz" olmadığı ölçümle sabitlenmiştir — handler kirli
mapping'i zaten biliyor:

    tpl.format(**{"n": kirli})        -> 0   (dict literal -> _analyze_Dict CLEAN)
    d = {"n": kirli}; tpl.format(**d) -> 0   (aynı, konteyner ertelemesi)
    tpl.format(**request.get_json())  -> 1   (mapping'in kendisi tainted)
    d = request.json; tpl.format(**d) -> 1
    tpl.format(**temiz_dict)          -> 0

İlk iki satır dokümante edilmiş konteyner ertelemesidir, `rest()`'in getirdiği
yeni bir kayıp değil; konteyner semantiği tasarlandığında kendiliğinden
iyileşir.

### Kabul edilen risk ve kaçış yolu

`rest()`, girdi olmayan bir konfigürasyon keyword parametresi bulunan bir
hedefte o parametreyi de girdi sayar. Bugün kapsamda böyle bir hedef yok:
`format`'ın keyword'leri gerçekten çıktıya besleniyor, `os.path.join`'in
keyword parametresi yok.

Böyle bir hedef çıkarsa çözüm bir bayrak eklemek değil, **pattern'i /
modeli bölmektir** — yukarıdaki `requires_sanitization_for` emsali. Bu kaçış
yolu, ileride okuyanın knob aramasını önlemek için şimdiden yazılmıştır.

### Uygulama notu

`rest()` ayrı bir `RestSelector` tipi olarak eklendi; tek parametre sözleşmesini
korumak için `bind()` bu selector'da `TypeError` yükseltir, çoklu bağlama yalnızca
`bind_all()` üzerinden yapılır. `RestSelector`, `from_index` sonrasındaki görünür
pozisyonel ifadeleri ve tüm keyword değerlerini bağlar; önceki `Starred` nedeniyle
belirsizleşen pozisyoneller korunarak bağlanmaz.

Uygulama `taint_engine.py` değişmeden çalışır: mevcut argüman state cache'i
`RestSelector`'ın bağladığı `Starred` ve keyword değerlerini zaten hazırlar.
Yeni varsayılan modeller yalnızca `os.path.join` ve receiver'ı input olan
`format` için eklendi; sanitization varsayılan olarak sıfırlanır.

### Süreç notu

M5.6'nın gerekçesi uygulama sonrası yeniden ölçülmediği için bayatladı. Bir
sıralama gerekçesi olarak sunulan örnek, sunulmadan önce koda karşı
ölçülmelidir.

## Süreç: dosya allowlist'i bir doküman regresyonu üretti

M5.9 ve M5.10 brief'leri "tam olarak şu dosyalara dokunulur" biçiminde katı
bir allowlist taşıyordu. Bu, kapsam kaymasını başarıyla önledi — iki pakette
de tek bir yasak sınır aşılmadı.

Ancak `architecture.md` iki allowlist'te de yoktu. Uygulayıcı doğru davranıp
dokunmadı ve doküman kodla **çelişir** hale geldi:

    "If, While, For, With, Try ve FunctionDef için özel visitor bulunmaz."

M5.9 tam olarak o visitor'ları ekledi. `Await`, `rest()` / `RestSelector` ve
variadic modeller de eksikti.

Kök neden brief'i yazanda (koordinatör), uygulayanda değil. Allowlist bir
kapsam aracıdır; hangi dokümanın etkilendiğini de aynı titizlikle
belirlemek gerekir.

**Kural:** traversal sözleşmesi, selector modeli veya çağrı semantiği
değişiyorsa `architecture.md` allowlist'e girer. Değişmiyorsa girmez.

## M5.9 — Statement header slotları

### Kök neden

`if` / `while` test'i, `for` / `async for` iter'i ve `with` / `async with`
context'i eksik bir expression handler nedeniyle değil, bu düğümlerin
statement visitor'ları başlık slotlarını `analyze_expression()`'a vermediği
için analiz edilmiyordu. Sonuç taint kaybı değil, başlıkta bulunan sink için
doğrudan bulgu kaybıydı.

### Karar

Her statement visitor başlık ifadesini analiz eder ve dönen state'i bağlamadan
atar; ardından `generic_visit(node)` çağırarak gövde traversal'ını korur.
`with` düğümlerinde listedeki her `context_expr` analiz edilir. `Await` ayrı
bir expression handler olarak değerinin state'ini döndürür; bu, statement
header slotlarından bağımsız bir kök nedendir.

`generic_visit()` başlık ifadesini tekrar `analyze_expression()`'a indirmez;
AST çocuklarını dolaşması inert olduğu için başlık sink'leri çift raporlanmaz.

`for` target ve `with ... as` optional target bağlanmaz. Konteynerden elemana
ve context sonucundan hedefe taint türetme semantiği ertelenmiştir; bu davranış
bilinçli olarak testlerle korunur.

## Paylaşılan source tanımı

SQL Injection ve XSS, Flask request input kaynağını aynı `id` ve `kind` ile
taşıyan iki ayrı `SourcePattern` olarak tanımlıyordu. Ölçülen tek fark
`request.values` hedefiydi: XSS bunu kapsarken SQL Injection kapsamıyordu ve
`request.values['n']` değerinin `cursor.execute` sink'ine ulaşması 0 bulgu
üretiyordu. Bu kayma tesadüfi bir yazım hatası değil, tanımın kural dosyalarında
kopyalanmasının ürettiği sürdürülemez bir yapısal kaymadır.

Bu nedenle yalnızca `targets` tuple'ı değil, `SourcePattern`'in tamamı
`rules/sources.py` içinde tek bir immutable örnek olarak paylaşılır. Böylece
`id`, `kind` ve hedefler birlikte değişir; kural başına özel source tanımlamak
ise farklı bir `kind` gerektiğinde hâlâ mümkündür.

Değişiklik M6'dan önce ve ayrı yapıldı: M6'nın diff'i yeni kategorinin saf
eklenmesi olarak kalmalı ve bu değişikliğin yayınlanmış SQL Injection
davranışını genişletmesi ayrı, bisect edilebilir bir diff olmalıdır.

## M6 — Path Manipulation

M6, `Rule` şemasını değiştirmeden CWE-22 için üç dosya sink'i (`open`,
`send_file`, `send_from_directory`) ve iki güvenli basename sanitizer'ı
(`secure_filename`, `os.path.basename`) tanımlar. Sanitization bağlamı
`"path"`'tir; SQL veya HTML bağlamları bu kural için geçerli değildir.
`send_from_directory(directory, path, ...)` imzasında kullanıcı kontrolündeki
parametre `path`'tir, yani **1 indeksli** (ikinci) pozisyonel argüman; 0
indeksli `directory` tehlikeli değildir. `parameter(1, "path")` her iki yazımı
da tek selector'la çözer.

### `os.path.join` ve sanitization

`os.path.join` nötr bir ayraç ekleyici değildir. Ölçüm:

```text
posixpath.join('/uploads', '/etc/passwd') = '/etc/passwd'
```

Mutlak bileşen önceki prefix'i sildiği için ham bir bileşen join'den sonra
sink'e ulaştığında zafiyet oluşturabilir. Buna rağmen `os.path.join` güvenli
basename sanitizer'ının işaretini korur; garanti join'den değil,
`secure_filename` ve `os.path.basename` çıktılarının mutlak yol veya ayraç
üretmemesinden gelir. Gelecekte eklenecek her sanitizer için kontrol kuralı
şudur: garantisi `os.path.join`'in prefix-silme davranışından sağ çıkıyor mu?

`Path` aynı nedenle taint ve sanitization koruyan bir `CallModel` ile modellenir.
`Path('/uploads', '/etc/passwd')` mutlak bileşen davranışını taşır; `/`
operatörü ise mevcut `BinOp` ve `merge_states()` akışıyla analiz edilir.
`format` bu karardan etkilenmez ve sanitization'ı sıfırlamaya devam eder; HTML
text değerini template'in yeni bağlamına taşımak güvenlik bağlamını korumaz.

### Bilinçli sınırlar

`normpath`, `abspath` ve `realpath` sanitizer değildir. Ölçümde
`normpath('../../etc/passwd')` hâlâ `'../../etc/passwd'`,
`join('/up', normpath('../../etc/passwd'))` ise confinement sağlamayan bir
sonuç üretir. Benzer şekilde `os.path.basename('..')` `'..'` döndürür; en kötü
durumda `base/..` bir dizini adlandırır, güvenli bir dosya adı garantisi vermez.

`Path(kirli).read_text()` 0 bulgu verir. `SinkPattern` receiver desteği
taşımadığı için bu boşluk ayrı bir tasarım kararına bırakılmıştır; receiver
sink'i için `rule_model.py` değiştirilmemiştir.

`os.remove`, `os.unlink`, `os.rename`, `shutil` ve arşiv çıkarma sink'leri
ertelenmiştir. `startswith` ile yapılan confinement kontrolü de control-flow
analysis gerektirdiği için modellenmez ve ilgili kod false positive üretebilir.

## Kural izolasyonu

M7 öncesinde `TaintState.kind` taşınıyor olsa da `_check_sinks()` bu alanı
kontrol etmiyordu. Bu, ilk üç kural aynı `kind="user-input"` source ailesini
paylaştığı için o zamana kadar doğru görünen bir no-op'tu. İkinci source ailesi
gelince dört çapraz tetikleme ölçüldü: `os.environ['SECRET']` SQL sink'inde,
HTTP yanıtında ve `open` sink'inde; `request.args['q']` ise Sensitive Data
Exposure'ın `print` sink'inde bulgu üretiyordu.

Çözüm yeni bir kavram değildir: `Rule`, source + sanitizer + sink'i tutarlı bir
birim olarak paketler ve doğal sözleşme "benim source kind'ımdan benim sink'ime"
okumasıdır. Generic motor, sink değerlendirmesinde state'in `kind` değerini
rule'un source kind kümesiyle karşılaştırır. Bu kural-özel mantık değildir;
`kind`, `TaintState`'in generic alanıdır ve kontrolde `sql`, `execute` veya
`path` gibi zafiyete özgü string'ler yoktur.

`SinkPattern.accepts_kinds` alanı reddedildi. Bugün bir sink'in birden fazla
source ailesini kabul etmesini gerektiren vaka yoktur; mevcut kuralların her
birini güncellemek M7'yi saf ekleme olmaktan çıkarırdı. İleride gerçek bir
istisna çıkarsa bu alan bir override olarak ayrıca tasarlanabilir.

`kind=None` taşıyan tainted state'ler filtrelenmez. Böylece bugün oluşmayan
ama modelin izin verdiği source'suz taint state'leri sessizce kaybolmaz.

## M7 — Sensitive Data Exposure

M7'nin taint yönü önceki kategorilerden farklıdır: güvenilmeyen input'tan
tehlikeli işleme değil, güvenilen ama hassas veriden görünür yere akış aranır.
Bu nedenle `FLASK_REQUEST_INPUT` paylaşılmaz; `kind="sensitive"` taşıyan ayrı
bir `secret-value` source pattern'i kullanılır. `request.form["password"]`
source yapılmadı: qualified-name çözümleyici subscript anahtarını atar ve
`request.form`'u geniş biçimde eşleştirerek source ailelerini kural sırasına
bağımlı hale getirirdi.

Kaynakların iki grubu vardır. Attribute-şekilli hedefler `password`, `secret`,
`api_key`, `token`, `api_token`, `private_key`, `SECRET_KEY` ve
`DATABASE_PASSWORD` gibi suffix eşleşen adlardır. Çağrı/subscript şekilli
hedefler `os.environ`, `os.getenv` ve doğrudan `getpass.getpass`'tır. `os.environ`
bilinçli olarak geniştir; `os.environ['PATH']` de aynı qualified-name'e
çözülür.

Konsol/log sink'leri `print` ve logging seviyeleridir. HTTP sink'leri
`Response` ile `make_response`'dur ve `parameter(0, "response")` ile iki
pozisyonel/keyword yazımı kapsanır. `Response` XSS kuralında da sink'tir;
kind izolasyonu sayesinde `os.environ['SECRET']` Sensitive Data Exposure,
`request.args['q']` ise XSS olarak raporlanır.

Bu kuralda sanitizer yoktur. Hash, masking veya truncation bir sırrı ortadan
kaldırmaz; başka biçimde ifşa etmeye devam eder. Modellenmemiş bir redaction
helper'ı ise mevcut bilinmeyen çağrı politikası nedeniyle taint'i zaten
temizler ve `print(redact(secret))` bugün 0 bulgu verir.

### Geniş environment kaynağı ve M11 bağımlılığı

`os.environ`'ın geniş eşleşmesi yanlış pozitif maliyeti taşır; `PATH` gibi
değerler de bulgu üretir. Bu tercih başka araçlara analojiyle değil, CodeXray'in
kendi mimarisiyle gerekçelidir: `project-context.md` ilk günden yanlış
pozitifleri azaltmak ve bulguları insan diline çevirmek için LLM triage katmanı
tasarlamıştır. Tespitte yüksek duyarlılık, triage'da hassasiyet bilinçli ve
tutarlı bir ayrımdır.

Bunun bir bağımlılık maliyeti vardır: M11 roadmap'in sonunda olduğu için
yapılmazsa geniş environment bulguları ham sevk edilir. M7'nin pratik
hassasiyeti triage'ın gerçekten uygulanmasına bağlıdır; bu da M11'i yukarı
çekme gerekçesini güçlendirir.

### Maliyetin çıktı tarafında ayrıştırılması

Maliyet sanıldığından düşüktür: `Finding.path[0]` kaynağı adlandırır. Ölçülen
`os.environ -> s -> print` ile `settings.SECRET_KEY -> s -> print` yolları,
geniş environment bulgularını isim-spesifik bulgulardan çıktı tarafında ayırır.
Bu ayrım için yeni bir Finding veya JSON şeması alanı gerekmez. Severity'yi
source'a göre ayırma alternatifi elendi; `severity` Rule seviyesindedir ve
SourcePattern'a taşımak iki ayrı Rule ile sink setlerini çoğaltarak source
seti sorununu yeniden üretirdi.

## CLI ve Finding'in dosya alanı

### Kuralların pakete taşınması

`rules/` repo kökünde kaldığında `pyproject.toml` yalnızca `src/` paketlerini
kurduğu için kurulu `codexray` motoru kuralsız kalıyordu. İzole venv ölçümü bu
durumu doğruladı: taşıma öncesi `from codexray.rules.sql_injection import ...`
`ModuleNotFoundError` verdi; taşıma sonrası aynı import `ok` verdi. Kurallar
`src/codexray/rules/` altına taşındı ve kayıt noktası olarak `ALL_RULES` eklendi.

### Dosya konumu ve JSON sözleşmesi

Bir `Finding` kendi kendine yetebilmesi için `filename` taşır; bu alan CLI ve
gelecekteki M11 triage girdisi için gereklidir. `Finding.path` yeniden
adlandırılmadı: bu alan `TaintState.path` ile aynı taint yolunu temsil eder ve
simetri korunur. Dosya yolu ile taint yolu JSON şemasında ayrıştırılır:
`file` dosya yoludur, `taint_path` ise `Finding.path` değeridir.

CLI her dosya için ayrı analyzer kullanır, dosyaları sıralı tarar ve
`SyntaxError` görülen dosyayı atlayıp stderr'e yazar. Exit kodları bulgu yoksa
`0`, en az bir bulgu varsa `1`, kullanım veya eksik path hatasında `2`'dir;
syntax hatası tek başına exit kodunu değiştirmez.

### Açık borç

CI `pip install .` çalıştırsa da testleri `pythonpath` ayarıyla kaynak
ağacından import ettiği için kurulan paketi henüz sınamıyor. İzole venv
doğrulaması bu CLI değişikliğinde elle yapıldı; CI'ın kurulu paketi test etmesi
ayrı bir iş olarak bırakıldı.


## Bulgu mesajı motordan çıkarıldı

### Kök neden

`_check_sinks` her bulgu için sabit bir cümle kuruyordu:

    "{source} kaynakli kullanici girdisi, sanitize edilmeden {sink}'ine ulasiyor"

M7'ye kadar bu doğruydu; üç kuralın da kaynağı gerçekten kullanıcı girdisiydi
ve üçünün de `requires_sanitization_for`'u doluydu. M7 ikinci source ailesini
(`kind="sensitive"`) getirince cümle yalan söylemeye başladı: `os.environ`
kullanıcı girdisi değil, ve M7'nin sanitizer'ı yok.

Bu, kural izolasyonu sorununun **birebir aynı şekli**: tek source ailesi
varken doğru olan bir varsayım, ikinci aile gelince kırıldı.

### Elenen üç seçenek

Kural başına mesaj şablonu alanı, `kind`'ı cümleye gömmek, ve nötr bir cümle
kurmak. Üçü de aynı soruyu soruyordu: *motor cümleyi nasıl kursun.* Asıl soru
**motor neden cümle kuruyor** idi.

### Karar

`Finding.message: str` kaldırıldı, yerine `Finding.kind: str | None` geldi.
Alan sayısı aynı, `_check_sinks`'te tek değişiklik: `kind=state.kind`.

Cümledeki her olgu zaten `Finding`'de vardı, biri hariç:

| Cümle parçası | Nerede |
|---|---|
| kaynak | `path[0]` |
| "kullanıcı girdisi" | hiçbir yerde — sabit kodlanmıştı |
| "sanitize edilmeden" | bulgunun var olması zaten ima ediyor |
| sink | `path[-1]` |

Yani nesir tek bir olgu taşıyordu: kaynağın ailesi. O artık `kind` olarak
yapısal biçimde duruyor.

Nesir sunum katmanına taşındı; CLI zaten vardı. İnsan çıktısı üç satırdan
ikiye indi ve `kind` başlık satırında etiket olarak görünüyor:

    sensitive_data.py:5  MEDIUM  sensitive-data-exposure  CWE-200  [sensitive]
        os.environ -> secret -> print

Kaldırılan üçüncü satır zaten üstündeki `path` satırının nesir hâliydi.

### Neden bu mimariyi hizalıyor

`project-context.md` ilk günden LLM triage katmanını "yanlış pozitifleri
azaltan, **insan diline çeviren**" katman olarak tanımladı. İnsan diline
çevirmek tasarım gereği M11'in işi; motorun kendi cümlesini kurması o katmanın
işine el atmaktı. Ayrım artık net: **motor olgu üretir, triage ifade eder.**
Yapısal veri M11 için hazır bir cümleden daha iyi girdi.

### Neden M7 ile aynı PR'da

`cli.py` main'de olduğu için JSON sözleşmesi yayınlanmış durumda ve
`"message"` → `"kind"` onu değiştiriyor; ayrı görünürlük hak ediyor — ama
ayrı **commit** olarak, ayrı PR olarak değil.

Belirleyici gerekçe: **bugün main yalan söylemiyor.** Yalanı M7'nin kendisi
yaratıyor. Düzeltme M7'den sonra ayrı bir PR olarak gelseydi, iki merge
arasındaki sürede main yanlış sınıflandırma üretirdi. Bir güvenlik aracının
tek bir merge döngüsü boyunca bile yanlış ifade üretmesi kabul edilmemeli.

### Ölçüm

Değişiklikten önce `message`'a bakan **sıfır** test vardı ve alan yalnızca
`cli.py`'de iki yerde tüketiliyordu. Bu, değişikliği ucuz kıldı — ama aynı
zamanda alanın hiç doğrulanmadığını gösteriyordu. `kind` aynı durumda
bırakılmadı: üç yeni test ve üç mutasyon eklendi.

## Kural izolasyonunun karışık kaynak regresyonu ve düzeltmesi

### Regresyon

İzolasyon eklendikten sonra ölçüldü. `TaintState` tek bir `kind` taşıyordu ve
`merge_states()` onu **ilk tainted parçadan** alıyordu (tek kaynak provenance).
İzolasyon kapısı o tekil değere baktığı için, karışık kaynaklı bir değerde bir
aile sessizce düşüyordu — ve sonuç **operand sırasına** bağlıydı:

    u = request.args['q']; t = os.environ['TOKEN']

    w = u + t   -> kind='user-input'  -> print(w)           0 bulgu  (sir kaciyor)
    w = t + u   -> kind='sensitive'   -> cursor.execute(w)  0 bulgu  (SQLi kaciyor)

Gerçekçi kalıpta:

    logging.info('user ' + u + ' token ' + t)   ->  0 bulgu

API token loglanıyor ve kaçırılıyordu, sırf kullanıcı operandı önce geldiği
için.

Bu, "dokümante edilmiş borç yüzeye çıktı" değil, **izolasyon değişikliğinin
yarattığı bir regresyondu**: doğru karşılaştırma M7+izolasyon ile
M7-izolasyonsuz arasındadır ve izolasyonsuz halde ikisi de raporlanıyordu.
Sessiz ve operand sırasına bağlı bir false negative, bir güvenlik aracında
sistematik false positive'den kötüdür. Bu nedenle sevk edilmedi, düzeltildi.

### Karar: `kind` yerine `kinds`

`TaintState.kind: str | None` **kaldırıldı**, yerine
`TaintState.kinds: frozenset[str]` geldi.

- Source kurulumu tek elemanlı bir küme üretir.
- `merge_states()` katkıda bulunan tüm parçaların kümelerini **birleştirir**
  (`sanitized_for`'un kesişim almasının tersi yönde: sanitization'da
  muhafazakâr olan kesişim, provenance'ta ise birleşimdir).
- `_check_sinks` kesişime bakar: `state.kinds & accepted_kinds` boş değilse
  sink ateşlenir.
- `Finding.kind` **eşleşen** kind'ı raporlar, bir "birincil" kind'ı değil.

Tekil `kind` alanı bilinçli olarak geri getirilmedi. Bırakılsaydı ileride
biri `state.kind == "sensitive"` yazabilirdi — tam da bu regresyonu yaratan
sıra-bağımlı okuma. Bir test bu alanın yokluğunu sabitliyor.

### Ölçüm

Düzeltmeden sonra, her iki operand sırasında da:

    w = u + t  ve  w = t + u   ->  print(w)           sensitive-data-exposure
    w = u + t  ve  w = t + u   ->  cursor.execute(w)  sql-injection
    logging.info('user ' + u + ' token ' + t)      ->  sensitive-data-exposure

Karışık bir değer **her iki** ailenin sink'ini de ateşler; her bulgu kendi
eşleşen kind'ıyla raporlanır. İzolasyonun kazanımları korunuyor: `os.environ`
değeri `cursor.execute`/`open`'a, `request.args` değeri `print`'e hâlâ 0 bulgu
veriyor. Kinds, CallModel, receiver, `os.path.join` ve f-string yollarından
korunarak taşınıyor.

### Kapsam dışı kalan

Bu, `TaintState.source`'un hâlâ tek kaynak taşıması anlamına gelen genel
multi-source provenance borcunu kapatmaz — yalnızca **sink kapısını besleyen**
alanı çoğullaştırır. `source` raporlamada kullanılıyor ve bir kapı girdisi
değil; çoğullaştırılması ayrı bir karardır.


## M7'nin kaynak eşleştirmesi diğer kurallardan kategorik olarak farklı

Bu bir iş maddesi değil, kayda geçirilmiş bir gözlem — dördüncü "tek aile
varsayımı" sürprizini önlemek için.

İlk üç kural belirli bir **API yolunu** hedefliyor:

    CallTarget("request.args")     -> tam nitelikli ad

M7 ise bir **isim sezgiseline** dayanıyor:

    CallTarget("password")         -> ".password" ile biten HERHANGI bir ad

Bu, projenin reddettiği regex'e dönüşmüyor — hâlâ ad tabanlı eşleştirme,
desen değil. Ama hassasiyet profili farklı, ve bu farkın somut bir sonucu
oldu: **büyük/küçük harf duyarlılığı SQL/XSS için doğru, M7 için sorun.**

`request.args` tam olarak öyle yazılır. Ama Django ve Flask konfigürasyon
sabitleri konvansiyon gereği büyük harflidir, dolayısıyla küçük harfli
`password` / `token` hedefleri `settings.PASSWORD` ve `settings.API_TOKEN`
gibi en yaygın biçimleri kaçırıyordu. Ölçüldü — kural ilk hâlinde:

    settings.SECRET_KEY   -> bulundu
    settings.API_TOKEN    -> KACIRILDI
    settings.PASSWORD     -> KACIRILDI
    config.SECRET         -> KACIRILDI

Bugünün çözümü ucuz ve kural içeriğinde kaldı: büyük harfli varyantlar tek
tek sayıldı (`PASSWORD`, `SECRET`, `API_KEY`, `TOKEN`, `API_TOKEN`,
`PRIVATE_KEY`). M7'nin bütün değeri hassasiyetinde olduğu için kural ilk
gününde amiral vakasını kaçırıyor olmamalıydı.

Genel çözüm — bu source ailesi için büyük/küçük harf duyarsız eşleştirme —
`matches_target()`'a dokunur ve **her kuralı** etkiler. Ayrı bir karar;
burada alınmadı.

Kapsamın genişlemediği de ölçüldü: `settings.DEBUG`, `config.TIMEOUT`,
`settings.ALLOWED_HOSTS`, `user.name` ve `config.DATABASE_URL` hâlâ bulgu
üretmiyor. Negatif testlerle sabitlendi.


## M11 LLM triage — tasarlandı, bilinçli olarak kurulmadı

Katmanın şekli tasarlandı ve maliyeti ölçüldü; kod yazılmadı. Bu kayıt,
ileride kuracak kişinin tasarım aşamasını baştan yapmaması içindir.

### Katmanın şekli

    Finding (yapisal)  ->  TriageClient (protokol)  ->  Verdict (yapisal + insan cumlesi)
                                ├── FakeTriage    (agsiz, testler icin)
                                └── ClaudeTriage  (opsiyonel bagimlilik)

Katmanın **değerli kısmı ağ gerektirmiyor**: protokol, `Verdict` tipi ve CLI
entegrasyonu tamamen offline test edilebilir. Yalnızca gerçek istemci SDK ve
kimlik bilgisi ister.

`Finding` artık nesir taşımadığı için (bkz. "Bulgu mesajı motordan çıkarıldı")
triage'ın girdisi hazır: yapısal olgu girer, yapısal verdict + bir insan
cümlesi çıkar. Doğru teknik araç **structured outputs**
(`output_config.format` / `messages.parse()`) — verdict şemayla doğrulanmış
gelir, nesir ayrıştırmak gerekmez.

**Sınır:** triage bulgu **üretemez**, yalnızca işaretler veya bastırır.
`project-context.md`'nin "tespit motoru değil, sadece triage" kararı.

### Çağrı deseni: tek çağrıda tüm bulgular

Bir taramanın bütün bulguları tek istekte değerlendirilir. Daha ucuz, ve model
bulguları birbirinin bağlamında görür — aynı dosyada tekrar eden bir kalıbı
fark edebilir. Bulgu başına çağrı N kat pahalı ve çapraz bağlamı kaybediyor;
büyük taramalarda gerekebilir, küçük ölçekte gereksiz.

### Maliyet (ölçüldü)

Bir tarama ≈ 1.1K girdi + 600 çıktı token. `claude-opus-5` ile
(\$5 / \$25 per MTok) **tarama başına ~2 sent**.

### Motive eden vaka (ölçüldü)

`os.environ['PATH']` ile `os.environ['SECRET']` nitelikli-ad eşleştirmesiyle
ayırt edilemiyor — `resolve_qualified_name` subscript anahtarını taşımıyor
(bkz. M7 karar kaydı). Bir LLM bunu ayırt edebilir; eşleştirici edemez.
M7'nin hassasiyeti bu katmanın varlığına bağlı olarak kayda geçmişti.

### Neden kurulmadı

**Ücretli bir katman istenmedi.** Ayrıca ortam ölçüldü: `ant` CLI kurulu
değil, `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` / `ANTHROPIC_PROFILE`
üçü de unset, `~/.config/anthropic` yok, `anthropic` SDK kurulu değil. Yani
hiçbir kimlik bilgisi yok.

Bu koşulda `ClaudeTriage` **hiç çalıştırılamadan** sevk edilirdi. On
milestone boyunca "ölçmeden iddia etme" disiplini uygulandı; doğrulanmamış
bir ağ istemcisi bunun ihlali olurdu. Yalnızca `FakeTriage` ile sevk etmek de
"triage denemesi" olmaktan çıkardı — sahte çıktı demo değildir.

Proje ücretsiz ve bağımlılıksız kaldı. Katman, projenin modüler yapısı gereği
zaman kalırsa çekirdeğe dokunmadan eklenebilir.

## M8 / M9 kapsam kesintisi

**AST-yapısal kurallar (M8) ve presence-check (M9) kapsam dışı bırakıldı.**

### Gerekçe: ikinci ve üçüncü bir kural şekli, yani ayrı bir motor

Mevcut `Rule` taint şeklidir: `sources` + `sanitizers` + `sinks`. M8 ve M9
bu şemaya girmiyor:

- **Empty Catch Block, Insecure Randomness, Hardcoded Password** yapısal AST
  kontrolleridir — ne source'ları, ne sanitizer'ları, ne sink'leri var. Tek
  düğüm/desen eşleştirmesi.
- **CSRF** bir *yokluk* kontrolüdür — bir korumanın bulunmadığını arar.
  Taint akışı yoktur, aranan şey bir akışın **olmaması** bile değil, bir
  bildirimin eksikliğidir.

Hardcoded password ayrıca taint olarak ifade **edilemiyor**: string
literal'in nitelikli adı yok (ölçüldü: `"hunter2"` → `None`), dolayısıyla
kural motoruna hiç ulaşmıyor.

`architecture.md` üç motor tipini ve registry desenini ilk günden tanımlıyor;
mimari niyet var. Ama bugüne kadar yalnızca **taint motoru** kuruldu. M8 ve
M9 ikinci ve üçüncü motoru yazmayı gerektirir — kural eklemek değil, motor
eklemek.

### Neden kesildi

Kalan sürede iki yeni motor yazmak, mevcut taint motorunun kalitesini
düşürmeden mümkün değildi. Proje ilk günden "8 zafiyeti yüzeysel yakalayan
araç değil, gerçek bir motor + o motorun genellenebilir olduğunu kanıtlayan
birkaç kategori" hedefiyle kuruldu (`roadmap.md` → "Neden bu sıra"). Dört
taint kategorisi ve motorun genellenebilirlik kanıtı teslim edildi; iki
yarım motor eklemek o hedefin tersi olurdu.

Yazılı bir kesinti mühendislik muhakemesidir; sessiz bir eksik teslim
edilememedir. Bu kayıt kesintiyi açık hâle getirir.

### Ne teslim edildi

Taint gerektiren dört kategori: SQL Injection, XSS, Path Manipulation,
Sensitive Data Exposure — sonuncusu farklı bir source ailesiyle, yani motorun
yalnızca sink tarafında değil kaynak tarafında da genelleştiğinin kanıtıyla.


## Gerçek uygulama taraması — motor ilk kez gerçek kodda

On milestone boyunca motor yalnızca birim testleri ve `examples/` üzerinde
çalıştırıldı. İlk gerçek kod taraması iki hedefte yapıldı ve **iki gün
kaybettirecek bir körlük ortaya çıkardı.**

### Hedefler

| Hedef | Ne | Boyut |
|---|---|---|
| `vulpy` | Bilerek zafiyetli Flask eğitim uygulaması | 57 dosya, 2 373 satır |
| `flask` + `werkzeug` + `jinja2` | Gerçek üretim kodu | 101 dosya, 45 137 satır |

### Bulunan körlük: SQL sink'i cursor değişkeninin ADINA bağlıydı

vulpy taraması **0 bulgu** verdi. Teşhis:

    cursor.execute(v)  -> 1 bulgu
    c.execute(v)       -> 0        <- vulpy bunu kullaniyor
    cur.execute(v)     -> 0
    db.execute(v)      -> 0
    conn.execute(v)    -> 0

Kural `CallTarget("cursor.execute")` hedefliyordu ve nitelikli-ad suffix
eşleştirmesi `"c.execute"` ile eşleşmiyor. Yani sink, cursor değişkeninin
harfiyen `cursor` adını taşımasını istiyordu.

**M4'ten beri böyleydi.** Görünmemesinin sebebi her testin ve her örneğin
`cursor` adını kullanmasıydı — testler kuralın kendi varsayımını
tekrarlıyordu, sınamıyordu.

Düzeltme tek satır ve kural içeriğinde: hedef `execute` (artı `executemany`).
Motor değişmedi. Ölçüldü — altı farklı cursor adı da artık eşleşiyor,
sanitizer davranışı korunuyor.

**Yanlış pozitif maliyeti sıfır ölçüldü:** 45 137 satır gerçek üretim
kodunda (Flask, Werkzeug, Jinja2) 0 bulgu, düzeltmeden önce de sonra da.

### vulpy hâlâ 0 bulgu veriyor — ve sebebi ölçüldü

Düzeltmeden sonra bile vulpy'nin SQLi'si yakalanmıyor, çünkü kod **aynı anda
üç dokümante edilmiş sınıra** çarpıyor:

    # mod_user.py (route handler)
    username = request.form.get('username')       # SOURCE  -- calisiyor
    username = libuser.login(username, password)  # 1) fonksiyon + modul siniri

    # libuser.py
    def login(username, password):
        c.execute("SELECT ... '{}' ...".format(username))   # 2) literal receiver

1. **Inter-procedural.** Source route handler'da, sink başka bir modüldeki
   fonksiyonda. MVP'nin ilk günden ilan ettiği sınır.
2. **Literal receiver `.format()`.** M5.8/M5.10'da ölçülüp bilinçli olarak
   ertelendi: `"...".format(x)` hiçbir nitelikli ada çözülmüyor.
3. **`%` tuple ile.** `"..." % (u, p)` — tuple `CLEAN` döndüğü için taint
   taşımıyor (konteyner ertelemesi). Tek değerle `"..." % u` çalışıyor.

Aynı kalıbın çalışan biçimleri ölçüldü:

    tek fonksiyon, f-string      -> 1 bulgu
    tek fonksiyon, "%s" % kirli  -> 1 bulgu
    tek fonksiyon, dogrudan      -> 1 bulgu
    tek fonksiyon, .format()     -> 0    (literal receiver)
    tek fonksiyon, "%s" % (k,)   -> 0    (konteyner)
    iki fonksiyon                -> 0    (inter-procedural)

### Ne öğretti

Bu tarama, projenin kendi disiplininin bir boşluğunu gösterdi: **testler ve
örnekler aynı kişi tarafından yazıldığında kuralın varsayımını tekrarlar.**
`cursor` adı on milestone boyunca hiç sorgulanmadı çünkü onu sorgulayacak
tek şey gerçek koddu.

Ölçmeden iddia etmeme disiplini iddiaları doğruladı; ama *hangi iddiaların
kurulacağını* seçen şey yine aynı varsayımlardı. Gerçek kod bu döngüyü
kıran tek girdi.
