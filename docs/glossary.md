# CodeXray — Glossary

## SAST

**Static Application Security Testing**

Kaynak kodunu çalıştırmadan analiz ederek güvenlik açıklarını tespit etmeye çalışan yaklaşım.

## AST

**Abstract Syntax Tree**

Kaynak kodunun yapısal ağaç temsilidir.

CodeXray Python'un `ast` modülünü kullanarak kodu AST'ye dönüştürür.

## Taint

Güvenilmeyen bir kaynaktan geldiği bilinen veya o kaynaktan türeyen veri.

## Taint Tracking

Tainted verinin program içinde nereden gelip nereye aktığını takip etme yöntemi.

## Source

Tainted verinin sisteme girdiği güvenilmeyen kaynak.

Örnek:

```python
request.args["username"]
```

## Sink

Tainted verinin ulaşmasının güvenlik açısından tehlikeli olduğu hassas işlem.

Örnek:

```python
cursor.execute(query)
```

## Sanitizer

Tainted veriyi belirli bir güvenlik bağlamı için güvenli hale getiren işlem.

Örnek:

```python
escape_sql(username)
```

Sanitizer genel olarak her bağlam için güvenli olduğu anlamına gelmez.

## TaintState

Bir değerin taint durumunu taşıyan immutable veri modeli.

Şu anda temel olarak:

- `tainted`
- `source`
- `kind`
- `path`
- `sanitized_for`

bilgilerini içerir.

## Taint Path

Tainted verinin source'tan sink'e kadar izlediği yol.

Örnek:

```text
request.args
    ↓
username
    ↓
query
    ↓
cursor.execute
```

## Propagation

Taint bilgisinin bir expression veya değişkenden başka bir expression veya değişkene aktarılması.

## Environment (`env`)

Analiz sırasında bilinen değişkenlerin mevcut `TaintState` bilgilerini tutan sözlük.

Örnek:

```text
username → TaintState(...)
query    → TaintState(...)
```

## TaintAnalyzer

AST üzerinde gezen ve expression'ların taint durumunu hesaplayan analiz motoru.

## Rule

Belirli bir güvenlik açığının nasıl tanınacağını tanımlayan güvenlik kuralı.

Bir rule temel olarak:

- source
- sanitizer
- sink

bilgilerini içerir.

## RuleEngine

Bir AST node'un güvenlik açısından source, sanitizer veya sink olup olmadığını belirleyen katman.

## RuleMatch

`RuleEngine` tarafından bulunan eşleşmeyi temsil eder.

Rule, eşleşmenin rolü ve ilgili pattern bilgisini taşır.

## SourcePattern

Bir veya daha fazla source hedefini tanımlayan rule bileşeni.

## SanitizerPattern

Belirli bir sanitizer'ı ve hangi güvenlik bağlamları için sanitization sağladığını tanımlayan rule bileşeni.

## SinkPattern

Bir sink'i ve kontrol edilmesi gereken tehlikeli argümanları tanımlayan rule bileşeni.

## CallModel

Bir fonksiyon veya kütüphane çağrısının **veri akışı semantiğini** tanımlayan model: hangi argümanlardan, hangi çıktıya, hangi taint davranışıyla.

`Rule` güvenlik anlamını (source/sanitizer/sink) tanımlarken `CallModel` yalnızca "bu çağrının dönüş değeri argümanlarından taint taşır mı" sorusunu cevaplar. Vulnerability-specific değildir.

Örnek:

```text
str(user_input)        → tainted return
json.dumps(user_input) → tainted return
len(user_input)        → clean return
```

Açıkça modellenmemiş çağrılar otomatik olarak tainted kabul edilmez.

## ArgumentSelector

Bir çağrının hangi **parametresinin** kastedildiğini, çağrı yerini bilmeden tanımlayan seçici.

Bir parametre pozisyonel indeksle, isimle veya her ikisiyle adreslenebilir — bu yüzden tek bir selector her iki yazımı da taşır:

```text
parameter(index, name)   # her iki yazım
positional(index)        # = parameter(index=...)
keyword(name)            # = parameter(name=...)
```

Geriye dönük uyumluluk için düz bir `int` de `positional(index)` anlamına gelir.

Kritik ayrım — tuple uzunluğu **parametre sayısını** verir:

```text
(parameter(0, "s"),)                      -> TEK parametre, iki yazımı var
(parameter(0), parameter(name="extra"))   -> İKİ ayrı parametre
```

## CallArgumentBinder

Bir `ArgumentSelector`'ı somut bir `ast.Call` üzerinde çözen katman.

Aynı mekanizma `CallModel`, sink ve sanitizer katmanlarında ortak olarak kullanılır.

Önce pozisyonel yazımı, sonra keyword yazımını dener; **ilk eşleşen kazanır, asla merge etmez.** Gerçek bir çağrıda bir parametre tek yolla geçilir.

Bilinçli olarak muhafazakârdır: çözülemeyen bir selector (eksik keyword, `**kwargs` içeriği, `*args` sonrası pozisyon) tahmin üretmez, hiçbir şeye bağlanmaz.

## Qualified Name

Bir AST expression'ının nokta zinciri şeklindeki adı.

Örnek:

```text
request.args
cursor.execute
```

CodeXray MVP'de qualified-name tabanlı matching kullanır.

## Intra-Procedural Analysis

Taint takibinin aynı fonksiyon sınırları içinde yapılması.

CodeXray MVP'sinin mevcut kapsamıdır.

## Inter-Procedural Analysis

Taint takibinin fonksiyonlar arasında yapılması.

CodeXray'de v0.2 / stretch goal olarak planlanmıştır.

## BinOp

Python AST'de ikili işlemleri temsil eder.

Örneğin:

```python
query = "SELECT ..." + username
```

gibi string birleştirmeleri.

## JoinedStr

Python AST'de f-string ifadelerini temsil eder.

Örneğin:

```python
query = f"SELECT ... {username}"
```

CodeXray bunu taint propagation için ayrıca analiz eder.

## Finding

CodeXray'in bir güvenlik problemi tespit ettiğinde oluşturduğu bulgu.

Bir finding şu bilgileri içerebilir:

- rule
- CWE
- severity
- message
- path
- line number

## CWE

**Common Weakness Enumeration**

Yazılım güvenlik zafiyetlerini standart kimliklerle sınıflandıran sistem.

Örnek:

```text
CWE-89 → SQL Injection
```

## False Positive

Kodun aslında güvenli olmasına rağmen aracın güvenlik açığı bildirmesi.

## False Negative

Kodda gerçek bir güvenlik açığı bulunmasına rağmen aracın bunu tespit edememesi.

## Type Inference

Kodda kullanılan nesnelerin gerçek türlerini analiz ederek hangi metodun veya işlemin çağrıldığını belirleme yaklaşımı.

CodeXray MVP'sinde tam type inference yoktur.

## Control-Flow Analysis

Programın farklı koşul ve branch yollarını modelleyerek veri akışını analiz etme yaklaşımı.

CodeXray MVP'sinde henüz uygulanmamıştır.

## Provenance

Bir tainted değerin hangi source'tan geldiğine ilişkin geçmiş bilgi.

CodeXray mevcut MVP'de tekil/primary source yaklaşımı kullanır.

## Structural Rule

Taint propagation gerektirmeden AST yapısına bakarak belirli bir güvenlik kalıbını kontrol eden rule türü.

## Presence Check

Belirli bir güvenlik kontrolünün veya korumanın bulunup bulunmadığını kontrol eden rule türü.

## Dependency Check

Kullanılan bağımlılıkların bilinen güvenlik zafiyetleri açısından kontrol edilmesi.

## LLM Triage

Tespit motorunun ürettiği bir finding'i ikinci görüş, açıklama veya önceliklendirme amacıyla bir LLM'e değerlendirtmek.

CodeXray'de LLM'in temel detection engine olması planlanmamaktadır.
