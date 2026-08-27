# Tasarım Kararları

Kronolojik karar günlüğü — "neden böyle" sorusuna cevap vermek için.

## Proje kapsamı: mini SAST + taint tracking

Sadece terim ezberlemek değil, terimleri tespit eden bir sistem
kurulması hedeflendi. Kapsam bilerek geniş değil (15 kategorinin
hepsi değil) — kalite, kapsamdan önceliklendirildi.

## LLM katmanı: triage, tespit motoru değil

Kendi ML modelini sıfırdan eğitmek reddedildi — yeterli etiketli veri
seti toplamak süre kısıtında gerçekçi değil ve sonucu muhtemelen
taint tracking'ten daha zayıf olurdu. Bunun yerine: kural motorunun
bulduğu sonuçları ikinci kez değerlendiren, yanlış pozitifleri azaltan
ve insan diline çeviren bir LLM triage katmanı (bonus, tespit motoru
değil) tercih edildi.

## Dil: Node.js → Python

İlk tasarım Node.js/Babel üzerineydi. Python'a geçildi çünkü: (1) en
akıcı olunan dil Python, Node'da akıcılık yok; (2) Python'un `ast`
modülü standart kütüphanede yerleşik, harici parser gerekmiyor; (3)
gerçek dünya emsali güçlü — Bandit, PyT. Önceden tasarlanan
`TaintState`/source-sanitizer-sink modeli dilden bağımsız olduğu için
geçişte kayıp olmadı.

## MVP kapsamı: intra-procedural

Fonksiyonlar arası taint propagation (call graph, parametre/return
takibi, recursive call'lar, aliasing) MVP'ye dahil edilmedi — bunu
eklemek taint motoru geliştirmekten çok mini bir program analiz
framework'ü geliştirmeye dönüşürdü. v0.2'ye bırakıldı, MVP'de bilinen
ve dokümante edilen bir bilgi kaybı olarak kabul edildi.

## TaintState modeli: sadece bool değil, zengin state

`Set<string>` (kirli değişkenler kümesi) yerine zenginleştirilmiş bir
`TaintState` (source, path, kind, sanitized_for alanlarıyla) tercih
edildi — bu sayede bulgu raporunda tam veri akışı izi gösterilebiliyor
(`request.args → username → query → cursor.execute`), sadece "tehlikeli"
denmiyor.

`TaintState` immutable (`frozen=True`) — `b = a` sonrası `b` üzerinde
yapılan bir değişikliğin `a`'yı etkilememesi için.

## `sanitized ≠ clean`

Bir SQL sanitizer'ından geçen değer otomatik olarak HTML için de güvenli
sayılmamalı. Bu yüzden `sanitized_for` tek bir boolean değil, bir küme
(`tuple[str, ...]`) — hangi bağlamlar için güvenli olduğu ayrı ayrı
tutuluyor.

`merge_states()`'te (BinOp/JoinedStr birleştirme) `sanitized_for` için
**kesişim** alınıyor, union değil — bir ifadenin bir parçası sql için
temiz, diğer parçası değilse, sonucu yanlışlıkla güvenli saymamak için.

## Eşleştirme: qualified-name, regex değil

`sources`/`sanitizers`/`sinks` listelerini regex string'leri haline
getirmek bilinçli olarak reddedildi — bu, taint motorunu giderek bir
"regex eşleştirme motoru"na dönüştürür ve projenin asıl değerini
(veri akışını gerçekten anlamak) sulandırır. Bunun yerine
`resolve_qualified_name()` AST üzerinde `Attribute`/`Name`/`Call`/
`Subscript` zincirini gezip `"cursor.execute"` gibi bir string'e
çeviriyor, kural bu string'le karşılaştırılıyor.

Kabul edilen sınır: bu tam type inference değil — farklı bir sınıfın
aynı isimli metodu (`execute`) yanlışlıkla eşleşebilir. `module` alanı
ileride bu ayrımı güçlendirmek için şemada zaten duruyor.

## Kural / traversal ayrımı

`RuleEngine` ile traversal (`taint_engine.py`) kesin olarak ayrıldı.
Traversal hiçbir zaman "if function_name == 'execute'" gibi kurala özgü
kod içermeyecek — sadece `RuleEngine.classify(node)`'a soruyor. Yeni
kategori eklemek `rules/` altına yeni bir dosya eklemek demek.
`RuleMatch` (rule + role + pattern) döndürülüyor, çıplak tuple değil —
çünkü sink/sanitizer tarafında pattern'in kendi alanlarına (
`dangerous_arguments`, `sanitizes_for`) tekrar erişim gerekiyor.

## Python'a özgü not: f-string'ler ayrı ele alınmalı

JS'de string concatenation (`+`) taint propagation'ın ana kaynağıyken,
Python'da SQL injection'ın en yaygın kaynağı f-string'ler
(`f"...{username}..."`). AST'de bunlar `BinOp` değil, ayrı bir düğüm
tipi olan `JoinedStr`. Motor her ikisini de (`_analyze_BinOp` ve
`_analyze_JoinedStr`) ayrı ayrı destekliyor.

## M3 sonrası repo review'da bulunan ve düzeltilen sorunlar

**Test altyapısı: temiz checkout'ta `pytest` başarısız oluyordu.**
`src/` layout kullanılıyor ama pytest bunu otomatik path'e eklemiyordu;
`tests/conftest.py`'deki manuel `sys.path` hack'i de sadece repo kökünü
(`rules/` için) ekliyordu, `src/`'i değil. Bağımsız olarak reprodüklendi
(`pip install` yapılmadan `ModuleNotFoundError: No module named
'codexray'`). Çözüm: `pyproject.toml`'a
`[tool.pytest.ini_options] pythonpath = ["src", "."]` eklendi,
`conftest.py` kaldırıldı — artık `git clone && pytest` kurulum
gerektirmeden çalışıyor.

**Sink sanitizer eşleşmesi: rule-wide union yerine pattern-level.**
`_check_sinks()` önceden bir rule'daki TÜM sanitizer'ların
`sanitizes_for` birleşimini zorunlu kılıyordu (`sql` VE `html` gibi).
Bir rule'da birden fazla, farklı bağlamlar için sanitizer olduğunda bu
yanlış bir soyutlamaydı. Çözüm: `SinkPattern`'e
`requires_sanitization_for` alanı eklendi — her sink kendi kabul ettiği
kategorileri açıkça tanımlıyor, rule'un diğer sanitizer'larından
etkilenmiyor.

**Test kapsamı genişletildi.** Önceki tek entegrasyon testine
(vulnerable/safe örnek dosyaları üzerinden) ek olarak birim seviyesinde
`test_rule_model.py` (RuleEngine.classify) ve `test_taint_engine.py`
(source, çok-adımlı propagation, BinOp, JoinedStr, sanitizer'ın
`sanitized_for` içeriğini doğrulayan test, sink, temiz/bilinmeyen
değer) eklendi.

## Açık tasarım borcu (bilinçli olarak ertelendi)

- **Multi-source provenance yok** — `merge_states()` birden fazla
  tainted parçayı birleştirirken source/kind bilgisini ilk parçadan
  alıyor, ikinci bir source varsa kaybediyor.
- **`analyze_expression` fallback'i CLEAN, UNKNOWN değil** —
  desteklenmeyen bir AST düğümü "bilmiyorum" yerine "temiz" sayılıyor,
  false negative riski var.
- **Control flow modellenmiyor** — `if`/`try`/`except` dallanmaları
  taint durumunu etkilemiyor, motor sıralı kod varsayıyor.

Üçü de MVP kapsamını bilinçli olarak küçük tutmak için şimdilik
ertelendi (bkz. `AGENTS.md`).
