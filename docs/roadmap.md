# Roadmap

```
M0  Proje fikri
     |
M1  Mimari / kapsam
     |
M2  Rule model
     |
M3  TaintState + traversal              <-- TAMAMLANDI (calisiyor, test edildi)
     |
M4  SQL Injection saglamlastirma        <-- TAMAMLANDI (packaging fix, sink semantigi, birim testler)
     |
M5  XSS (ayni motor uzerinde)           <-- TAMAMLANDI
     |
M5.1 Generic call-return propagation     <-- TAMAMLANDI
M5.5 Shared call-argument binding        <-- TAMAMLANDI
     |   + parameter modeli
M5.6 Traversal statement kapsami         <-- TAMAMLANDI
M5.7 BoolOp / IfExp propagation          <-- TAMAMLANDI
M5.8 Receiver analizi + propagation      <-- TAMAMLANDI
     |
M5.9 Statement header slotlari           <-- TAMAMLANDI
     |   (if / while test, for iter, with context)
     |
M5.10 Variadic argument model            <-- TAMAMLANDI
     |   (os.path.join, tpl.format - keyfi sayida arguman)
     |
CLI  Calistirilabilir tarayici           <-- TAMAMLANDI
     |   (motorun ilk uctan uca kullanimi)
     |
M6  Path Manipulation                     <-- TAMAMLANDI
     |
M7  Sensitive Data Exposure               <-- TAMAMLANDI
     |   (ilk farkli source ailesi -- genellenebilirligin asil sinavi)
     |
M11a Triage denemesi (kucuk olcek)        <-- next
     |   (kategori sayisindan bagimsiz, yukari cekildi)
     |
M8d Ikinci kural sekli tasarim karari
     |   (ast-structural + presence-check mevcut Rule semasina sigmiyor)
     |
M8  AST-structural kurallar
     |   (Empty Catch Block, Insecure Randomness, Hardcoded Password)
     |
M9  Presence-check (CSRF)
     |
M10 Bonus: dependency check (pip-audit / OSV.dev)
     |
M11 Bonus: LLM triage katmani (tam)
     |
M12 CI entegrasyonu                      <-- .github/workflows/ci.yml ile TAMAMLANDI
```

## Neden bu sıra

SQL Injection pilot kural: source/sanitizer/sink/TaintState/propagation/
Finding/CWE mekanizmasının tamamı önce tek, gerçek bir vaka üzerinde
oturtuluyor. M4 tamamlanmadan (motor + SQL Injection uçtan uca sağlam
çalışmadan) M5'e geçilmeyecek — amaç "8 zafiyeti yüzeysel yakalayan
araç" değil, "gerçek bir motor + o motorun genellenebilir olduğunu
kanıtlayan birkaç kategori" olması.

Taint gerektiren kategoriler (M4–M7) taint gerektirmeyenlerden
(M8–M9) önce geliyor çünkü motorun asıl değeri veri akışı takibi —
bu önce sağlamlaştırılıyor.

## M5.1-M5.8 neden araya girdi

M4'ün kapısı ("motor uçtan uca sağlam çalışmadan bir sonraki kategoriye
geçilmez") kategori #3'ten önce tekrar uygulandı. Motor borçlarının maliyeti
kural sayısıyla artıyor: kural eklemeden önce düzeltmek bir dosyaya, sonra
düzeltmek her kurala dokunmak demek.

- **Parameter modeli (M5.5):** her yeni kural belirsiz selector sözdizimini
  kopyalayacaktı.
- **Traversal statement kapsamı (M5.6):** `return Response(tainted)` hiç
  analiz edilmiyordu; `visit_Return` bunu kapattı.

### Düzeltme: bu bölümün önceki hali yanlıştı

Bu bölüm daha önce M5.6'yı "Return sink abstraction" olarak adlandırıyor ve
gerekçe olarak `return Response(tainted)` → 0 bulgu ölçümünü gösteriyordu.
İki hata vardı:

1. **Numara çakışması.** `current-state.md` M5.6'yı traversal statement
   kapsamı için kullanıyordu; roadmap aynı numarayı başka bir işe veriyordu.
   Yukarıdaki şema artık `current-state.md`'nin numaralarını kullanıyor.
2. **Bayat ölçüm.** `return Response(tainted)` M5.6 ile kapandı (bugün
   ölçüldü: 1 bulgu), gerekçe uygulamadan sonra güncellenmedi. Kalan gerçek
   boşluk çıplak `return tainted`: tainted bir dönüş değerini generic sink
   sayan abstraction hâlâ yok (ölçüldü: 0 bulgu) ve açık tasarım borcunda
   "Return sink abstraction yok" olarak duruyor.

## Dört strateji kararı (M5.10 sonrası)

İki koordinatör bağımsız olarak aynı dört boşluğu tespit etti. Karara
bağlandılar ve sıra buna göre değişti.

### 1. Kapının durma koşulu

"Motor sağlam olmadan kategori eklenmez" kuralı M4'te doğruydu ama
sonlandırılabilir değildi: `analyze_expression` bilinmeyen düğüme `CLEAN`
döndüğü sürece her zaman bir sonraki boşluk bulunur. M5.1'den M5.10'a on
alt-milestone, sıfır yeni kategori.

**Eşik:** bir motor boşluğu, ancak bir kategorinin **amiral kalıbını**
kaçırtıyorsa o kategoriyi bloklar.

`with open(...)` M6'nın amiral kalıbıydı, M5.9'u haklı çıkardı.
`os.path.join(...)` aynı şekilde M5.10'u. `UnaryOp`, walrus, lambda gövdesi,
subscript slice ve literal receiver bu eşiği geçmez — kategorilerden sonra
ele alınırlar.

Reddedilen alternatif: "yeni kategori sıfır motor değişikliği gerektiriyorsa
motor sağlamdır." Global bir test ve zaten sağlanıyor (M5.10 `taint_engine.py`
değişmeden geçti), dolayısıyla tüm motor işini anında keserdi — fazla kör.

### 2. CLI M6'dan önce

Bugün CodeXray'i bir insan çalıştıramıyor: `TaintAnalyzer` ve `RuleEngine`
elle kurulup `visit()` çağrılması gerekiyor. Roadmap'te M0–M12 vardı ve CLI
hiçbirinde yoktu — "Not Implemented Yet" listesinin ilk satırıydı ama
milestone'u yoktu.

Motorun kalitesi, gösterilebilirliğinin çok önünde. CLI ayrıca motorun uçtan
uca gerçekten çalıştığını ilk kez test edecek; şimdiye kadar yalnızca birim
testleriyle doğrulandı.

### 3. İkinci kural şekli — şimdi kayda geç, M7'den sonra tasarla

`Rule` = `sources` + `sanitizers` + `sinks`, yani taint şekli. Empty Catch
Block yapısal bir kontrol, CSRF bir yokluk kontrolü; ikisi de bu şemaya
girmiyor.

`architecture.md` üç motor tipini ve registry desenini zaten tanımlıyor,
yani mimari niyet var. Eksik olan bir tasarım kararı ve bir milestone.

M6 ve M7 taint kategorileri olduğu için bu boşluk onları **bloklamıyor**.
Ama M8'de pusuya düşmemek için sıraya `M8d` olarak açıkça eklendi —
M5.5'i haklı çıkaran argümanın aynısı, daha büyük ölçekte.

### 4. Triage yukarı çekildi

M11 listenin sonundaydı; zaman biterse ilk düşecek olan oydu. Triage katmanı
kategori sayısından bağımsız çalışır — sekiz kategori beklemesine gerek yok.
CLI ve M6'dan sonra küçük ölçekli bir deneme (`M11a`) eklendi; tam katman
yerinde kaldı.

### Yeni sıra

    CLI -> M6 -> M7 -> M11a -> M8d -> M8 -> M9 -> M10 -> M11

## M5.9 / M5.10 neden M6'dan önce

Aynı kapı, aynı gerekçe. İkisi de ölçülerek seçildi:

- **Statement header slotları (M5.9):** `with open(kirli) as f:` bugün 0 bulgu
  üretiyor. Gövdeler `generic_visit()` ile zaten geziliyor; kör olan yalnızca
  başlık ifadeleri — `if`/`while` test'i, `for` iter'i, `with` context'i.
  `with open(...)` Path Manipulation'ın en yaygın yazımı olduğu için M6'nın ön
  koşulu. Aynı körlük SQL tarafını da etkiliyor: `for row in
  cursor.execute(q):` de 0 bulgu.
- **Variadic argument model (M5.10):** `os.path.join("/base", kirli)` 0 bulgu.
  Path Manipulation'ın kanonik kompozisyon kalıbı. Kazanç, keyfi sayıda
  argüman üzerinde **pozisyondan bağımsız** taint: `os.path.join(kirli, "a", "b")`
  da `os.path.join("/b", kirli)` da tek bir tanımla kapanır. Aynı abstraction
  `tpl.format("s", kirli)` üzerinden bir SQLi kalıbını da kapatıyor.

`join` bu listede **değil**. Ölçüldü: `join` tam olarak tek argüman alır (bir
iterable), dolayısıyla boşluğu variadic arity değil konteyner-vs-eleman
semantiğidir. `sep.join(kirli_string)` düz bir `CallModel` ile kapanır;
`sep.join([kirli])` ve `sep.join(parts)` variadic ile de kapanmaz.

`"SELECT {}".format(kirli)` bu ikisinin dışında kalıyor: literal receiver'ın
nitelikli adı olmadığı için (`resolve_qualified_name` → `None`) hiçbir modele
ya da kurala ulaşmıyor. Shape-based matching ayrı bir tasarım kararıdır ve
bilinçli olarak ertelendi — bkz. `design-decisions.md` → "Literal receivers
cannot be matched".

M6+ numaraları bilinçli olarak değiştirilmedi.
