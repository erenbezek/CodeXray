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
M5  XSS (ayni motor uzerinde)           <-- next
     |
M6  Path Manipulation
     |
M7  Sensitive Data Exposure
     |
M8  AST-structural kurallar
     |   (Empty Catch Block, Insecure Randomness, Hardcoded Password)
     |
M9  Presence-check (CSRF)
     |
M10 Bonus: dependency check (pip-audit / OSV.dev)
     |
M11 Bonus: LLM triage katmani
     |
M12 CI entegrasyonu (GitHub Actions)
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
