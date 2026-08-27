# Proje Bağlamı

## Bu proje ne, neden yapılıyor

Bilişim güvenliği stajı kapsamında geliştirilen bir mini SAST (statik
uygulama güvenlik testi) aracı. Önceden 15 güvenlik zafiyeti kategorisi
(OWASP Top 10 + tipik SAST araçlarının bulgu kategorileri) kavramsal
olarak çalışılmıştı; bu proje o kavramları **gerçekten tespit eden bir
sistem** haline getiriyor.

Konumlandırma: ticari araçların (Semgrep, Checkmarx, Snyk) yerini almak
değil, onların çalışma prensibini (özellikle taint tracking) küçük
ölçekte, savunulabilir şekilde yeniden inşa etmek. Gerçek dünya emsali:
Python'un kendi SAST aracı **Bandit** ve akademik taint-tracking aracı
**PyT**.

## Kapsam

**MVP çekirdek kategoriler (8):**
- Taint tracking ile: SQL Injection, XSS, Path Manipulation, Sensitive
  Data Exposure
- AST yapısal kontrol ile: Empty Catch Block, Insecure Randomness,
  Hardcoded Password / Password in Command
- Yokluk kontrolü ile: CSRF

**Bonus:** Using Components with Known Vulnerabilities (`pip-audit` /
OSV.dev orkestrasyonu — kendi tespit mantığı gerekmiyor)

**Kapsam dışı (MVP için):** Broken Authentication, Broken Access
Control (IDOR — stretch goal), Security Misconfiguration, XXE,
Insufficient Logging/Monitoring, HTTP Header Manipulation.

**MVP sınırı: intra-procedural.** Fonksiyonlar arası taint propagation
(call graph, parametre/return takibi) bilinçli olarak v0.2'ye
bırakıldı — kapsamı bir program analiz framework'üne büyütmemek için.

## Mimari (özet)

İki katman:
1. **Çekirdek — taint tracking motoru:** AST parse → kural motoru
   (source/sanitizer/sink sınıflandırması) → propagation → bulgu.
   Detay için bkz. `architecture.md`.
2. **Bonus — LLM triage:** kural motorunun bulduğu her sonucu ikinci
   kez değerlendirip yanlış pozitifleri azaltan, insan diline çeviren
   bir katman. Tespit motoru değil, sadece triage.

Kural/traversal ayrımı mimarinin en önemli kararı: `taint_engine.py`
hiçbir kurala özgü mantık içermez, her şey `rules/` altındaki `Rule`
tanımlarından gelir. Yeni kategori eklemek çekirdeğe dokunmadan
yapılabilir.

## Şimdiye kadar alınmış önemli kararlar

Bkz. `design-decisions.md` — kronolojik karar günlüğü.

## Bilinen sınırlamalar

- Qualified-name eşleştirme tam type inference değil (bkz. `AGENTS.md`)
- Intra-procedural sınır bilinçli bir bilgi kaybı yaratıyor (v0.2'ye
  kadar)
- `_check_sinks()`'in sanitizer-set eşleştirmesi fazla katı olabilir
  (bkz. `AGENTS.md` — bilinen tasarım borcu)

## Roadmap

Bkz. `roadmap.md`.
