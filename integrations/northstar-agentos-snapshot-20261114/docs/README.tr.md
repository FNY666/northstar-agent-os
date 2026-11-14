# Northstar Agent OS

**Açık, güvenilir ve yönetişimli otonom yapay zekâ çalışma arkadaşı runtime bileşenleri.**

[English](../README.md) · [简体中文](README.zh-CN.md) · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · [Español](README.es.md) · [한국어](README.ko.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · [Português (Brasil)](README.pt-BR.md) · [Italiano](README.it.md) · [Türkçe](README.tr.md) · [Tiếng Việt](README.vi.md)

**Tek cümleyle:** Northstar; açık model yönlendirmesi, yerel araç sınırları, denetlenebilirlik ve kurtarılabilir yürütme kullanarak yönetişimli yapay zekâ çalışma arkadaşları oluşturmak için bağımsız olarak sürdürülen bir projedir. **Bugün yayımlanan bileşen, sınırlı bir yerel worker adaptörü olan Northstar Codex Sidecar’dır; tamamlanmış bir otonom ajan platformu değildir.**

> English is the canonical project entry. Translations mirror its scope and security claims; update them when the canonical README changes.

## Nedir?

Northstar, yapay zekâ çalışma arkadaşlarının sınırsız prompt ve araç döngüsü yerine görünür sınırlar içinde çalışmasını isteyen geliştiriciler için bileşen odaklı bir runtime projesidir. Çağıran tarafından görülebilen sözleşme, kısıtlı yürütme, yapılandırılmış sonuçlar ve operasyonel kurtarma gibi küçük ve test edilebilir yapı taşlarına odaklanır.

Proje artımlı olarak geliştirilmektedir. Tek bir bileşen kendi başına yararlı olabilir; ancak testlerin geçmesi, eksiksiz bir ajan platformunun güvenli veya üretime hazır olduğunu kanıtlamaz.

## Bugün ne yayımlandı?

- `../components/northstar-codex-sidecar/` — istekleri doğrulayan, Codex’i read-only modunda çalıştıran, girdiyi ve çıktıyı sınırlayan, hataları temizleyen, zaman aşımına uğrayan süreç gruplarını sonlandıran ve yapılandırılmış durumlar döndüren yerel Unix socket servisi.
- Deterministik testler, systemd hardening şablonu, temkinli kurulum betiği ve rollback betiği.

## Sidecar nasıl çalışır?

Her Unix socket bağlantısı için tek bir JSON isteği kabul edilir:

```json
{"request_id":"demo-1","prompt":"Reply with OK","timeout_ms":10000}
```

Yanıt, sınırlandırılmış tek bir JSON nesnesidir:

```json
{"request_id":"demo-1","status":"ok","text":"OK"}
```

Önemli özellikler:

- Yalnızca Unix socket; TCP listener yoktur.
- Katı istek allowlist’i: `request_id`, `prompt`, `timeout_ms`.
- Prompt ve timeout sınırları.
- Codex `--sandbox read-only` ve `--ephemeral` ile çalışır.
- Ayrı süreç grubu; timeout durumunda önce TERM, sonra KILL ile temizlenir.
- Bağlantı başına okuma süresi ve sınırlı worker pool.
- Yapılandırılmış hata sınıfları ve sır redaction’ı.
- Özel servis kullanıcısı ve systemd hardening şablonu.
- Codex, yönetici hizmeti açıkça kurup etkinleştirene kadar devre dışıdır.

## Hızlı başlangıç

Gereksinimler: Linux, Python 3.10 veya üzeri, servis kullanıcısının erişebildiği ayrı kurulmuş bir `codex` çalıştırılabilir dosyası, systemd ve özel ayrıcalıksız servis kullanıcısı/workspace.

```sh
cd components/northstar-codex-sidecar
python3 -m py_compile sidecar.py transport.py service.py sidecar_socket.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
sh -n install.sh rollback.sh
```

Etkinleştirmeden önce betikleri ve servis hesabını inceleyin:

```sh
sudo ./install.sh
sudo systemctl enable --now northstar-codex-sidecar.service
```

Codex çalıştırılabilir dosyası varsayılan olarak `PATH` içinden bulunur; standart olmayan bir yol için `CODEX_BIN` ayarlayın.

## Kimler için?

Northstar, test edilebilir, denetlenebilir, devre dışı bırakılabilir ve geri alınabilir dar kapsamlı bir yürütme bileşenine ihtiyaç duyan yerel veya self-hosted AI çalışma arkadaşı runtime geliştiricileri ve operatörleri içindir. Barındırılan bir AI ürünü, otomatik güvenlik garantisi veya kimlik, politika, workspace ve gözlemlenebilirlik mimarisinin yerine geçen bir çözüm değildir.

## Ne değildir?

- Henüz eksiksiz bir multi-agent işletim sistemi değildir.
- Barındırılan bir servis veya üretime hazır olma sözü değildir.
- Genel amaçlı bir shell yürütme API’si değildir.
- Çağıranları kendisi yetkilendirmez, her çalıştırmayı izole etmez ve üst süreç iptalini kendiliğinden iletmez.
- Codex kimlik bilgilerini içermez ve Codex hesabı sağlamaz.

**Not a complete autonomous-agent platform.**

## OpenBot ile ilişkisi

Northstar bağımsız bir projedir ve OpenBot uyumlu entegrasyonları hedefler. OpenBot, CopilotKit veya bakımcılarıyla bağlantılı değildir ve onlar tarafından onaylanmamıştır. Sidecar, OpenBot tarzı runtime’lara entegre olabilir; ancak upstream OpenBot deposunun parçası olduğunu iddia etmez.

Uyumluluk, sahiplik, onay veya güvenlik eşdeğerliği değil, entegrasyon hedefidir.

## Güvenlik sınırı

Sidecar çağıranları yalnızca Unix izinleriyle doğrular. Üretim entegrasyonu ayrıca çağıran yetkilendirmesi ve kimlik bağlama, run veya actor başına workspace izolasyonu, üst süreç iptalinin iletilmesi, hassas prompt kaydı yapmayan gözlemlenebilirlik, health check ve rollback, native Linux eşzamanlılık/süreç ağacı doğrulaması ve Codex hesap/ağ/araç yapılandırmasının incelemesini sağlamalıdır.

Unix socket’i TCP proxy üzerinden açmayın. API key, OAuth token, Codex login durumu, private key, üretim `.env` dosyası veya kullanıcı transcript’i commit etmeyin.

## Proje durumu

Bu, Northstar’ın ilk açık bileşenidir. Daha geniş Northstar Agent OS runtime’ı artımlı olarak geliştirilmektedir. Runtime kimlik bağlama, run başına workspace yetkilendirmesi, iptal iletimi, native Linux uçtan uca doğrulama ve üretim dağıtım entegrasyonu host sorumluluğu veya gelecekteki çalışmalardır. **Bu depo eksiksiz bir otonom ajan platformu değildir.**

Süreç grubu temizliği hedef native Linux dağıtımında doğrulanmalıdır; mobil Linux’taki sinyal ve PID toplama davranışı temsil edici olmayabilir.

## Katkı ve bakım

Kanıt, test, güvenlik, uyumluluk ve rollback beklentileri için [CONTRIBUTING.md](../CONTRIBUTING.md) dosyasına bakın. Güvenlik raporları için [SECURITY.md](../SECURITY.md) dosyasına bakın. English is the canonical source for project scope; translations should be updated when it changes.

## Lisans

MIT. Bkz. [LICENSE](../LICENSE).
