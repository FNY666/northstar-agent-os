# Northstar Agent OS

**Offene, zuverlässige und gesteuerte Runtime-Komponenten für autonome KI-Kollegen.**

[English](../README.md) · [简体中文](README.zh-CN.md) · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · [Español](README.es.md) · [한국어](README.ko.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · [Português (Brasil)](README.pt-BR.md) · [Italiano](README.it.md) · [Türkçe](README.tr.md) · [Tiếng Việt](README.vi.md)

**In einem Satz:** Northstar ist ein unabhängig gepflegtes Projekt zum Aufbau gesteuerter KI-Kollegen aus explizitem Model-Routing, lokalen Tool-Grenzen, Auditierbarkeit und wiederherstellbarer Ausführung. **Die heute veröffentlichte Komponente ist Northstar Codex Sidecar, ein eingeschränkter lokaler Worker-Adapter — keine vollständige Plattform für autonome Agenten.**

> English is the canonical project entry. Translations mirror its scope and security claims; update them when the canonical README changes.

## Was ist es?

Northstar ist ein komponentenorientiertes Runtime-Projekt für Entwickler, die möchten, dass KI-Kollegen mit sichtbaren Grenzen arbeiten, statt in einer uneingeschränkten Prompt-und-Tool-Schleife. Im Mittelpunkt stehen kleine, testbare Bausteine: ein für den Aufrufer sichtbarer Vertrag, begrenzte Ausführung, strukturierte Ergebnisse und betriebliche Wiederherstellung.

Das Projekt wird schrittweise aufgebaut. Eine einzelne Komponente kann nützlich sein, aber bestandene Komponententests beweisen weder die Sicherheit einer vollständigen Agentenplattform noch deren Produktionsreife.

## Was ist heute enthalten?

- `../components/northstar-codex-sidecar/` — ein lokaler Unix-Socket-Dienst, der Anfragen prüft, Codex im read-only-Modus ausführt, Ein- und Ausgabe begrenzt, Fehler bereinigt, abgelaufene Prozessgruppen aufräumt und strukturierte Statuswerte zurückgibt.
- Deterministische Tests, systemd-Hardening-Vorlage, konservatives Installationsskript und Rollback-Skript.

## Wie funktioniert das Sidecar?

Pro Unix-Socket-Verbindung wird genau eine JSON-Anfrage akzeptiert:

```json
{"request_id":"demo-1","prompt":"Reply with OK","timeout_ms":10000}
```

Die Antwort ist ein begrenztes JSON-Objekt:

```json
{"request_id":"demo-1","status":"ok","text":"OK"}
```

Wichtige Eigenschaften:

- Nur Unix-Socket; kein TCP-Listener.
- Strikte Allowlist: `request_id`, `prompt`, `timeout_ms`.
- Grenzen für Prompt und Timeout.
- Codex läuft mit `--sandbox read-only` und `--ephemeral`.
- Eigene Prozessgruppe, bei Timeout mit TERM und danach KILL bereinigt.
- Lese-Deadline pro Verbindung und begrenzter Worker-Pool.
- Strukturierte Fehlerklassen und Geheimnis-Redaktion.
- Dedizierter Dienstbenutzer und systemd-Hardening-Vorlage.
- Codex bleibt deaktiviert, bis ein Administrator den Dienst ausdrücklich installiert und aktiviert.

## Schnellstart

Voraussetzungen: Linux, Python 3.10 oder neuer, eine separat installierte und für den Dienstbenutzer verfügbare `codex`-Datei, systemd sowie ein dedizierter unprivilegierter Dienstbenutzer und Workspace.

```sh
cd components/northstar-codex-sidecar
python3 -m py_compile sidecar.py transport.py service.py sidecar_socket.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
sh -n install.sh rollback.sh
```

Prüfe Skripte und Dienstkonto, bevor du den konservativen Lebenszyklus aktivierst:

```sh
sudo ./install.sh
sudo systemctl enable --now northstar-codex-sidecar.service
```

Die Codex-Datei wird standardmäßig über `PATH` gefunden; für einen nicht standardmäßigen Pfad `CODEX_BIN` setzen.

## Für wen ist es gedacht?

Northstar richtet sich an Entwickler und Betreiber lokaler oder self-hosted KI-Kollegen-Runtimes, die eine eng begrenzte, testbare, auditierbare, deaktivierbare und rücksetzbare Ausführungskomponente benötigen. Es ist kein gehostetes KI-Produkt, keine automatische Sicherheitsgarantie und kein Ersatz für eine vollständige Identitäts-, Policy-, Workspace- und Observability-Architektur.

## Was ist es nicht?

- Noch kein vollständiges Multi-Agent-Betriebssystem.
- Kein gehosteter Dienst und kein Versprechen der Produktionsreife.
- Keine allgemeine Shell-Ausführungs-API.
- Autorisiert Aufrufer nicht selbst, isoliert nicht jede Ausführung und propagiert die Abbruchanforderung des Elternprozesses nicht automatisch.
- Enthält keine Codex-Zugangsdaten und stellt kein Codex-Konto bereit.

**Not a complete autonomous-agent platform.**

## Beziehung zu OpenBot

Northstar ist ein unabhängiges Projekt für OpenBot-kompatible Integrationen. Es ist nicht mit OpenBot, CopilotKit oder deren Maintainer verbunden und wird von ihnen nicht empfohlen oder offiziell unterstützt. Das Sidecar kann in OpenBot-ähnliche Runtimes integriert werden, ohne zu behaupten, Teil des Upstream-OpenBot-Repositories zu sein.

Kompatibilität bezeichnet ein Integrationsziel, nicht Eigentum, Empfehlung oder Sicherheitsgleichheit.

## Sicherheitsgrenze

Das Sidecar authentifiziert Aufrufer ausschließlich über Unix-Berechtigungen. Eine Produktionsintegration muss zusätzlich Aufruferautorisierung und Identitätsbindung, Workspace-Isolation pro Run oder Actor, Abbruchweiterleitung, Observability ohne sensible Prompts zu protokollieren, Health Checks und Rollback, native Linux-Verifikation von Nebenläufigkeit und Prozessbaum sowie eine Prüfung der Codex-Konto-, Netzwerk- und Tool-Konfiguration bereitstellen.

Den Unix-Socket nicht über einen TCP-Proxy exponieren. Niemals API-Keys, OAuth-Tokens, Codex-Loginstatus, private Schlüssel, Produktions-`.env`-Dateien oder Benutzertranskripte committen.

## Projektstatus

Dies ist die erste öffentliche Northstar-Komponente. Die umfassendere Northstar-Agent-OS-Runtime wird schrittweise entwickelt. Identitätsbindung, Workspace-Autorisierung pro Run, Abbruchweiterleitung, native Linux-End-to-End-Verifikation und Produktionsdeployment bleiben Host-Verantwortung oder zukünftige Arbeit. **Dieses Repository ist keine vollständige Plattform für autonome Agenten.**

Die Bereinigung von Prozessgruppen muss auf der vorgesehenen nativen Linux-Distribution validiert werden; Signal- und PID-Reaping-Verhalten in mobilem Linux ist möglicherweise nicht repräsentativ.

## Beiträge und Pflege

Siehe [CONTRIBUTING.md](../CONTRIBUTING.md) für Erwartungen an Nachweise, Tests, Sicherheit, Kompatibilität und Rollback. Sicherheitsmeldungen: [SECURITY.md](../SECURITY.md). English is the canonical source for project scope; translations should be updated when it changes.

## Lizenz

MIT. Siehe [LICENSE](../LICENSE).
