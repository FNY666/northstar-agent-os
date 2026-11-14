# Northstar Agent OS

**Componentes de runtime abiertos, fiables y gobernados para compañeros de IA autónomos.**

[English](../README.md) · [简体中文](README.zh-CN.md) · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · [Español](README.es.md) · [한국어](README.ko.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · [Português (Brasil)](README.pt-BR.md) · [Italiano](README.it.md) · [Türkçe](README.tr.md) · [Tiếng Việt](README.vi.md)

**En una frase:** Northstar es un proyecto independiente para ensamblar compañeros de IA gobernados mediante enrutamiento explícito de modelos, límites de herramientas locales, auditabilidad y ejecución recuperable. **El componente publicado hoy es Northstar Codex Sidecar, un adaptador local restringido para workers; no es una plataforma completa de agentes autónomos.**

> English is the canonical project entry. Translations mirror its scope and security claims; update them when the canonical README changes.

## Qué es

Northstar es un proyecto de runtime orientado a componentes para desarrolladores que quieren que sus compañeros de IA operen con límites visibles, en lugar de depender de un ciclo sin restricciones de prompt y herramientas. Se centra en bloques pequeños y comprobables: un contrato visible para el llamador, ejecución restringida, resultados estructurados y recuperación operativa.

El proyecto se construye de forma incremental. Un componente puede ser útil por sí solo, pero que sus pruebas pasen no demuestra que una plataforma completa de agentes sea segura o esté lista para producción.

## Qué se publica hoy

Este repositorio publica actualmente un componente:

- `../components/northstar-codex-sidecar/` — servicio local mediante Unix socket que valida solicitudes, ejecuta Codex en modo read-only, limita entrada y salida, redacta errores, limpia grupos de procesos agotados por timeout y devuelve estados estructurados.
- Pruebas deterministas, plantilla de hardening para systemd, instalador conservador y script de rollback.

## Cómo funciona el Sidecar

Se acepta una solicitud JSON por cada conexión Unix socket:

```json
{"request_id":"demo-1","prompt":"Reply with OK","timeout_ms":10000}
```

La respuesta es un objeto JSON acotado:

```json
{"request_id":"demo-1","status":"ok","text":"OK"}
```

Propiedades importantes:

- Solo Unix socket; no existe listener TCP.
- Lista estricta de campos: `request_id`, `prompt` y `timeout_ms`.
- Límites para prompt y timeout.
- Codex se ejecuta con `--sandbox read-only` y `--ephemeral`.
- Grupo de procesos separado, limpiado con TERM y después KILL al agotarse el tiempo.
- Deadline de lectura por conexión y pool de workers acotado.
- Clases de error estructuradas y redacción de secretos.
- Usuario de servicio dedicado y plantilla de hardening de systemd.
- Codex permanece desactivado hasta que un administrador instale y habilite explícitamente el servicio.

## Inicio rápido

Requisitos: Linux, Python 3.10 o superior, un ejecutable `codex` instalado por separado y disponible para el usuario del servicio, systemd y un usuario/espacio de trabajo sin privilegios dedicado.

```sh
cd components/northstar-codex-sidecar
python3 -m py_compile sidecar.py transport.py service.py sidecar_socket.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
sh -n install.sh rollback.sh
```

Revisa los scripts y la cuenta de servicio antes de habilitar el ciclo conservador:

```sh
sudo ./install.sh
sudo systemctl enable --now northstar-codex-sidecar.service
```

El ejecutable Codex se busca por defecto en `PATH`; usa `CODEX_BIN` para una ruta no estándar.

## Para quién es

Northstar es para desarrolladores y operadores de runtimes locales o self-hosted de compañeros de IA que necesitan un componente de ejecución estrecho, comprobable, auditable, desactivable y reversible. No es un producto de IA alojado, una garantía de seguridad automática ni un sustituto de la arquitectura de identidad, políticas, espacios de trabajo y observabilidad.

## Qué no es

- Todavía no es un sistema operativo completo para agentes multiagente.
- No es un servicio alojado ni una promesa de preparación para producción.
- No es una API general de ejecución de shell.
- No autoriza por sí mismo a los llamadores, no aísla cada ejecución y no propaga la cancelación del padre.
- No incluye credenciales de Codex ni proporciona una cuenta Codex.

**Not a complete autonomous-agent platform.**

## Relación con OpenBot

Northstar es un proyecto independiente dirigido a integraciones compatibles con OpenBot. No está afiliado ni respaldado por OpenBot, CopilotKit ni sus mantenedores. El Sidecar puede integrarse con runtimes de estilo OpenBot sin afirmar que forma parte del repositorio upstream de OpenBot.

La compatibilidad es un objetivo de integración, no propiedad, respaldo ni equivalencia de seguridad.

## Límite de seguridad

El Sidecar autentica a los llamadores únicamente mediante permisos Unix. Una integración de producción debe añadir autorización e identidad del llamador, aislamiento de workspace por ejecución o actor, propagación de cancelación, observabilidad sin registrar prompts sensibles, health checks, rollback, verificación de concurrencia y procesos en Linux nativo, y revisión de la cuenta, red y herramientas de Codex.

No expongas el Unix socket mediante un proxy TCP. Nunca subas API keys, OAuth tokens, estado de login de Codex, claves privadas, archivos `.env` de producción ni transcripciones de usuarios.

## Estado del proyecto

Este es el primer componente público de Northstar. El runtime más amplio de Northstar Agent OS se está construyendo de manera incremental. La vinculación de identidad, la autorización del workspace por ejecución, la cancelación, la verificación end-to-end en Linux nativo y la integración de despliegue de producción siguen siendo responsabilidad del host o trabajo futuro. **Este repositorio no es una plataforma completa de agentes autónomos.**

La limpieza de grupos de procesos debe validarse en la distribución Linux nativa objetivo; el comportamiento de señales y recolección de PID en Linux móvil puede no ser representativo.

## Contribución y mantenimiento

Consulta [CONTRIBUTING.md](../CONTRIBUTING.md) para conocer las expectativas de evidencia, pruebas, seguridad, compatibilidad y rollback. Consulta [SECURITY.md](../SECURITY.md) para reportes de seguridad. English is the canonical source for project scope; translations should be updated when it changes.

## Licencia

MIT. Consulta [LICENSE](../LICENSE).
