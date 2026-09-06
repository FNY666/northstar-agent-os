# Northstar Agent OS

**Componentes de runtime abertos, confiáveis e governados para colegas de IA autônomos.**

[English](../README.md) · [简体中文](README.zh-CN.md) · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · [Español](README.es.md) · [한국어](README.ko.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · [Português (Brasil)](README.pt-BR.md) · [Italiano](README.it.md) · [Türkçe](README.tr.md) · [Tiếng Việt](README.vi.md)

**Em uma frase:** Northstar é um projeto independente para montar colegas de IA governados a partir de roteamento explícito de modelos, limites de ferramentas locais, auditabilidade e execução recuperável. **O componente publicado hoje é o Northstar Codex Sidecar, um adaptador local restrito para workers — não uma plataforma completa de agentes autônomos.**

> English is the canonical project entry. Translations mirror its scope and security claims; update them when the canonical README changes.

## O que é

Northstar é um projeto de runtime orientado a componentes para desenvolvedores que querem que colegas de IA operem com limites visíveis, em vez de depender de um ciclo sem restrições de prompt e ferramentas. O foco está em blocos pequenos e testáveis: um contrato visível para o chamador, execução restrita, resultados estruturados e recuperação operacional.

O projeto é desenvolvido de forma incremental. Um componente pode ser útil por si só, mas testes aprovados não provam que uma plataforma completa de agentes seja segura ou esteja pronta para produção.

## O que é publicado hoje

- `../components/northstar-codex-sidecar/` — serviço local via Unix socket que valida solicitações, executa o Codex em modo read-only, limita entrada e saída, oculta erros, limpa grupos de processos após timeout e retorna estados estruturados.
- `../components/northstar-run-contract/` — contrato Run Request/Receipt versionado, Run Binding HMAC com expiração e fronteira de adaptadora rigorosa para entregar uma execução verificada ao Sidecar.
- `../components/northstar-agent-runtime/` — loop de agente governado: fluxo de eventos, dez hooks de ciclo de vida, portão de permissões em três camadas, limites independentes de turnos/chamadas de ferramentas/USD, subagentes, sessões somente de acréscimo, compactação apenas em fronteiras seguras e rastreamento por spans. Ele não guarda credenciais do modelo nem inicia uma CLI de modelo: a execução do Codex é delegada ao Sidecar pelo Unix socket.
- Testes determinísticos, modelo de hardening do systemd, instalador conservador e script de rollback.

## Como o Sidecar funciona

Uma solicitação JSON é aceita por conexão Unix socket:

```json
{"request_id":"demo-1","prompt":"Reply with OK","timeout_ms":10000}
```

A resposta é um objeto JSON limitado:

```json
{"request_id":"demo-1","status":"ok","text":"OK"}
```

Propriedades importantes:

- Somente Unix socket; não há listener TCP.
- Lista estrita de campos: `request_id`, `prompt` e `timeout_ms`.
- Limites para prompt e timeout.
- O Codex é executado com `--sandbox read-only` e `--ephemeral`.
- Grupo de processos separado, limpo com TERM e depois KILL em caso de timeout.
- Prazo de leitura por conexão e pool de workers limitado.
- Classes de erro estruturadas e redaction de segredos.
- Usuário de serviço dedicado e modelo de hardening do systemd.
- O Codex permanece desativado até que um administrador instale e habilite o serviço explicitamente.

## Início rápido

Requisitos: Linux, Python 3.10 ou superior, um executável `codex` instalado separadamente e disponível para o usuário do serviço, systemd e um usuário/espaço de trabalho dedicado sem privilégios.

```sh
cd components/northstar-codex-sidecar
python3 -m py_compile sidecar.py transport.py service.py sidecar_socket.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
sh -n install.sh rollback.sh
```

Revise os scripts e a conta do serviço antes de habilitar o ciclo conservador:

```sh
sudo ./install.sh
sudo systemctl enable --now northstar-codex-sidecar.service
```

O executável do Codex é localizado em `PATH` por padrão; use `CODEX_BIN` para um caminho não padrão.

## Para quem é

Northstar é para desenvolvedores e operadores de runtimes locais ou self-hosted de colegas de IA que precisam de um componente de execução limitado, testável, auditável, desativável e reversível. Não é um produto de IA hospedado, uma garantia automática de segurança nem um substituto para uma arquitetura completa de identidade, políticas, workspaces e observabilidade.

## O que não é

- Ainda não é um sistema operacional completo para agentes multiagente.
- Não é um serviço hospedado nem uma promessa de prontidão para produção.
- Não é uma API geral de execução de shell.
- Não autoriza os chamadores, não isola cada execução e não propaga sozinho o cancelamento do processo pai.
- Não inclui credenciais do Codex nem fornece uma conta do Codex.

**Not a complete autonomous-agent platform.**

## Relação com o OpenBot

Northstar é um projeto independente voltado a integrações compatíveis com OpenBot. Não é afiliado nem endossado pelo OpenBot, CopilotKit ou seus mantenedores. O Sidecar pode ser integrado a runtimes no estilo OpenBot sem afirmar que faz parte do repositório upstream do OpenBot.

Compatibilidade é um alvo de integração, não propriedade, endosso ou equivalência de segurança.

## Limite de segurança

O Sidecar autentica os chamadores somente por permissões Unix. Uma integração de produção deve acrescentar autorização e vínculo de identidade do chamador, isolamento de workspace por execução ou ator, propagação de cancelamento, observabilidade sem registrar prompts sensíveis, health checks e rollback, verificação de concorrência e árvore de processos em Linux nativo e revisão da conta, rede e configuração de ferramentas do Codex.

Não exponha o Unix socket por um proxy TCP. Nunca faça commit de API keys, OAuth tokens, estado de login do Codex, chaves privadas, arquivos `.env` de produção ou transcrições de usuários.

## Status do projeto

Este é o primeiro componente público do Northstar. O runtime mais amplo do Northstar Agent OS está sendo construído de forma incremental. Vínculo de identidade, autorização de workspace por execução, propagação de cancelamento, verificação end-to-end em Linux nativo e integração de implantação em produção continuam sendo responsabilidades do host ou trabalho futuro. **Este repositório não é uma plataforma completa de agentes autônomos.**

A limpeza de grupos de processos deve ser validada na distribuição Linux nativa de destino; o comportamento de sinais e recuperação de PID no Linux móvel pode não ser representativo.

## Contribuição e manutenção

Veja [CONTRIBUTING.md](../CONTRIBUTING.md) para as expectativas de evidência, testes, segurança, compatibilidade e rollback. Veja [SECURITY.md](../SECURITY.md) para relatórios de segurança. English is the canonical source for project scope; translations should be updated when it changes.

## Licença

MIT. Veja [LICENSE](../LICENSE).
