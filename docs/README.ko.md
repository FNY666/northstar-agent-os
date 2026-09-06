# Northstar Agent OS

**자율 AI 동료를 위한 개방적이고 신뢰할 수 있으며 거버넌스가 적용된 런타임 구성 요소입니다.**

[English](../README.md) · [简体中文](README.zh-CN.md) · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · [Español](README.es.md) · [한국어](README.ko.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · [Português (Brasil)](README.pt-BR.md) · [Italiano](README.it.md) · [Türkçe](README.tr.md) · [Tiếng Việt](README.vi.md)

**한 문장으로:** Northstar는 명시적 모델 라우팅, 로컬 도구 경계, 감사 가능성, 복구 가능한 실행을 조합해 거버넌스가 적용된 AI 동료 런타임을 만드는 독립 프로젝트입니다. **현재 공개된 구성 요소는 제한된 로컬 worker 어댑터인 Northstar Codex Sidecar이며, 완성된 자율 에이전트 플랫폼이 아닙니다.**

> English is the canonical project entry. Translations mirror its scope and security claims; update them when the canonical README changes.

## 무엇인가요

Northstar는 제한 없는 프롬프트와 도구의 반복에 의존하지 않고, AI 동료가 명확한 경계 안에서 동작하도록 만들고 싶은 개발자를 위한 구성 요소 중심 런타임 프로젝트입니다. 호출자가 확인할 수 있는 계약, 제한된 실행, 구조화된 결과, 운영 복구라는 작고 테스트 가능한 기반에 집중합니다.

프로젝트는 점진적으로 개발됩니다. 개별 구성 요소는 단독으로 유용할 수 있지만, 테스트 통과만으로 전체 에이전트 플랫폼의 안전성이나 운영 준비 상태를 증명할 수는 없습니다.

## 현재 공개된 것

이 저장소는 현재 다음 구성 요소를 공개합니다.

- `../components/northstar-codex-sidecar/` — 요청을 검증하고 Codex를 read-only 모드로 실행하며 입력과 출력을 제한하고 오류를 비식별화하고 timeout 프로세스 그룹을 정리한 뒤 구조화된 상태를 반환하는 로컬 Unix socket 서비스입니다.
- `../components/northstar-run-contract/` — 버전이 지정된 Run Request/Receipt 계약, 만료되는 HMAC Run Binding, 검증된 실행을 Sidecar에 넘기는 엄격한 어댑터 경계.
- `../components/northstar-agent-runtime/` — 통치되는 에이전트 루프: 이벤트 스트림, 10개 라이프사이클 훅, 3단 권한 게이트, 턴/도구 호출/USD 상한, 서브에이전트, 추가 전용 세션, 안전한 경계에서만 수행하는 압축, span 단위 추적. 모델 자격 증명을 보관하지 않고 모델 CLI를 실행하지 않으며, Codex 실행은 Unix socket을 통해 Sidecar에 위임합니다.
- 결정론적 테스트, systemd hardening 템플릿, 보수적인 설치 스크립트, rollback 스크립트.

## Sidecar 작동 방식

Unix socket 연결마다 JSON 요청 하나를 받습니다.

```json
{"request_id":"demo-1","prompt":"Reply with OK","timeout_ms":10000}
```

응답은 제한된 JSON 객체 하나입니다.

```json
{"request_id":"demo-1","status":"ok","text":"OK"}
```

주요 속성:

- Unix socket만 사용하며 TCP listener는 제공하지 않습니다.
- 엄격한 요청 허용 목록: `request_id`, `prompt`, `timeout_ms`.
- prompt와 timeout에 상한이 있습니다.
- Codex는 `--sandbox read-only` 및 `--ephemeral`로 실행됩니다.
- 별도 프로세스 그룹을 사용하며 timeout 시 TERM 이후 KILL로 정리합니다.
- 연결별 read deadline과 제한된 worker pool.
- 구조화된 오류 분류와 비밀정보 redaction.
- 전용 서비스 사용자와 systemd hardening 템플릿.
- 관리자가 명시적으로 설치하고 활성화하기 전까지 Codex는 비활성화됩니다.

## 빠른 시작

요구 사항: Linux, Python 3.10 이상, 서비스 사용자가 실행할 수 있도록 별도 설치된 `codex` 실행 파일, systemd, 전용 비특권 서비스 사용자와 workspace.

```sh
cd components/northstar-codex-sidecar
python3 -m py_compile sidecar.py transport.py service.py sidecar_socket.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
sh -n install.sh rollback.sh
```

활성화하기 전에 스크립트와 서비스 계정, 경로와 권한을 검토하세요.

```sh
sudo ./install.sh
sudo systemctl enable --now northstar-codex-sidecar.service
```

기본 Codex 실행 파일은 `PATH`에서 찾습니다. 표준 경로가 아니면 `CODEX_BIN`을 설정하세요.

## 대상 사용자

Northstar는 테스트, 감사, 비활성화, rollback이 가능한 좁은 실행 구성 요소가 필요한 로컬 또는 self-hosted AI 동료 런타임 개발자와 운영자를 위한 것입니다. 호스팅 AI 제품, 자동 안전 보장, 또는 전체 identity·policy·workspace·observability 구조의 대체재가 아닙니다.

## 무엇이 아닌가요

- 아직 완성된 multi-agent 운영 체제가 아닙니다.
- 호스팅 서비스나 production readiness 보장이 아닙니다.
- 범용 shell 실행 API가 아닙니다.
- 호출자 권한 부여, 모든 실행의 격리, 부모 cancellation 전파를 스스로 수행하지 않습니다.
- Codex 자격 증명이나 Codex 계정을 포함하지 않습니다.

**Not a complete autonomous-agent platform.**

## OpenBot과의 관계

Northstar는 독립 프로젝트이며 OpenBot-compatible 통합을 대상으로 합니다. OpenBot, CopilotKit 또는 그 유지관리자와 제휴하거나 공식 승인을 받은 프로젝트가 아닙니다. Sidecar는 OpenBot 스타일 런타임과 통합될 수 있지만 upstream OpenBot 저장소의 일부라고 주장하지 않습니다.

Compatibility는 통합 대상일 뿐 소유권, 보증, 보안 동등성을 뜻하지 않습니다.

## 보안 경계

Sidecar는 Unix 권한만으로 호출자를 인증합니다. production 통합에는 호출자 권한 부여와 identity binding, 실행/actor별 workspace 격리, 부모 cancellation 전파, 민감한 prompt를 기록하지 않는 observability, health check와 rollback, native Linux 동시성 및 process-tree 검증, Codex 계정·네트워크·도구 설정 검토가 추가로 필요합니다.

Unix socket을 TCP proxy로 노출하지 마세요. API key, OAuth token, Codex login state, private key, production `.env` 파일, 사용자 transcript를 커밋하지 마세요.

## 프로젝트 상태

이것은 Northstar의 첫 번째 공개 구성 요소입니다. 더 넓은 Northstar Agent OS 런타임은 점진적으로 개발 중입니다. 런타임 identity binding, 실행별 workspace 권한 부여, cancellation 전파, native Linux end-to-end 검증, production 배포 통합은 host 책임 또는 향후 작업으로 남아 있습니다. **이 저장소는 완성된 자율 에이전트 플랫폼이 아닙니다.**

프로세스 그룹 정리는 대상 native Linux 배포판에서 검증해야 하며, mobile Linux의 signal 및 PID reaping 동작은 대표성이 없을 수 있습니다.

## 기여 및 유지관리

증거, 테스트, 보안, 호환성, rollback 기준은 [CONTRIBUTING.md](../CONTRIBUTING.md)를 참조하세요. 보안 보고는 [SECURITY.md](../SECURITY.md)를 참조하세요. English is the canonical source for project scope; translations should be updated when it changes.

## 라이선스

MIT. [LICENSE](../LICENSE)를 참조하세요.
