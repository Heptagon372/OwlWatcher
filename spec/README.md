# spec — 계약

에이전트(C#/Swift)와 규칙 엔진과 콘솔이 공유하는 유일한 진실. 구현이 셋으로 갈라져도
여기가 하나면 갈라지지 않는다.

```bash
node validate.mjs
```

## 파일

| 파일 | 무엇 |
|---|---|
| [`signals.json`](signals.json) | 신호 카탈로그 S1–S15. **등급의 단일 출처**이고, `m1Status` 가 구현 상태를 말한다 |
| [`observation.schema.json`](observation.schema.json) | 수집기가 내보내는 관측. 규칙 엔진의 유일한 입력 |
| [`event.schema.json`](event.schema.json) | 규칙 엔진의 출력. append-only 해시체인의 한 항목 |
| [`policy.schema.json`](policy.schema.json) | 허용목록·거부목록·임계값 |
| [`heartbeat.schema.json`](heartbeat.schema.json) | `POST /functions/v1/heartbeat` 본문 |
| [`policy/school-common.json`](policy/school-common.json) | 학교 공용 허용목록. 실기기 오탐 코퍼스에서 나왔다 |
| [`fixtures/`](fixtures) | 크로스플랫폼 회귀 픽스처 14종 |
| [`validate.mjs`](validate.mjs) | 정책·픽스처가 스키마를 실제로 지키는지 확인 |

## 관측이 등급을 결정하는 방식

수집기는 **사실만** 낸다. 등급은 규칙 엔진이 매긴다. 그 사이를 잇는 것이 `source` 다.

```json
{ "kind": "exec", "source": "kernel",    "signal": "S9", "path": "~/Downloads/helper.exe" }
{ "kind": "exec", "source": "userspace", "signal": "S9", "collector": "wmi-poll", "degraded": true }
```

같은 실행 사실이지만 아래쪽은 P0 이 될 수 없다. 커널이 아니라 폴링이 봤기 때문이고,
폴링은 짧게 살았다 죽는 프로세스를 놓치므로 "시험 구간의 모든 실행을 봤다"고 말할 수 없다.
이 강등은 규칙 엔진 한 곳에서만 일어난다.

### 플랫폼 판단은 수집기가 한다

"에이전트형 프로세스"나 "가상머신 게스트"의 정의는 플랫폼마다 다르다.
그래서 규칙 엔진이 추측하지 않고 수집기가 답한다.

| 필드 | 누가 답하나 | 없으면 |
|---|---|---|
| `agentLike` | macOS: `activationPolicy` · Windows: 최상위 창 존재 여부 | `hasVisibleWindow === false` 로 폴백 |
| `vmGuestLikely` | CPUID + SMBIOS 를 함께 본 판정 | `hypervisorPresent` 로 폴백 |

폴백이 있는 이유는 픽스처와 아직 없는 macOS 수집기 때문이다.

## 픽스처

각 픽스처는 `session` · `policyRefs` · `steps[]` 와, 레퍼런스 구현이 구운 `expect` 를 갖는다.

```jsonc
"expect": {
  "events": [ { "rule": "...", "grade": "P0", "severity": "crit", "subjectKey": "...", "contexts": [] } ],
  "chainHead": "db659f7736a6…"   // 이게 맞으면 알림 문구 한 글자까지 같다
}
```

규칙을 **의도적으로** 바꿨을 때만 다시 굽는다.

```bash
cd ../core-rules && node bin/run-fixtures.js --bless
```

| 픽스처 | 무엇을 지키나 |
|---|---|
| `001-clean-session` · `010-allowlisted-noise` | 정상 좌석에서 알림 0건 (설계서 12장 목표: P0 오탐 0건) |
| `002-s9-unknown-exec` | 설계서 05장 알림 예시 그대로 |
| **`003-scan-evasion`** | **v0.2 핵심 회귀** — 사전점검 직전 종료 → 시험 중 재실행 |
| `004-s13-capture-guard-fail` | 캡처 차단이 되돌려지면 P0 crit |
| `005` · `012` | S2 단독은 warn · 같은 대상 5분에 한 번 |
| `006-s4-caps-pattern` | 250ms 주기 4회 → S4 |
| `007-p1-escalation` | 같은 프로세스에 P1 이 겹치면 crit |
| `008-s5-canary-reached` | 카나리 도달은 crit, 비콘 실패는 info |
| `009-ledger-bypass` | 화면에는 있는데 원장에 없다 = 원장 우회 |
| `011-s14-attestation` | 소프트웨어 키는 표기, 서명 검증 실패는 P0 |
| `013-vm-and-remote-control` | VM 은 P1, 거부목록은 허용목록을 이긴다 |
| `014-source-downgrade` | 출처가 사용자 공간이면 P0 → P1 |
