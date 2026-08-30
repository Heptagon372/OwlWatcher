# OwlWatch

Icon Cheater류 "화면 캡처 → AI → 위장 출력" 커닝 도구에 대응하는 시험 무결성 프로그램.
설계는 [docs/design-v0.2.md](docs/design-v0.2.md) 에 있고, 이 저장소가 그 구현이다.
Windows 쪽은 실기기에서 검증했고, macOS 쪽은 Apple 승인을 기다리며 코드만 준비돼 있다.

> **이 도구는 부정행위를 판정하지 않는다.** 확인 요청을 만들고 증거를 보관할 뿐이고,
> 처분은 사람과 위원회가 한다. 휴대폰·2차 기기·AI 안경은 범위 밖이다.

---

## 지금 무엇이 되는가

| 구성 요소 | 상태 |
|---|---|
| [`spec/`](spec) — 스키마, 신호 카탈로그 S1–S15, 픽스처 14종 | 검증기로 강제 |
| [`core-rules/`](core-rules) — 탐지 규칙 **레퍼런스 구현**(JS) | 테스트 38건 |
| [`agent-windows/`](agent-windows) — 규칙 엔진 C# 포트 + 수집기 + L0/L1 앱 | 픽스처 14/14, 체인 해시까지 일치 · 실기기 검증 |
| [`console/`](console) — Next.js 15 + Supabase (M2) | 빌드·타입체크 통과. 실 프로젝트 연결은 미검증 |
| [`mock-server/`](mock-server) — 하트비트·비콘·카나리·좌석 맵 | TPM 서명 검증 동작 |
| [`sim/`](sim) — `owlwatch-sim`, 설계서 12장 (a)~(g) | 정답 기능 없음 · 탐지까지 확인 |
| [`agent-macos/`](agent-macos) — ESF · AAC · 규칙 엔진 Swift 포트 (M4) | **한 번도 컴파일되지 않았다.** Apple 승인 대기 |

신호별 구현 상태는 [`spec/signals.json`](spec/signals.json) 의 `status` 가 단일 출처다.
실기기에서 확인한 한계는 [docs/limits.md](docs/limits.md).

### 차단·원장 요약

| | Windows | macOS |
|---|---|---|
| **캡처 차단 (S13)** | **동작 확인** — `WDA_EXCLUDEFROMCAPTURE` + 센티넬 자가검증 (대조군 100% → 차단 후 0.0%) | 창 단위 차단이 존재하지 않는다. AAC 로 대체 |
| **커널 원장 (S9)** | ETW 구현됨. 권한 있으면 **P0**, 없으면 폴링 폴백 **P1** (강등이 자동) | ESF 구현됨(미컴파일). 승인 대기 |
| **락다운 (L2)** | Take a Test — **승인 불필요, 이 기기에서 가용 확인** | AAC — 승인 대기 |
| **기기 키 (S14)** | TPM CNG **동작 확인** | 미구현 |

---

## 빠르게 돌려보기

필요한 것: **.NET 8 SDK**, **Node 20+**. 에이전트·규칙 엔진·시뮬레이터는 의존성이 없고,
콘솔만 npm 패키지를 쓴다.

```bash
dotnet build OwlWatch.sln
```

### 1. 스펙과 규칙 엔진

```bash
node spec/validate.mjs && cd core-rules && node --test test/*.test.js
```

### 2. 패리티 — C# 포트가 레퍼런스와 같은 판정을 내는가

```bash
dotnet run --project agent-windows/tests/OwlWatch.SpecRunner
```

이벤트의 규칙·등급·심각도·대상·맥락뿐 아니라 **최종 체인 해시까지** 맞아야 통과다.
해시가 맞는다는 건 알림 문구 한 글자까지 같다는 뜻이다.

### 3. 커널 원장 (S9) — ETW 배관과 권한

```bash
dotnet run --project agent-windows/tests/OwlWatch.SpecRunner -- --etw
```

구조체 레이아웃과 TDH 매니페스트 해석은 권한 없이도 검증된다. 실시간 세션은 관리자 또는
Performance Log Users 가 필요하고, 없으면 정확한 Win32 오류를 남긴다.

등급이 출처를 따라가는지 전 구간으로 보려면:

```bash
dotnet run --project agent-windows/tests/OwlWatch.SpecRunner -- --ledger
```

실제로 프로세스를 하나 띄우고, 원장이 그것을 보고, 규칙 엔진까지 통과시킨다.
커널이면 P0/crit, 폴백이면 P1/warn 이 나와야 하고 후자에는 강등 이유가 증거에 남아야 한다.

### 4. 이 기기에서 캡처 차단이 되는가

```bash
dotnet run --project agent-windows/src/OwlWatch.ExamCheck -- --capture-test
```

### 5. L0 점검 — 설치 없이 30초

```bash
dotnet run --project agent-windows/src/OwlWatch.ExamCheck
```

`--no-ui` 로 텍스트, `--json` 으로 JSON, `--emit-allowlist <경로>` 로 이 기기의 상주 앱에서
허용목록 초안을 뽑는다. 종료 코드: `0` 정상 · `1` 정황 · `2` 확인 필요 · `3` 오류 · `4` 동의 거부.

### 6. L1 에이전트 + 목 서버

```bash
node mock-server/server.mjs
```

```bash
cp agent-windows/owlwatch.config.example.json agent-windows/owlwatch.config.json
dotnet run --project agent-windows/src/OwlWatch.Agent
```

좌석 맵은 <http://127.0.0.1:8787/> 에서 본다. `시험 시작` 을 누르면 다음 하트비트 응답으로
`arm` 명령이 내려가 감시가 시작된다 — 학생 쪽에서 만들 수 없는 경로다.

하트비트 서명 상호운용만 따로 확인하려면:

```bash
dotnet run --project agent-windows/tests/OwlWatch.SpecRunner -- --heartbeat
```

### 7. 탐지 회귀 시나리오

```bash
dotnet run --project sim/OwlWatchSim -- --help
```

`owlwatch-sim` 은 커닝 도구의 **관측 가능한 부수 효과만** 재현한다 — 화면을 읽지 않고,
AI 에 붙지 않고, 정답을 만들지 않는다. `(g) evade` 가 v0.2 의 핵심 회귀다.

### 8. 콘솔 (M2)

```bash
cd console && npm install && npm run build
```

Supabase 없이도 빌드된다 — 첫 화면이 연결되지 않았다고 말한다.
스키마·Edge Function 은 [`console/supabase/`](console/supabase) 에 있고,
이벤트 append-only·해시체인·P2 알림 금지를 **DB 트리거가 강제한다.**


---

## 설계에서 이어받은 것 세 가지

### 등급은 근거의 성질이지 점수가 아니다

`P0` 결정적 / `P1` 강한 정황 / `P2` 약한 정황. 이 등급의 상한을 정하는 것은 규칙이 아니라
**관측의 출처**다.

| source | 상한 |
|---|---|
| `kernel` · `server` · `selfverify` | P0 |
| `userspace` | P1 |

같은 사실이라도 커널이 아니라 폴링으로 봤으면 등급이 자동으로 내려가고, 그 이유가 이벤트 증거에 남는다.
강등은 코드 한 곳([`RuleEngine.Push`](agent-windows/src/OwlWatch.Rules/RuleEngine.cs))에서만 일어나고,
**수집기는 등급을 주장하지 않는다.**

그래서 M1 의 Windows 에이전트는 커널 원장이 없어 S9 로 P0 를 만들지 못한다. UI 가 그렇게 말한다.

### 등급과 심각도는 직교한다

등급은 증거의 성질, 심각도(`info`/`warn`/`crit`)는 운영 긴급도다.
S5 카나리 도달은 P1 이지만 crit 이고, 비콘 실패는 P2 이면서 info 다 —
*학교망 장애로 40명이 동시에 빨간불이 되면 감독관이 시스템을 꺼 버린다.*

### 레퍼런스 구현과 포트를 픽스처로 묶는다

에이전트는 이벤트를 기기에서 만들어 하드웨어 키로 서명한다. 그래서 규칙 엔진이 플랫폼마다 존재해야 하고,
그러면 반드시 갈라진다. 갈라지지 않게 하는 방법은 하나뿐이다 —
**같은 입력에서 같은 체인 해시가 나오는지 기계가 확인하는 것.**

```
core-rules/ (JS, 레퍼런스)  ──bless──▶  spec/fixtures/*.json  ◀──verify──  OwlWatch.Rules (C# 포트)
```

규칙을 의도적으로 바꿨으면 `cd core-rules && node bin/run-fixtures.js --bless` 로 기대값을 다시 굽는다.
그러지 않고 해시가 어긋나면 그건 버그다.

---

## 저장소 구조

설계서 13장의 구조를 따른다.

```
spec/            스키마 · 신호 카탈로그 · 정책 · 크로스플랫폼 픽스처 · 검증기
core-rules/      탐지 규칙 레퍼런스 구현 (JS) — 시험장에서 돌지 않는다
agent-windows/
  src/OwlWatch.Core/        정규화 JSON · 해시체인 · 정책 판정 (플랫폼 중립)
  src/OwlWatch.Rules/       규칙 엔진 C# 포트 (플랫폼 중립)
  src/OwlWatch.Collectors/  S1–S6 · S8 · S9(폴백) · S13 · S14 수집기
  src/OwlWatch.Runtime/     세션 상태 기계 · 이벤트 저장소 · 하트비트 · 공용 UI
  src/OwlWatch.ExamCheck/   L0 — 설치 없는 점검
  src/OwlWatch.Agent/       L1 — 캡처 차단 + 자가검증
  tests/OwlWatch.SpecRunner/ 패리티 · 하트비트 상호운용
agent-macos/
  Sources/OwlWatchCore/       JSON · 정규화·해시체인 · 정책          (순수 Swift)
  Sources/OwlWatchRules/      규칙 엔진 Swift 포트                   (순수 Swift)
  Sources/OwlWatchCollectors/ ESF · AAC · 사용자 공간 수집기         (승인 필요)
  SystemExtension/            엔타이틀먼트
console/         Next.js 15 + Supabase — 좌석 맵 · 알림 피드 · 리포트
  supabase/migrations/        설계서 08장 표 + append-only 트리거
  supabase/functions/         heartbeat · session-register
sim/             owlwatch-sim — 정답 기능 없음, 용도 제한
mock-server/     개발용 하트비트 서버 + 좌석 맵
docs/            설계서 사본 · 처리방침 · 한계 · 감독관 지침
```

**에이전트에는 NuGet·npm 의존성이 없다.** 시험장 PC 에 오프라인으로 배포하고, 공급망을
줄이고, "무엇을 안 하는지"를 코드로 증명하기 쉬워진다(설계서 10장 소스 공개).
학생 기기에 설치되지 않는 콘솔만 Next.js + Supabase 를 쓴다 — 설계서가 지정한 스택이다.

---

## 개인정보

수집 범위는 [docs/privacy.md](docs/privacy.md) 에 있고, **그 범위를 강제하는 것은
[`Native.cs`](agent-windows/src/OwlWatch.Collectors/Native.cs) 의 P/Invoke 목록**이다.
키 입력 후킹·클립보드·파일 열람 API 가 거기 없다. 목록 자체가 감사 대상이다.

기본 보관 30일. 동의하지 않으면 아무 관측도 만들지 않는다.

---

## 다음 단계

설계서 13장 로드맵 기준. 코드가 있어도 **검증되지 않은 것은 되지 않은 것으로 센다.**

| | 상태 |
|---|---|
| **M0** Apple 엔타이틀먼트 2건 신청 · Developer ID / EV 코드서명 | **미착수 — 지금 가장 급한 항목.** 승인 대기가 가장 길고, macOS 코드는 이미 그것만 기다린다 |
| **M1** Windows 캡처 차단 + 자가검증 · ExamCheck | 완료 · 실기기 검증 |
| **M2** 콘솔 | 스키마·Edge Function·UI 작성 완료. **실 Supabase 프로젝트에서 미검증** |
| **M3** Windows ETW 원장 | 배관 검증 완료. **관리자 권한 환경에서 실제 이벤트 수신 미검증** |
| **M4** macOS ESF + Secure Enclave | 코드 작성 완료, **미컴파일**. Secure Enclave 는 미구현 |
| **M5** 파일럿 2건 → 회고 → 허용목록·임계값 조정 | 미착수 |
| **M6** L2 — Take a Test 연동(작성 완료) · AAC(승인 대기) · 게이트웨이 로그 S15(미착수) | 부분 |

### 바로 다음에 해야 할 것

1. **Apple 엔타이틀먼트 신청** — 다른 무엇보다 먼저. 코드는 이미 기다리고 있다
2. **관리자 계정에서 `--etw` 실행** — 커널 원장이 실제로 이벤트를 받는지, 그리고
   Performance Log Users 만으로 충분한지(설계서 14장 미결 2번)
3. **Mac 에서 `swift run owlwatch-specrunner`** — Swift 포트가 14/14 를 내는지
4. **캡처 차단 우회 경로 실측** — PrintScreen · Snipping Tool · OBS 각각으로
   (설계서 14장 미결 4번, [docs/limits.md](docs/limits.md) 1절)
