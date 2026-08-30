# agent-macos (M4)

> **이 코드는 한 번도 컴파일되지 않았다.** Windows 개발 기기에서 작성했고 Swift 툴체인이
> 없었다. Mac 에서 아래 한 줄이 14/14 를 낼 때까지는 동작한다고 말할 수 없다.
>
> ```bash
> swift run owlwatch-specrunner
> ```
>
> 그 명령이 통과하면 규칙 엔진이 JS 레퍼런스·Windows 포트와 **체인 해시까지** 같다는 뜻이고,
> 통과하지 못하면 어디가 다른지 픽스처 단위로 알려 준다. 그게 이 저장소가
> 세 구현을 묶는 방식이다(설계서 G3 · 12장).

---

## 왜 이 상태로 두는가

설계서 13장 M0: *"Apple 엔타이틀먼트 2건 신청(ESF · AAC) — 승인 대기가 가장 긴 항목이라
무조건 먼저."*

승인은 코드가 준비돼 있든 아니든 걸린다. 그래서 승인을 기다리는 동안 쓸 수 있게
코드를 먼저 써 둔다. 승인이 도착하면 Xcode 프로젝트를 붙이고 서명·공증만 하면 된다.

## 선결 조건

| 항목 | 무엇 | 없으면 |
|---|---|---|
| `com.apple.developer.endpoint-security.client` | S9 · S10 · S11 · S12 | `es_new_client` 가 실패한다. 관측을 아예 내지 않고, 호출자가 사용자 공간 수집기로 폴백하면 **등급이 P1 로 내려간다** |
| `com.apple.developer.automatic-assessment-configuration` | L2 락다운(AAC) | 키오스크 라이트가 상한. 캡처를 못 막는다는 사실을 학생·감독관에게 그대로 표시한다 |
| Developer ID 서명 + 공증 | 배포 | 시스템 확장을 설치할 수 없다 |
| 전체 디스크 접근 | ESF 실행 | `ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED` |

엔타이틀먼트 신청 명의는 **학교 개발자 계정**이 현실적이다(설계서 14장 미결 1번).
학생 동아리 명의로 받을 수 있는지는 확인되지 않았다.

## 구조

```
Sources/
  OwlWatchCore/        JSON · Canonical(정규화·해시체인) · Policy   ← 순수 Swift, 오늘 빌드된다
  OwlWatchRules/       Summaries · RuleEngine                       ← 순수 Swift, 오늘 검증된다
  OwlWatchCollectors/  EndpointSecurityClient · AssessmentSession
                       · UserspaceCollectors                        ← 승인·프레임워크 필요
  owlwatch-specrunner/ 픽스처 패리티 러너
SystemExtension/       Info.plist · 엔타이틀먼트
```

`OwlWatchCollectors` 는 EndpointSecurity 프레임워크를 링크하므로 SwiftPM 만으로는
실행 테스트가 안 된다 — 시스템 확장 타깃이 필요하고, 그건 Xcode 프로젝트다.
`OwlWatchCore` 와 `OwlWatchRules` 는 순수 Swift 라 **오늘 빌드·검증된다.**

## macOS 가 Windows보다 나은 지점 / 나쁜 지점

| | macOS | Windows |
|---|---|---|
| 커널 원장 (S9) | ESF — 승인만 받으면 완전하다 | ETW — 관리자 권한, M1 은 폴링 폴백(P1) |
| 캡처 권한 관측 (S10) | **있다** (15.4+) | 대응물 없음 → S13 으로 대체 |
| HID 오픈 관측 (S12) | **있다** — 여는 행위가 커널에 남는다 | 대응 관측 없음 |
| 에이전트형 판정 (S1) | `activationPolicy` 가 답을 준다 | 근사해야 한다 |
| 창 단위 캡처 차단 | **없다** — `sharingType = .none` 은 레거시이고 15.4+ ScreenCaptureKit 이 무시한다 | `WDA_EXCLUDEFROMCAPTURE` 로 오늘 가능 |
| 락다운 (L2) | AAC — 승인 대기 | Take a Test — **승인 불필요, 오늘 가능** |

설계서 04장이 말한 두 칸의 보완이 그대로다. Windows 는 캡처 권한 관측이 없으니 캡처를
막고 자가검증하고, macOS 는 창 단위 차단이 없으니 P0 탐지로 같은 등급을 만든다.

**흉내 내지 않는다.** `NSWindow.sharingType = .none` 은 지금 캡처를 막지 못하고,
막는 척하는 코드는 이 저장소에 없다. `KioskLite.disclosure` 가 그 사실을 학생에게
그대로 보여 준다.

## 구독 범위 = 수집 범위

`EndpointSecurityClient.subscriptions` 배열이 우리가 커널에 묻는 것의 전부다.
감사 대상이라 상수로 박아 뒀다(설계서 10장).

```
NOTIFY_EXEC · FORK · EXIT     S9
NOTIFY_MMAP                   S11
NOTIFY_IOKIT_OPEN             S12
NOTIFY_TRACE                  S8
NOTIFY_TCC_MODIFY (15.4+)     S10
```

없는 것: `AUTH_*` (우리는 차단하는 주체가 아니라 기록하는 주체다),
`NOTIFY_OPEN` / `WRITE` / `READDIR` (파일 내용 계열).

## Mac 에서 처음 할 일

```bash
cd agent-macos
swift build                      # Core · Rules 만 빌드된다
swift run owlwatch-specrunner    # 14/14 가 나와야 한다
```

실패하면 그건 이 포트의 버그다 — 픽스처가 어디서 갈렸는지 알려 준다.
성공하면 그다음이 Xcode 프로젝트와 엔타이틀먼트다.

## 알려진 미확인 항목

- **S2 의 macOS 26 회귀** — 상태 항목이 Control Center 로 귀속돼 AX 경로가 달라진다는
  보고(설계서 14장 미결 5번). 지금은 권한이 필요 없는 `CGWindowList` 레이어 25 경로를 쓴다.
- **`CodeSigning.platformBinary`** — `kSecCodeInfoFlags` 의 플랫폼 비트를 쓰는데,
  ESF 의 `is_platform_binary` 와 같은 값인지 실기기에서 대조해야 한다.
- **공증 여부(`notarized`)** — 아직 채우지 않는다. `SecAssessment` API 가 필요하고,
  그건 네트워크를 탈 수 있어 시험망 기본 거부와 충돌한다.
- **Secure Enclave 하트비트 서명(S14)** — 미구현. Windows 의 TPM 경로
  (`Attestation.cs`)에 대응하는 `kSecAttrTokenIDSecureEnclave` 구현이 필요하다.
