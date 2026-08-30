# OwlWatch 설계서 v0.2

> 이 파일은 아티팩트 원본([OwlWatch 설계서](https://claude.ai/code/artifact/afc8f614-4645-46c2-b34a-45f9aa8cb32f))을
> 저장소에 옮긴 사본이다. 그림은 설명으로 대체했고, 나머지 내용은 그대로다.
> 원본이 바뀌면 이 파일도 다시 옮겨야 한다 — 지금 기준은 v0.2 · 2026-08-28.
>
> 구현이 이 문서와 어긋나는 지점은 [limits.md](limits.md) 에 실측과 함께 기록한다.

---

**기술 설계서 · v0.2 · 2026-08-28 · S.OWL 내부**

Icon Cheater류 "화면 캡처 → AI → 위장 출력" 커닝 도구에 대응하는 시험 무결성 프로그램의 설계다. v0.2는 두 가지를 고쳤다 — 탐지 근거를 OS 커널·보안 프레임워크가 기록한 결정적 사실로 끌어올렸고(휴리스틱 점수 → 확신 등급 모델), macOS와 Windows를 같은 신호·같은 차단력으로 맞췄다. 전편 대응 브리핑의 6.5절을 구체화한 문서. 이름은 가칭.

| | |
|---|---|
| 플랫폼 | macOS 13+ · Windows 10 2004+ (신호·차단 동등 설계) |
| 신호 | 15개, 그중 결정적(P0) 7개 |
| 차단 계층 | L0 점검 · L1 캡처차단 · L2 락다운 |
| 수집 안 하는 것 | 키 입력 · 화면 내용 · 카메라 · 파일 (메타데이터만) |
| 최단 실전 투입 | 2주 — Windows 캡처 차단 (승인 불필요) |

근거 표기: **확정** 공개 문서로 확인한 동작 · **실험** 실기기 검증 필요 · **제안** 대안 있음

## 00 · 목표·비목표·원칙

### 목표

- G1 · 확실성 알림 하나하나가 "무엇이 사실로 확인됐는지"를 등급으로 말한다. 학사위원회에서 다투는 건 늘 "그게 확실하냐"이므로, 정황과 사실을 섞지 않는다.

- G2 · 차단 우선 가능한 환경에서는 탐지가 아니라 차단한다. 커닝 도구의 입력(=시험 화면 캡처)을 없애면 아이콘·LED·다중문항 모드가 한꺼번에 죽는다.

- G3 · 플랫폼 패리티 macOS와 Windows에서 같은 신호를 같은 등급으로 낸다. 한쪽만 되는 도구는 "맥북 쓰면 안 걸린다"는 소문 하나로 무력해진다.

- G4 · 투명성 학생이 수집 항목을 화면에서 그대로 보고, 30일이면 데이터가 사라진다.

- G5 · 운영 부담 0에 가깝게 감독관 1명이 40석을 태블릿 하나로. 알림은 "어디 가서 무엇을 확인하라"를 말한다.

### 비목표

- 휴대폰·2차 기기·AI 안경·핫스팟 우회. 소프트웨어로 못 막는다는 것을 문서와 UI에 명시한다.

- 부정행위 판정. 확인 요청을 만들고 증거를 보관할 뿐, 처분은 사람과 위원회가 한다.

- 범용 프록터링(얼굴 인식·시선 추적·룸 스캔). 범위는 "노트북 상주 도구"로 고정.

- 키 입력·화면 내용·클립보드·파일 수집. 코드에 해당 API 호출을 두지 않는다.

### 설계 원칙

#### P1 · 커널이 말하게 한다
사용자 공간 스캔은 "스캔 직전에 종료 → 시험 중 재실행"으로 회피된다. macOS Endpoint Security와 Windows ETW는 시험 구간의 모든 실행을 커널에서 기록하므로 회피가 안 된다. 이것이 v0.2의 핵심 변화다.

#### P2 · 프로세스가 근원이다
메뉴바 아이콘·LED·네트워크는 전부 프로세스의 부수 효과다. 아이콘 모양을 알아맞히는 방식은 만들지 않는다. 서명자(Team ID / 인증서 주체)로 허용목록을 건다.

#### P3 · 예방 > 탐지 > 기록
OS 평가 모드(macOS AAC, Windows Take a Test)와 창 단위 캡처 차단이 1순위. 자체 탐지는 그것이 불가능한 시험을 위한 차선이다.

#### P4 · 클라이언트를 믿지 않는다
학생 기기가 보낸 값은 조작될 수 있다. 하드웨어 키(Secure Enclave / TPM) 서명과 서버측 로그(게이트웨이·LMS)로 교차 검증한 것만 P0으로 친다.

## 01 · 공격 사슬과 절단 지점

Icon Cheater의 모든 모드는 같은 파이프라인을 탄다. 어디를 끊을 수 있는지가 곧 통제 목록이다.

> **그림** — 커닝 도구의 파이프라인(화면에서 캡처, AI 요청, 아이콘 또는 LED 출력)과 각 단계를 끊는 네 가지 통제: 캡처 차단과 락다운, 허용목록 네트워크, 커널 프로세스 원장, 출력 관찰
> 
> (원본 아티팩트의 SVG. 저장소 사본에는 설명만 옮겼다.)

그림 1. 파이프라인과 절단 지점. ①은 입력을 없애므로 출력 모드와 무관하게 전부 무력화한다. ③은 v0.2에서 사용자 공간 스캔에서 커널 원장으로 바뀌어 "스캔 직전 종료" 회피가 통하지 않는다.

| Icon Cheater 기능 | ①캡처차단 | ②네트워크 | ③커널 원장 | ④출력 관찰 | 결과 등급 |
|---|---|---|---|---|---|
| A. 메뉴바/트레이 아이콘 위장 | 무력화 | 학교망일 때 | S9 실행 기록 | S2 항목 소유자 | P0 확보 가능 |
| B. 키보드 LED 점멸 | 답 자체가 없음 | — | S9 | S12 HID 접근 · S4 상태 토글 | P0 확보 가능 |
| C. 여러 문제 일괄 | — | — | S9 | — | P0 |
| D. ChatGPT 차단 우회(자체 백엔드) | 앱 외 통신 차단(L2) | 기본 거부 | S5 연결 목록 | — | P0 (게이트웨이 로그) |
| Cluely형 캡처 제외 오버레이 | — | — | S9 | S3 캡처 제외 창 | P0 |
| 휴대폰·2차 기기·AI 안경 | — | — | — | — | 범위 밖 |

## 02 · 확신 등급 모델

v0.1의 단순 가중치 합산을 버린다. 점수 90은 "확실"이 아니라 "휴리스틱이 90이라고 했다"일 뿐이고, 위원회에서 그대로 무너진다. 대신 근거를 성질로 나눈다.

| 등급 | 정의 | 해당 신호 | 단독 처리 |
|---|---|---|---|
| P0 결정적 | OS 커널·보안 프레임워크 또는 학교가 소유한 서버가 기록한 사실. 학생 기기의 사용자 공간 코드가 위조할 수 없다. | S9 프로세스 원장 · S10 캡처 권한 부여 · S12 HID 장치 접근 · S13 캡처 차단 자가검증 실패 · S14 하드웨어 키 불일치 · S15 게이트웨이/LMS 로그 · S7 락다운 이탈 | crit 단독으로 확인 요청 + 증거 보전 |
| P1 강한 정황 | 정상 사용에서는 잘 나오지 않는 조합. 개별로는 설명 가능하지만 겹치면 우연이 어렵다. | S1 미허용·미서명 에이전트형 프로세스 · S2 메뉴바/트레이 소유자 · S3 캡처 제외 창 · S4 Caps Lock 비인간 패턴 · S11 캡처 스택 로드 · S6 VM·원격제어 | warn · 같은 프로세스에 2개 이상 겹치면 crit |
| P2 약한 정황 | 단독으로는 아무 의미 없음. P0·P1이 있을 때 서술을 보강하는 맥락. | 다운로드 경로 실행 · 시험 직전 시작 · 인터페이스 2개 · 미공증 바이너리 | 알림 없음. 이벤트에만 첨부 |

규칙. 알림 문구는 등급을 먼저 말한다 — "[확정] 좌석 17 · 시험 시작 3분 전 ~/Downloads/helper 실행됨(미서명). 커널 실행 기록." 리포트에서 P0만 "확인된 사실"로 기술하고, P1은 "정황", P2는 "참고"로 분리한다. 처분 문서에 P1을 사실처럼 쓰지 않는다 — 이 규칙 하나가 시스템의 신뢰를 좌우한다.

등급을 이렇게 나누면 오탐의 비용도 달라진다. P1 오탐은 "감독관이 한 번 가서 확인"으로 끝나지만 P0 오탐은 시스템 전체를 못 믿게 만든다. 그래서 P0에는 휴리스틱을 넣지 않는다 — 커널이 기록했거나, 우리 서버가 기록했거나, 우리 코드가 검증에 실패했거나 셋 중 하나여야 한다.

## 03 · 시스템 아키텍처

세 개의 실행 단위와 하나의 네트워크 정책. 학생 기기에는 시험 시간에만 도는 에이전트, 강의실에는 기본 거부 네트워크, 감독관에게는 웹 콘솔. 시뮬레이터는 개발·검증 전용이다.

> **그림** — 학생 노트북의 에이전트는 커널 원장과 사용자 공간 수집기에서 관측값을 모아 탐지기로 보내고, 하드웨어 키로 서명한 하트비트를 시험 네트워크 게이트웨이를 거쳐 콘솔로 전송한다. 게이트웨이는 LMS와 비콘만 허용하고 카나리를 차단하며 서버측 로그를 남긴다.
> 
> (원본 아티팩트의 SVG. 저장소 사본에는 설명만 옮겼다.)

그림 2. v0.2의 변화는 왼쪽 위 커널 원장과 가운데 게이트웨이 로그다 — 둘 다 학생 기기의 사용자 공간 코드가 손댈 수 없는 P0 근거를 만든다.

### 배포 단계

| 레벨 | 무엇을 하나 | macOS 요건 | Windows 요건 | 얻는 등급 |
|---|---|---|---|---|
| L0 ExamCheck / 설치 없는 점검 | 시험 직전 30초 스캔 → 결과 화면 + 6자리 코드. 상주 없음. 콘솔 없이도 동작 | 서명·공증된 .app, 권한 없이 실행. 접근성 권한은 선택(S2 정밀도) | 서명된 단일 .exe, 관리자 불필요 | P1·P2 |
| L1 Agent / 커널 원장 + 캡처 차단 | 시험 시간 동안 상주. 커널 실행 원장, 캡처 차단 + 자가검증, HID 접근 관측, HW 키 서명 하트비트, 종료 시 자기 삭제 | Endpoint Security 시스템 확장 — Apple 엔타이틀먼트 승인 + 설치 시 1회 관리자 | ETW 세션용 서비스 — MSI 설치 시 1회 관리자. 캡처 차단은 관리자 불필요 | P0 + P1 |
| L2 Lockdown / OS 평가 모드 | OS 평가 모드로 LMS를 띄움 → 캡처 자체가 불가능, 앱 외 네트워크 차단 | AEAssessmentSession — 엔타이틀먼트 승인 필요 | Take a Test — 승인 불필요, URL 프로토콜 | 차단(탐지 불필요) |

결정. v0.1은 "L0 macOS 먼저"였는데, 두 OS를 맞추면 순서가 바뀐다. Windows가 먼저다 — 캡처 차단(승인 불필요)과 Take a Test(승인 불필요)가 둘 다 즉시 쓸 수 있어 2주 안에 실전 투입이 가능하다. macOS는 Apple 승인이 걸린 항목(ESF·AAC)이 크리티컬 패스이므로 승인 신청을 이번 주에 넣고, 그 사이 L0으로 버틴다.

## 04 · 플랫폼 패리티

같은 신호를 두 OS에서 같은 등급으로 내는 것이 목표다. 아래 표에서 등급이 어긋나는 칸이 곧 "맥북 쓰면 안 걸린다"는 소문의 재료이므로, 어긋난 칸마다 보완책을 붙였다.

> **그림** — 같은 탐지기와 콘솔 위에 macOS는 Endpoint Security 시스템 확장과 AAC 평가 모드로, Windows는 ETW 서비스와 창 캡처 제외 및 Take a Test로 각각 같은 종류의 결정적 신호와 차단을 제공한다
> 
> (원본 아티팩트의 SVG. 저장소 사본에는 설명만 옮겼다.)

그림 3. 붉은 줄이 차단 계층, 검은 줄이 텔레메트리 계층이다. 두 계층 모두 기능은 동등하고 도입 장벽만 다르다 — Windows는 오늘 켤 수 있고, macOS는 Apple 승인을 기다린다. 그 아래 스키마·규칙·등급·UI는 한 벌이다.

| 능력 | macOS | Windows | 패리티 |
|---|---|---|---|
| 커널 실행 원장 | Endpoint Security NOTIFY_EXEC/FORK/EXIT — 경로·인자·cdhash·서명 ID·플랫폼 바이너리 여부 포함확정 | ETW Microsoft-Windows-Kernel-Process 실시간 세션 + 이미지 로드. 실시간 세션은 관리자/Performance Log Users 권한 필요 → 서비스로 실행 | 동등 |
| 캡처 권한 부여 관측 | NOTIFY_TCC_MODIFY(macOS 15.4+) — service ScreenCapture, 대상 앱 신원, 허용/거부, 사유확정 | 동등물 없음. Windows는 화면 캡처에 권한 게이트가 없다 | mac 우세 → Windows는 캡처 차단으로 대체(아래) |
| 창 단위 캡처 차단 | NSWindow.sharingType = .none은 레거시, macOS 15.4+ ScreenCaptureKit이 무시확정 → 사실상 불가 | SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) — 모니터에만 표시, 캡처엔 빈 내용. Win10 2004+확정 | win 우세 → macOS는 AAC로 대체 |
| OS 평가 모드(락다운) | AEAssessmentSession — 캡처·앱전환·메뉴바·앱 외 네트워크 차단. 엔타이틀먼트 승인 필요 | Take a Test — 잠금 화면 위 전체화면, 캡처 검은 화면, 클립보드 초기화. 승인 불필요 | 기능 동등 · 도입 속도만 다름 |
| 메뉴바 / 트레이 소유자 | 앱별 kAXExtrasMenuBarAttribute(접근성) 또는 CGWindowListCopyWindowInfo 레이어 25 | HKCU\…\NotifyIconSettings + 트레이 툴바 열거 | 동등 (mac 26 회귀는 AX 경로로 우회) |
| HID / LED 제어 관측 | NOTIFY_IOKIT_OPEN — HID 키보드 디바이스를 연 프로세스가 그대로 기록됨확정 | LED만 켜려면 커널 접근이 필요 → 실사용 도구는 실제 Caps Lock 상태를 토글하게 되고, 그건 폴링으로 확정 관측실험 | 경로는 달라도 등급 동일(P0) |
| 하드웨어 바인딩 | Secure Enclave 키(kSecAttrTokenIDSecureEnclave)로 하트비트 서명 | TPM 2.0 — CNG Microsoft Platform Crypto Provider 키로 서명 | 동등 |
| 배포·서명 | Developer ID 서명 + 공증, 시스템 확장은 사용자 승인 UI | EV 코드 서명 권장(SmartScreen), MSI/MSIX 배포 | 동등 |

패리티가 깨지는 두 칸의 보완. ① Windows에는 캡처 권한 관측이 없다 → 대신 캡처 자체를 막고(창 제외) 그것이 실제로 작동하는지 자가검증(S13)한다. ② macOS에는 창 단위 캡처 차단이 없다 → AAC 승인 전까지는 커널 원장(S9) + 캡처 권한 관측(S10)이라는 탐지로 같은 등급(P0)을 만든다. 결과적으로 두 OS 모두 "P0 근거를 낼 수 있다"는 선은 지킨다.

## 05 · 신호 카탈로그 S1–S15

등급은 02장 기준. P0은 커널·학교 서버·우리 코드의 검증 실패 셋 중 하나에서만 나온다.

### P0 · 결정적

| ID | 무엇을 잡나 | macOS | Windows | 주의 |
|---|---|---|---|---|
| S9 / 프로세스 원장 | 시험 구간에 실행된 모든 프로세스의 경로·서명·부모·시작 시각. 스캔 직전 종료 후 시험 중 재실행하는 회피가 통하지 않는다 | ES NOTIFY_EXEC/FORK/EXIT. 메시지에 실행 파일 경로, cdhash, signing id, Team ID, is_platform_binary, 부모 pid 포함확정 | ETW Microsoft-Windows-Kernel-Process(프로세스·이미지 로드) 실시간 세션. 서명은 로드된 이미지 경로에 WinVerifyTrust 병행 | 실시간 세션·ES 클라이언트 모두 특권 필요 → L1 설치 시 1회 관리자. 원장은 이름·경로·해시만 남기고 인자(argv)는 저장하지 않는다(개인정보) |
| S10 / 캡처 권한 부여 | 시험 직전·중에 어떤 앱이 화면 기록 권한을 받았는가 | ES NOTIFY_TCC_MODIFY(macOS 15.4+). service = ScreenCapture, 대상 앱 신원, ALLOWED/DENIED, 변경 사유확정 | 해당 없음 — Windows는 캡처에 권한 게이트가 없다. S13(차단 자가검증)으로 대체 | 15.4 미만 macOS에서는 이벤트가 없다. 엔타이틀먼트를 가진 앱은 이벤트를 만들지 않는다는 한계도 문서화 |
| S12 / HID 장치 접근 | 키보드 LED를 직접 제어하려는 프로세스 | ES NOTIFY_IOKIT_OPEN — HID 키보드/LED 디바이스를 연 프로세스가 그대로 남는다확정 | LED만 켜려면 커널 경로가 필요해 일반 앱은 실제 Caps Lock 상태를 토글하게 된다 → S4 폴링이 곧 확정 관측실험 | 정상적으로 HID를 여는 앱(Karabiner, 게이밍 키보드 유틸)은 허용목록으로. 단 시험 중 신규 오픈은 등급 유지 |
| S13 / 캡처 차단 자가검증 | 보호가 실제로 작동 중인지. 실패 = 누군가 무력화했거나 환경이 지원하지 않음 | AAC 세션 활성 확인(AEAssessmentSession 상태 + delegate 중단 콜백) | 시험 창에 WDA_EXCLUDEFROMCAPTURE 적용 후 스스로 캡처해 결과가 비어 있는지 확인. 30초 주기 | MS는 이 플래그가 보안 기능이 아니라고 명시하고 우회 기법이 공개돼 있다 → 자가검증 실패를 crit로 다루는 이유가 이것 |
| S7 / 락다운 이탈 | 평가 모드에서 빠져나온 시각 | AAC 세션 종료·중단 이벤트, presentationOptions 재확인 | Take a Test 프로세스·창 소멸 | 정전·크래시와 구분하기 위해 원장(S9)의 종료 사유와 대조 |
| S14 / 하드웨어 키 검증 | 하트비트가 그 기기에서 나왔는가. 세션 키 복제·재생 공격 차단 | Secure Enclave 키(kSecAttrTokenIDSecureEnclave)로 서명, 공개키는 세션 등록 시 고정 | TPM 2.0 — CNG Microsoft Platform Crypto Provider 키로 서명 | TPM 없는 구형 PC는 소프트웨어 키로 폴백하고 등급을 P1로 낮춰 표기(속이지 않는다) |
| S15 / 서버측 로그 | 학생 기기와 무관하게 게이트웨이·LMS가 남긴 사실 | 게이트웨이: 좌석 IP별 연결·DNS 질의(차단된 목적지 포함). LMS: 문항 표시·응답 제출 타임라인. 콘솔이 세션 시각과 정렬 | 이 신호만이 "에이전트를 껐다"에도 살아남는다. 리포트의 뼈대 | — |

### P1 · 강한 정황

| ID | 무엇을 잡나 | macOS | Windows | 오탐 원인 |
|---|---|---|---|---|
| S1 | 허용목록 밖 프로세스 — Dock/작업표시줄에 없는 에이전트형, 미서명·비공증 | NSWorkspace.runningApplications(activationPolicy .accessory/.prohibited) + proc_listallpids; 서명 SecStaticCodeCreateWithPath → Team ID | CreateToolhelp32Snapshot; WinVerifyTrust + 인증서 주체; GetProcessTimes | Dropbox·Raycast·Karabiner·카카오톡 등 상주 앱 → 학교 공용 허용목록으로 흡수 |
| S2 | 메뉴바/트레이 항목의 소유 프로세스가 허용목록 밖 | 앱별 AXUIElementCreateApplication(pid) → kAXExtrasMenuBarAttribute(접근성). 대체: CGWindowListCopyWindowInfo 레이어 25 → kCGWindowOwnerPID | HKCU\Control Panel\NotifyIconSettings\*의 ExecutablePath·IsPromoted; 라이브는 Shell_TrayWnd/NotifyIconOverflowWindow 툴바 열거 | 정상 유틸의 상태 항목 — S1과 같은 허용목록 |
| S3 | 캡처에서 제외된 창(Cluely형) | CGWindowListCopyWindowInfo의 kCGWindowSharingState == 0인 타 프로세스 창 | EnumWindows → GetWindowDisplayAffinity ≠ WDA_NONE → GetWindowThreadProcessId | 비밀번호 관리자·DRM 플레이어 → 허용목록. 우리 시험 창은 제외 |
| S4 | Caps Lock의 비인간적 토글(≤300ms 주기, 1.5초 내 2회 이상) | 50Hz CGEventSource.flagsState(.hidSystemState)(권한 불필요) | 50Hz GetKeyState(VK_CAPITAL). Windows에서는 이 신호가 사실상 LED 모드의 확정 관측(S12 참조) | Karabiner 등 리매핑, 실제 타이핑 → 주기 규칙성으로 구분 |
| S11 | 캡처 스택 로드 — 화면 캡처 프레임워크를 메모리에 올린 프로세스 | ES NOTIFY_MMAP이 ScreenCaptureKit.framework를 매핑하는 프로세스를 알려준다 | ETW 이미지 로드에서 dxgi.dll·d3d11.dll·Windows.Graphics.Capture 조합. 단 GDI BitBlt 경로는 신호가 없다 | 화상회의·녹화 앱 → 허용목록. Windows는 커버리지가 낮으므로 보조 신호로만 |
| S5 | 네트워크 포스처 — 시험망 여부, 다중 인터페이스, 프로세스별 원격 연결 | beacon/canary; getifaddrs; 프로세스별 소켓 proc_pidinfo(PROC_PIDLISTFDS) | 동일 beacon/canary; GetAdaptersAddresses(RNDIS·Bluetooth PAN); GetExtendedTcpTable(OWNER_PID) | 학교망 장애 시 beacon 실패는 info로만. crit는 canary 성공에만 |
| S6 | VM·원격제어 | sysctl kern.hv_vmm_present; 금지 프로세스 프리셋(RustDesk·AnyDesk·TeamViewer·VNC) | CPUID 하이퍼바이저 비트, SMBIOS 제조사; 같은 프리셋 | 개발 수업의 정당한 VM → 시험 정책에 명시 |
| S8 | 에이전트 무결성 — 자기 서명 검증, 디버거 부착, 시계 조작 | SecCodeCheckValidity(self), P_TRACED; ES NOTIFY_TRACE로 다른 프로세스가 붙는 것도 관측 | Authenticode self-check, CheckRemoteDebuggerPresent; ETW로 핸들 오픈 관측실험 | — |

### 핵심 수집기 스케치

#### S9 · 커널 프로세스 원장 (macOS, Endpoint Security)

```
// 시스템 확장. 엔타이틀먼트: com.apple.developer.endpoint-security.client (Apple 승인 필요)
es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
    switch (msg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_EXEC: {
        const es_process_t *p = msg->event.exec.target;
        emit(Observation{
            .kind = "exec",
            .path = str(p->executable->path),          // ~ 로 치환해 저장
            .cdhash = hex(p->cdhash),                   // 이름을 바꿔도 동일 바이너리면 같은 값
            .signingId = str(p->signing_id),
            .teamId = str(p->team_id),                  // 허용목록의 키
            .platformBinary = p->is_platform_binary,
            .ppid = p->ppid, .ts = msg->time });
        break; }
    case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:              // S12: HID/LED 접근
        emit(.iokitOpen(client: str(msg->event.iokit_open.user_client_class),
                        pid: audit_token_to_pid(msg->process->audit_token)));
        break;
    case ES_EVENT_TYPE_NOTIFY_TCC_MODIFY:              // S10: macOS 15.4+
        // service == "ScreenCapture" && right == ALLOWED  → P0 이벤트
        emit(.tccGrant(service: …, identity: …, right: …, reason: …));
        break;
    }
});
es_subscribe(client, (es_event_type_t[]){ ES_EVENT_TYPE_NOTIFY_EXEC,
    ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT,
    ES_EVENT_TYPE_NOTIFY_MMAP, ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN,
    ES_EVENT_TYPE_NOTIFY_TCC_MODIFY, ES_EVENT_TYPE_NOTIFY_TRACE }, 7);
// AUTH_* 는 구독하지 않는다 — 우리는 차단하는 주체가 아니라 기록하는 주체다.
```

#### S9 · 커널 프로세스 원장 (Windows, ETW)

```
// Windows 서비스 (LocalSystem). 실시간 ETW 세션은 관리자/Performance Log Users 권한 필요.
var session = new TraceEventSession("OwlWatch-Ledger");
session.EnableProvider("Microsoft-Windows-Kernel-Process",
    TraceEventLevel.Informational,
    (ulong)(KernelProcessKeywords.Process | KernelProcessKeywords.Image));

session.Source.Dynamic.All += e => {
    if (e.EventName == "ProcessStart/Start") {
        var path = (string)e.PayloadByName("ImageName");
        Emit(new Observation {
            Kind = "exec", Path = Redact(path),
            Sha256 = Hash(path),                       // cdhash 대응물
            Signer = Authenticode.SubjectOf(path),     // 허용목록의 키
            Ppid = (int)e.PayloadByName("ParentProcessID"),
            Ts   = e.TimeStamp });
    }
    if (e.EventName == "ImageLoad")                    // S11: 캡처 스택
        NoteModule((int)e.ProcessID, (string)e.PayloadByName("ImageName"));
};
// 폴백(서비스 설치 불가 시): WMI __InstanceCreationEvent ON Win32_Process — 폴링 기반이라
// 짧게 살았다 죽는 프로세스를 놓칠 수 있어 등급을 P1로 낮춰 표기한다.
```

#### S13 · 캡처 차단 + 자가검증 (Windows, 관리자 불필요)

```
// 1) 시험 창을 캡처에서 제외 — 화면에는 정상 표시, 캡처 결과에는 내용 없음
SetWindowDisplayAffinity(examHwnd, WDA_EXCLUDEFROMCAPTURE);   // Win10 2004+

// 2) 30초마다: 우리가 직접 캡처해 실제로 비어 있는지 확인
bool StillProtected() {
    if (!GetWindowDisplayAffinity(examHwnd, out var aff) || aff != WDA_EXCLUDEFROMCAPTURE)
        return false;                                  // 누군가 플래그를 되돌림
    using var shot = CaptureScreenRegion(WindowRect(examHwnd));
    return IsUniformBlack(shot);                       // 내용이 보이면 보호가 깨진 것
}
// 실패 → P0 crit "시험 창 캡처 보호 해제됨". MS는 이 플래그를 보안 기능이라고 하지 않으며
// 우회 기법이 공개돼 있다. 그래서 '설정했다'가 아니라 '지금도 유효하다'를 계속 증명한다.
```

### 탐지 규칙

- 등급 우선: P0 하나면 즉시 crit. P1은 같은 프로세스에 2개 이상 겹칠 때만 crit, 하나면 warn. P2는 알림을 만들지 않고 이벤트 본문에만 붙는다.

- 원장 상관: 사용자 공간 스캔 결과(S1·S2)와 커널 원장(S9)이 어긋나면 그 자체가 신호다 — "메뉴바에 항목이 있는데 원장에 실행 기록이 없다"는 원장 우회 시도이고, 반대는 스캔 회피다.

- 허용목록 계층: OS 기본(Apple·Microsoft) → 학교 공용(협업툴·백신·입력기) → 강의별(IDE·VM) → 세션 임시(감독관이 현장에서 허용, 그 시험 동안만). 키는 이름이 아니라 Team ID / 인증서 주체 / cdhash.

- 디바운스: 같은 규칙·같은 대상은 5분에 한 번. 상태 변화(사라짐·재등장)는 별도 이벤트.

- 알림 문구: [확정] 좌석 17 · 09:58 ~/Downloads/helper 실행(미서명, 커널 기록) · 09:59 화면기록 권한 허용 → 화면 오른쪽 위 아이콘 확인. 아이콘 모양 추정·부정행위 단정 금지.

## 06 · 차단 계층

차단의 목적은 하나다 — 커닝 도구가 캡처한 이미지에 문제가 안 보이게 만드는 것. 그러면 아이콘·LED·다중문항이 한꺼번에 무의미해진다. 두 OS는 여기서 경로가 갈린다.

> **그림** — 세 가지 경우 비교. 윈도우는 시험 창에 캡처 제외 플래그를 걸어 커닝 도구의 캡처가 빈 화면이 된다. 승인 전 맥은 캡처를 막지 못해 문제가 그대로 캡처되지만 커널 원장과 권한 관측으로 탐지한다. 평가 모드를 켠 맥은 시스템 전체에서 캡처가 차단된다.
> 
> (원본 아티팩트의 SVG. 저장소 사본에는 설명만 옮겼다.)

그림 4. 같은 공격에 대해 세 환경이 만드는 결과의 차이. 승인 전 macOS만 "캡처가 성공하는" 칸이고, 그 칸을 P0 탐지로 메운다.

#### Windows · 창 캡처 제외 L1
SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE). 창은 모니터에만 표시되고 캡처에는 내용이 나오지 않는다(Win10 2004+). LMS는 앱 안의 WebView2로 띄운다. 관리자도, 어떤 승인도 필요 없다 — 그래서 2주 안에 실전 투입이 가능한 유일한 차단 수단.
MS는 이것이 보안 기능이 아니라고 명시하고 우회 기법도 공개돼 있다. 그래서 S13 자가검증을 30초마다 돌려 "지금도 유효함"을 증명하고, 실패를 crit로 다룬다.
Win10 2004+권한 불필요보안 경계 아님

#### Windows · Take a Test L2
ms-edu-secureassessment:<시험 URL>#enforceLockdown. 잠금 화면 위 전체화면, 캡처 결과 검은 화면, 클립보드 초기화, PrintScreen 비활성, 다른 앱 접근 불가. Windows 10/11.
백그라운드 프로세스는 계속 돈다 — 볼 화면이 없어 무력할 뿐이다. 진입 전 L0 스캔을 강제하고, 창이 사라지면 S7 crit.
승인 불필요Win10/11

#### macOS · AAC L2
AEAssessmentSession. 시스템이 Dock·메뉴바·알림·앱 전환을 막고 화면 캡처를 차단하며 네트워크를 평가 앱에만 허용한다. LMS는 WKWebView로.
선결: com.apple.developer.automatic-assessment-configuration 엔타이틀먼트를 Apple에 신청·승인(SEB가 이 방식). 승인 신청이 크리티컬 패스이므로 이번 주에 넣는다.
Apple 승인 필요macOS 10.15.4+

#### macOS · 승인 전 대안 L1
창 단위 캡처 차단은 없다 — NSWindow.sharingType = .none은 Apple이 레거시로 규정했고 macOS 15.4+ ScreenCaptureKit이 무시한다. 흉내 내지 않는다.
대신 키오스크 라이트(presentationOptions로 Dock·메뉴바 숨김, 앱 전환·강제 종료 비활성)로 아이콘 표시 공간을 없애고, 차단이 아니라 P0 탐지(S9·S10·S12)로 같은 확신을 만든다.
즉시 가능차단 아님 · 탐지

왜 자체 락다운을 만들지 않는가. 프로세스 강제 종료·캡처 차단·네트워크 격리는 OS 평가 모드보다 잘 만들 수 없고, 잘못 만들면 학생 기기를 망가뜨린다. OwlWatch의 차별점은 락다운 자체가 아니라 락다운이 불가능한 시험에서의 P0 근거 확보와 LED 같은 화면 밖 채널의 관측이다.

## 07 · 시험 네트워크

정보전산원과 함께 만드는 정책이지 코드가 아니다. 에이전트는 이 정책이 적용됐는지 증명하고, 게이트웨이는 학생이 손댈 수 없는 P0 로그를 남긴다.

| 항목 | 설계 | 이유 |
|---|---|---|
| SSID / VLAN | 시험 전용 SSID(예: SKHU-EXAM), 시험 시간대만 활성. 클라이언트 격리(AP isolation) | 일반 SSID에 정책을 걸면 다른 수업이 죽는다. 격리는 학생 간 답 공유 차단 |
| 이그레스 | 기본 거부. 허용: LMS, 콘솔(Supabase 호스트), beacon, 시간 동기화. 나머지 전부 차단 — 카테고리 필터가 아니라 목적지 허용목록 | "ChatGPT 차단"은 자체 백엔드 앱에 무의미. 목적지 허용목록만 실효 |
| beacon | 시험 VLAN에서만 라우팅되는 내부 호스트. GET /b → 200 + 세션 salt | 위치 권한·SSID 읽기 없이 "시험망에 있다"를 증명 |
| canary | 동아리가 운영하는 공용 호스트. 게이트웨이는 이를 차단하므로 에이전트는 연결 실패를 기대. 호스트명과 IP를 세션마다 교체 | 연결 성공 = 핫스팟·테더링 → crit. 고정 호스트면 hosts 파일로 위장되므로 세션마다 바꾼다 |
| 서버측 로그 (S15) | 좌석 IP별 연결·DNS 질의 로그를 콘솔이 수집(24h 보관). 차단된 목적지도 기록 | 에이전트를 꺼도 남는 유일한 근거. 리포트의 뼈대 |
| 실패 모드 | beacon 장애 시 warn이 아니라 info("네트워크 확인"). crit는 canary 성공에만 | 학교망 장애로 40명이 동시에 빨간불이 되면 감독관이 시스템을 끈다 |

## 08 · 콘솔·데이터 모델

S.OWL 플랫폼과 같은 스택(Next.js + Supabase)이라 동아리 인프라를 그대로 쓴다.

#### 세션 설정
시험 이름·시간·좌석 수·레벨(L0/L1/L2)·허용목록·증거 보관 기간. 생성 시 세션 코드 발급. 플랫폼별로 어떤 신호가 켜지는지 미리 보여준다(패리티 표를 UI로).

#### 좌석 맵
회색(미접속)·초록(정상)·노랑(P1 warn)·빨강(P0/crit)·검정(하트비트 끊김 30초). 칩에 OS 아이콘과 60초 코드 표시.

#### 알림 피드
등급 배지를 문장 앞에 둔다. 근거 관측값 펼치기 + 처리 버튼("확인함·정상" / "확인함·조치" / "이 앱 허용(이 세션만)"). 모든 처리는 감사 로그.

#### 리포트
P0 확인된 사실 / P1 정황 / P2 참고를 절대 섞지 않고 세 절로 출력. 좌석별 타임라인, 게이트웨이 로그, 증거 번들(해시체인 검증값). 30일 후 자동 삭제.

| 테이블 | 핵심 컬럼 | 비고 |  |  |  |
|---|---|---|---|---|---|
| exams | id, title, starts_at, ends_at, level, owner_id, policy_id, session_code_hash, retention_days | RLS: owner 또는 exam_staff | — | — | — |
| policies | id, scope(school | course | exam), allow jsonb[{teamId,signer,cdhash,note}], deny, thresholds | 버전 관리 | — |
| sessions | id, exam_id, seat, os, agent_version, hw_key_pub, attestation(hw | sw), started_at, last_heartbeat_at, state | 이름 저장 안 함(좌석 + 학번 해시). attestation=sw면 UI에 그대로 표기 | — | — |
| events | id, session_id, ts, grade(P0 | P1 | P2), rule, summary, evidence jsonb, seq, prev_hash, sig | 해시체인 append-only. sig는 기기 하드웨어 키 | — |
| alerts | id, event_id, status(open | ack_ok | ack_action | allowed), handled_by, handled_at, note | 감독관 처리 기록 |
| net_logs | exam_id, seat_ip, ts, dst, action(allow | deny), qname | S15. 게이트웨이가 직접 적재 | — | — |
| audit_log | actor, action, target, ts | 증거 열람·삭제·허용목록 변경 전부 | — | — | — |

```
POST /functions/v1/heartbeat        // Supabase Edge Function
{ "sessionId": "…", "seq": 412, "ts": "2026-10-14T01:20:10Z",
  "state": "armed",
  "posture": { "beacon": true, "canary": false, "ifaces": 1, "captureGuard": "ok" },
  "summary": { "ledgerExecs": 3, "unknownProcs": 0, "statusItems": 3, "capsPatterns": 0 },
  "sig": "…" }          // Secure Enclave / TPM 키 서명. 서버가 등록된 공개키로 검증
// 서버: seq 단조 증가 · 시각 편차 ±30s · 서명 검증 → Realtime 브로드캐스트
// 검증 실패 = S14 (P0). 오프라인이면 로컬 해시체인에 쌓았다가 순서 보존 재전송.
```

## 09 · 세션 상태 기계

> **그림** — 세션 상태: 대기에서 사전점검을 거쳐 준비 상태가 되고, 감독관의 시험 시작으로 감시 상태에 들어가며, 감시 중 경고와 위험 상태를 오가고, 하트비트가 끊기면 오프라인, 시험 종료로 종료와 리포트로 간다
> 
> (원본 아티팩트의 SVG. 저장소 사본에는 설명만 옮겼다.)

그림 5. 세션 상태. PRECHECK에서 커널 원장과 캡처 차단이 실제로 켜졌는지까지 확인해야 READY로 넘어간다.

- PRECHECK는 L0 그 자체이며, L1에서는 여기에 "원장 가동 확인 + 캡처 차단 자가검증 1회 통과"가 추가된다. 둘 중 하나라도 실패하면 READY로 못 간다 — 보호가 꺼진 채 시험이 시작되는 상황을 구조적으로 막는다.

- ARMED 진입은 감독관이 콘솔에서 시작을 누르거나, 학생 화면의 60초 코드가 콘솔과 일치함을 감독관이 확인했을 때만. 학생이 임의로 들어가지 못한다.

- 종료: 시험 종료 후 에이전트는 스스로 종료하고 L1 구성 요소를 제거한다. 상주하지 않는다는 약속을 코드로 지킨다(시스템 확장·서비스는 시험 기간 단위 설치/해제 옵션 제공).

## 10 · 개인정보·투명성

커널 원장을 도입하면 수집 범위가 넓어 보이므로, 오히려 이 장이 더 엄격해져야 한다. 원장은 무엇이 실행됐는가만 남기고 무엇을 했는가는 남기지 않는다.

| 수집 | 수집하지 않음 |
|---|---|
| 실행 파일 경로(홈은 ~로 치환)·해시(cdhash/SHA-256)·서명자·부모 pid·시각 / 메뉴바/트레이 항목의 소유 프로세스 / 창의 캡처 공유 상태(제목 아님) / Caps Lock 상태 전이 시각, HID 디바이스 오픈 사실 / 화면 기록 권한 부여 사실(대상 앱 신원) / 인터페이스 수·beacon/canary 결과·프로세스별 원격 host:port / 캡처 차단 자가검증 결과·하트비트 서명 | 실행 인자(argv)·환경변수, 키 입력, 화면 내용·스크린샷, 창 제목, 클립보드, 파일 내용·목록, 브라우저 방문 기록, 카메라·마이크, 위치·SSID, 학생 이름 |

- ES/ETW 구독 범위를 코드로 제한: AUTH_* 이벤트와 NOTIFY_OPEN/WRITE/READDIR(파일 내용 계열)은 구독하지 않는다. 구독 목록 자체가 감사 대상이며 소스에 상수로 박아 리뷰 가능하게 둔다.

- 동의 화면: 위 표를 그대로 보여주고 "시험 응시 조건으로 동의". L1 설치 시 관리자 권한이 필요한 이유와 제거 방법을 같은 화면에 적는다.

- 학생 상태창: 전송된 이벤트를 감독관이 보는 것과 동일한 형식·등급으로 학생도 본다. 시험 후 로컬 로그 내보내기 가능.

- 보관·삭제: 기본 30일, 이의제기 중인 세션만 연장. 삭제도 감사 로그.

- 법적 정합: 개인정보보호법 제15조(동의)·제16조(최소 수집)·제30조(처리방침). Supabase 리전은 서울로 고정해 국외이전 쟁점을 피한다.

- 소스 공개: 에이전트를 공개한다. "무엇을 안 하는지"를 코드로 증명하는 가장 싼 방법이고, 허용목록·임계값은 서버 정책이라 공개해도 손실이 적다.

## 11 · 자기 보호와 우회

| 우회 시도 | 완화 | 남는 한계 |
|---|---|---|
| 스캔 직전 종료 → 시험 중 재실행 | 해결됨 — 커널 원장(S9)이 재실행 순간을 기록. v0.1의 최대 구멍이었다 | 원장 자체를 끄면 하트비트 요약의 ledgerExecs가 멈춰 OFFLINE·무결성 crit |
| 에이전트 종료·가짜 하트비트 | 하드웨어 키 서명(S14) + seq 단조성 + 서버 시각 검증. 30초 내 OFFLINE 표시. 게이트웨이 로그(S15)는 계속 남음 | 서명된 바이너리를 패치하면 무결성 검사도 패치 가능 — 최종적으로는 감독관 육안과 서버측 로그에 의존 |
| 캡처 차단 플래그 되돌리기(Windows) | S13 자가검증이 30초마다 실제 캡처로 확인 → 되돌리는 즉시 P0 crit | DWM 하위에서 합성 결과를 가져가는 우회는 창 플래그로 못 막는다 → L2(Take a Test)가 답 |
| 이름·서명 위장 | 이름이 아니라 Team ID/인증서 주체/cdhash로 대조. 미서명·자체 서명은 그 자체가 정황 | 유출된 정상 서명, 정상 앱에 기생하는 플러그인 형태 |
| VM 안에서 시험, 호스트에서 커닝 | S6 VM 탐지 → 정책상 금지면 crit | 중첩 가상화·베어메탈 위장 |
| 핫스팟으로 시험망 회피 | S5 canary(세션마다 호스트·IP 교체) → crit. L2에서는 앱 외 네트워크가 아예 차단 | 기기 두 대를 쓰면 네트워크 통제 밖 |
| Caps Lock 대신 백라이트·화면 밝기·팬 소음 | HID 디바이스 오픈(S12)이 macOS에서는 그대로 잡힌다. L2면 입력 자체가 없다 | Windows L0/L1에서는 못 잡음 — 정책 문구("위장 신호 일체")와 감독으로 |
| 휴대폰·AI 안경·2차 기기 | 범위 밖 | 평가 설계·대면 회귀만이 답 |

기대치 관리. OwlWatch는 "커닝을 불가능하게" 만드는 도구가 아니라 노트북 상주형 도구의 비용과 발각 확률을 크게 올리고, 발각됐을 때 다툴 수 없는 근거를 남기는 도구다. 콘솔 첫 화면과 학교 제안서에 이 문장을 그대로 넣는다.

## 12 · 테스트 계획

- 시뮬레이터 owlwatch-sim(양 플랫폼, 정답 기능 없음): (a) 상태 항목 아이콘 주기 교체, (b) Caps Lock 패턴 토글, (c) HID 디바이스 오픈만 하고 아무것도 안 하기, (d) canary POST, (e) 캡처 제외 창 생성, (f) 미서명/자체서명/Downloads 실행 변형, (g) 스캔 회피 시나리오 — 사전점검 직전 종료 후 30초 뒤 재실행. (g)가 v0.2의 핵심 회귀 테스트다.

- 탐지기 회귀: 수집기 출력을 JSON 픽스처로 녹화해 규칙 엔진을 플랫폼 없이 테스트. 같은 픽스처가 macOS·Windows 양쪽 수집기에서 나와야 하며, 등급이 어긋나면 실패로 처리한다(패리티 테스트).

- 오탐 코퍼스: Dropbox·OneDrive·Raycast·Alfred·Bartender·Karabiner·카카오톡·Discord·Notion·1Password·백신·한컴 입력기 등 상주 앱 30종 → 학교 공용 허용목록 초안이 여기서 나온다. 목표는 좌석당 warn ≤0.2건, P0 오탐 0건.

- 플랫폼 매트릭스: macOS 13/14/15/26(Intel·Apple Silicon) — 15.4 미만은 S10 없음을 UI에 표기. Windows 10 22H2 / 11 24H2, TPM 유무 각각.

- 차단 검증: Windows에서 시험 창을 띄운 뒤 PrintScreen·Snipping Tool·OBS·시뮬레이터 캡처로 각각 결과가 비는지 확인. 비지 않는 경로가 있으면 그 경로를 문서에 한계로 명시한다.

- 레드팀: 교수·학사팀 승인 하에 시뮬레이터 변형만으로, 동아리원끼리. 결과는 우회 방법이 아니라 "탐지 실패 → 수정" 이슈로만 기록.

- 파일럿: T2 시험 2개(각 30–40명) — 하나는 Windows 위주, 하나는 macOS 위주. 측정: 스캔 소요, 학생 문의 수, 오탐, 감독관 처리 시간.

## 13 · 로드맵·스택

- M0 · 이번 주Apple 엔타이틀먼트 2건 신청(ESF · AAC) · Developer ID / EV 코드서명 인증서 · 스펙 저장소승인 대기가 가장 긴 항목이라 무조건 먼저. 학교 개발자 계정 명의가 현실적.

- M1 · 2주Windows 캡처 차단 + 자가검증(L1) · ExamCheck 양 플랫폼(L0)승인이 필요 없는 유일한 차단 수단이라 가장 먼저 실전에 들어간다. 시뮬레이터 (a)(b)(d)(e)(f)(g) 동시 작성.

- M2 · 3주콘솔 MVP — 세션·좌석 맵·등급 알림·리포트, 하트비트 서명 검증S.OWL 플랫폼의 Auth/RLS 패턴 재사용.

- M3 · 4주Windows ETW 원장 서비스(S9·S11) + TPM 키(S14) · 시험 SSID 정책 초안여기서 Windows가 P0 등급에 도달한다.

- M4 · 5주macOS ESF 시스템 확장(S9·S10·S12) + Secure Enclave 키 — 승인 도착 시미승인 시 L0 + 키오스크 라이트로 파일럿 진행하고 승인 후 교체.

- M5 · 6주중간고사 파일럿 2건(Windows/macOS 각 1) → 회고 → 허용목록·임계값 조정

- M6 · 기말 전L2 — Windows Take a Test 연동, macOS AAC(승인 시) · 게이트웨이 로그 수집(S15)

### 저장소 구조

```
owlwatch/
  spec/            Observation·Event·Policy JSON Schema, 허용목록, 크로스플랫폼 픽스처
  agent-macos/     Swift · App/ + SystemExtension(EndpointSecurity)/ · Developer ID 서명·공증
  agent-windows/   C# .NET 8 · App(WebView2 + 캡처차단)/ + Service(ETW)/ · EV 서명 · MSI
  core-rules/      탐지 규칙·등급 판정 순수 로직 (양쪽에서 같은 픽스처로 테스트)
  console/         Next.js 15 + Supabase · functions/heartbeat · migrations
  sim/             owlwatch-sim (macOS/Windows) · 정답 기능 없음 · 용도 제한 명시
  docs/            이 설계서 · 처리방침 · 감독관 지침 · 학칙 문구 제안
```

## 14 · 미결 사항

- Apple 엔타이틀먼트 2건(ESF·AAC)을 학생 동아리 명의로 받을 수 있는지 — 학교 개발자 계정 경유가 현실적. 승인 실패 시 macOS는 L0 + 키오스크 라이트가 상한이 된다.

- Windows에서 실시간 ETW 세션의 최소 권한 — 관리자 대신 Performance Log Users 그룹으로 충분한지, 학교 이미지에 그룹을 미리 넣어둘 수 있는지 확인 실험.

- Windows LED 전용 제어(상태 변화 없는 점멸)가 비관리자 앱에서 실제로 가능한지 — 가능하다면 Windows S12에 구멍이 생기므로 시뮬레이터로 먼저 확인 실험.

- WDA_EXCLUDEFROMCAPTURE가 막지 못하는 캡처 경로 목록(DWM 하위, 하드웨어 캡처 카드, 원격 데스크톱) — 검증 후 한계로 명시.

- macOS 26에서 S2의 AX 경로 동작(상태 항목이 Control Center로 귀속되는 회귀) — 실기기 확인.

- 학교가 이미 쓰는 시험 도구(TrustLock 등)와의 공존 — L0는 공존 가능, L2는 택일. 충돌 시 우선순위 규칙 필요.

- 기기 지문·하드웨어 키 공개키의 보관 범위 — 학기 단위 폐기로 할지 시험 단위로 할지.

- 이름. OwlWatch는 가칭.

S.OWL 내부 설계서 v0.2 · 2026-08-28 · API 이름과 동작은 Apple·Microsoft 공개 문서 기준이며, 실기기 검증 전 항목은 실험으로 표시. 이 도구는 부정행위를 판정하지 않는다.


