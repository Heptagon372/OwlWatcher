# console — 감독관 콘솔 (M2)

설계서 08장. Next.js 15 + Supabase.

```bash
npm install
npm run dev
```

## 왜 여기만 의존성이 있는가

저장소의 나머지(에이전트·규칙 엔진·시뮬레이터)는 NuGet·npm 의존성이 없다. 시험장 PC 에
오프라인으로 배포해야 하고, "무엇을 안 하는지"를 코드로 증명해야 하기 때문이다.

콘솔은 학생 기기에 설치되지 않는 웹 앱이라 그 제약이 적용되지 않는다.
설계서가 지정한 대로 S.OWL 플랫폼과 같은 스택(Next.js + Supabase)을 쓴다.

## 설정

| 환경변수 | 무엇 |
|---|---|
| `NEXT_PUBLIC_SUPABASE_URL` | 프로젝트 URL. **리전은 서울로 고정** (설계서 10장 국외이전) |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | 익명 키. 읽기는 RLS 가 막는다 |

`service_role` 키는 콘솔에 넣지 않는다. 브라우저에 유출되는 순간 RLS 가 무의미해진다 —
쓰기는 Edge Function 만 한다.

설정하지 않으면 첫 화면이 그렇게 말하고, 개발 중에는 [`mock-server/`](../mock-server) 가
같은 하트비트 계약을 구현하므로 Supabase 계정 없이 전체 흐름을 볼 수 있다.

## 구조

```
app/
  page.tsx                    시험 목록
  exams/[id]/page.tsx         좌석 맵 + 알림 피드
  exams/[id]/report/page.tsx  리포트 — P0/P1/P2 를 세 절로
lib/
  types.ts   labels.ts   supabase.ts
supabase/
  migrations/0001_init.sql          설계서 08장 표 그대로
  functions/heartbeat/              seq · 시각 · 서명 검증
  functions/session-register/       기기 공개키 고정
  functions/_shared/canonical.ts    정규화 JSON (세 번째 구현)
```

## 스키마가 강제하는 것

애플리케이션 코드를 믿지 않는다. DB 가 막는다.

| 규칙 | 어떻게 |
|---|---|
| 이벤트는 append-only | UPDATE·DELETE 트리거가 예외를 던진다 |
| 해시체인이 이어져야 한다 | INSERT 트리거가 seq 연속성과 prev_hash 를 확인한다 |
| P2 로 알림을 만들지 않는다 | `alerts` INSERT 트리거가 거부한다 (설계서 02장) |
| 학생 이름을 저장하지 않는다 | 담을 컬럼이 없다. 좌석 번호와 학번 해시뿐 |
| 시험 소유자·감독만 본다 | RLS 기본 거부 + `can_see_exam()` |
| 보관 기간 뒤 삭제 | `purge_expired()`, 삭제도 감사 로그에 남는다 |

## 리포트가 하는 일

P0(확인된 사실) · P1(정황) · P2(참고)를 **절대 섞지 않고** 세 절로 낸다.
좌석 중에 커널 원장을 못 쓴 곳이나 소프트웨어 키로 서명한 곳이 있으면 리포트 맨 위에
그 사실을 먼저 적는다 — 등급을 읽는 사람이 무엇을 근거로 읽고 있는지 알아야 하기 때문이다.

## 아직 없는 것

- 인증 UI (Supabase Auth 를 붙여야 한다)
- 알림 처리 버튼 — `확인함·정상` / `확인함·조치` / `이 앱 허용(이 세션만)`
- 증거 번들 내보내기 (에이전트 쪽에는 있다)
- 정책 편집 UI — 지금은 SQL 로 넣는다
- Realtime 구독 — 지금은 3초 폴링
