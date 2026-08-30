-- OwlWatch 콘솔 스키마. 설계서 08장 표를 그대로 옮긴다.
--
-- 두 가지가 스키마 수준에서 강제된다.
--   1) events 는 append-only 해시체인이다. UPDATE·DELETE 를 막고 seq 단조성을 제약으로 건다.
--      "증거를 나중에 고쳤다"는 반론을 코드가 아니라 DB 가 막아야 한다.
--   2) 학생 이름을 담을 컬럼이 없다. 좌석 번호와 학번 해시뿐이다(설계서 10장 비수집).

create extension if not exists pgcrypto;

-- ── 정책 ─────────────────────────────────────────────────────────

create table policies (
  id            text primary key,
  scope         text not null check (scope in ('os','school','course','session')),
  version       integer not null default 1,
  note          text,
  comments      jsonb not null default '[]'::jsonb,
  allow         jsonb not null default '[]'::jsonb,
  deny          jsonb not null default '[]'::jsonb,
  thresholds    jsonb not null default '{}'::jsonb,
  capture_stack_modules jsonb not null default '[]'::jsonb,
  policy_notes  jsonb not null default '{}'::jsonb,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

comment on table policies is '허용목록 계층. 키는 이름이 아니라 Team ID / 인증서 주체 / cdhash.';

-- ── 시험 ─────────────────────────────────────────────────────────

create table exams (
  id                uuid primary key default gen_random_uuid(),
  title             text not null,
  starts_at         timestamptz not null,
  ends_at           timestamptz not null,
  level             text not null check (level in ('L0','L1','L2')),
  owner_id          uuid not null references auth.users(id),
  policy_id         text references policies(id),
  session_code_hash text not null,
  retention_days    integer not null default 30 check (retention_days between 1 and 365),
  exam_url          text,
  created_at        timestamptz not null default now(),
  constraint exam_window check (ends_at > starts_at)
);

comment on column exams.session_code_hash is
  '세션 비밀은 해시로만 저장한다. 감독관 대조용 표식이지 인증이 아니다.';

-- 감독 인력. 소유자 외에 이 시험을 볼 수 있는 사람.
create table exam_staff (
  exam_id uuid not null references exams(id) on delete cascade,
  user_id uuid not null references auth.users(id),
  role    text not null default 'proctor' check (role in ('proctor','reviewer')),
  primary key (exam_id, user_id)
);

-- ── 좌석 세션 ────────────────────────────────────────────────────

create table sessions (
  id                uuid primary key default gen_random_uuid(),
  exam_id           uuid not null references exams(id) on delete cascade,
  seat              integer,
  student_hash      text,
  os                text not null check (os in ('windows','macos')),
  agent_version     text not null,
  hw_key_pub        text not null,
  attestation       text not null check (attestation in ('hw','sw')),
  ledger            text not null default 'fallback' check (ledger in ('kernel','fallback','off')),
  last_seq          integer not null default 0,
  started_at        timestamptz not null default now(),
  last_heartbeat_at timestamptz,
  state             text not null default 'precheck'
                    check (state in ('idle','precheck','ready','armed','warn','crit','offline','ended')),
  posture           jsonb not null default '{}'::jsonb,
  summary           jsonb not null default '{}'::jsonb,
  arm_pending       boolean not null default false,
  unique (exam_id, seat)
);

comment on column sessions.student_hash is
  '학번 해시. 이름은 저장하지 않는다.';
comment on column sessions.attestation is
  'sw 면 이 기기는 하드웨어로 신원을 증명하지 못한다. UI 에 그대로 표기한다 — 속이지 않는다.';
comment on column sessions.ledger is
  'kernel 이 아니면 S9 이 P0 를 만들지 못한다. 리포트가 이 값을 근거로 등급을 설명한다.';

-- ── 이벤트 · append-only 해시체인 ────────────────────────────────

create table events (
  id         bigserial primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  seq        integer not null,
  ts         timestamptz not null,
  grade      text not null check (grade in ('P0','P1','P2')),
  severity   text not null check (severity in ('info','warn','crit')),
  rule       text not null,
  signals    text[] not null,
  summary    text not null,
  subject    jsonb not null,
  evidence   jsonb not null,
  contexts   text[] not null default '{}',
  prev_hash  char(64) not null,
  hash       char(64) not null,
  sig        text,
  received_at timestamptz not null default now(),
  unique (session_id, seq),
  unique (session_id, hash)
);

create index events_session_seq on events (session_id, seq);
create index events_grade on events (grade) where grade = 'P0';

comment on table events is
  '설계서 02장: P0만 확인된 사실이다. 리포트는 P0/P1/P2 를 절대 섞지 않는다.';

-- 증거는 고쳐지지 않는다. 트리거로 막는다 — 애플리케이션 코드를 믿지 않는다.
create or replace function events_append_only() returns trigger
language plpgsql as $$
begin
  raise exception '이벤트는 append-only 다. 수정·삭제할 수 없다 (증거 무결성).';
end;
$$;

create trigger events_no_update before update on events
  for each row execute function events_append_only();
create trigger events_no_delete before delete on events
  for each row execute function events_append_only();

-- 체인이 이어지는지 삽입 시점에 확인한다.
create or replace function events_check_chain() returns trigger
language plpgsql as $$
declare
  prev record;
begin
  select seq, hash into prev from events
   where session_id = new.session_id order by seq desc limit 1;

  if prev is null then
    if new.seq <> 1 then
      raise exception '첫 이벤트의 seq 는 1 이어야 한다 (받은 값 %)', new.seq;
    end if;
    if new.prev_hash <> repeat('0', 64) then
      raise exception '첫 이벤트의 prev_hash 는 제네시스여야 한다';
    end if;
  else
    if new.seq <> prev.seq + 1 then
      raise exception 'seq 가 이어지지 않는다 (이전 %, 받은 %)', prev.seq, new.seq;
    end if;
    if new.prev_hash <> prev.hash then
      raise exception '해시체인이 끊겼다 — 이벤트가 빠졌거나 조작됐다';
    end if;
  end if;
  return new;
end;
$$;

create trigger events_chain before insert on events
  for each row execute function events_check_chain();

-- ── 알림 처리 ────────────────────────────────────────────────────

create table alerts (
  id         bigserial primary key,
  event_id   bigint not null references events(id) on delete cascade,
  status     text not null default 'open'
             check (status in ('open','ack_ok','ack_action','allowed')),
  handled_by uuid references auth.users(id),
  handled_at timestamptz,
  note       text,
  unique (event_id)
);

comment on table alerts is
  'P2 는 알림을 만들지 않는다. 설계서 02장 — 단독으로는 아무 의미 없는 등급이다.';

-- P2 로는 알림을 만들지 못하게 막는다.
create or replace function alerts_reject_p2() returns trigger
language plpgsql as $$
declare g text;
begin
  select grade into g from events where id = new.event_id;
  if g = 'P2' then
    raise exception 'P2 이벤트로는 알림을 만들지 않는다 (설계서 02장)';
  end if;
  return new;
end;
$$;

create trigger alerts_no_p2 before insert on alerts
  for each row execute function alerts_reject_p2();

-- ── 서버측 로그 (S15) ────────────────────────────────────────────

create table net_logs (
  id       bigserial primary key,
  exam_id  uuid not null references exams(id) on delete cascade,
  seat_ip  inet not null,
  ts       timestamptz not null,
  dst      text,
  action   text not null check (action in ('allow','deny')),
  qname    text
);

create index net_logs_exam_ts on net_logs (exam_id, ts);

comment on table net_logs is
  'S15. 게이트웨이가 직접 적재한다. 에이전트를 껐을 때도 살아남는 유일한 근거 — 리포트의 뼈대.';

-- ── 감사 로그 ────────────────────────────────────────────────────

create table audit_log (
  id     bigserial primary key,
  actor  uuid references auth.users(id),
  action text not null,
  target text not null,
  detail jsonb not null default '{}'::jsonb,
  ts     timestamptz not null default now()
);

comment on table audit_log is
  '증거 열람·삭제·허용목록 변경을 전부 남긴다(설계서 10장). 삭제도 감사 대상이다.';

-- ── RLS ──────────────────────────────────────────────────────────
-- 기본은 거부. 시험 소유자와 배정된 감독만 본다.

alter table exams      enable row level security;
alter table exam_staff enable row level security;
alter table sessions   enable row level security;
alter table events     enable row level security;
alter table alerts     enable row level security;
alter table net_logs   enable row level security;
alter table audit_log  enable row level security;
alter table policies   enable row level security;

create or replace function can_see_exam(target uuid) returns boolean
language sql security definer stable as $$
  select exists (select 1 from exams e where e.id = target and e.owner_id = auth.uid())
      or exists (select 1 from exam_staff s where s.exam_id = target and s.user_id = auth.uid());
$$;

create policy exams_read on exams for select using (can_see_exam(id));
create policy exams_write on exams for all using (owner_id = auth.uid()) with check (owner_id = auth.uid());

create policy staff_read on exam_staff for select using (can_see_exam(exam_id));

create policy sessions_read on sessions for select using (can_see_exam(exam_id));
create policy sessions_write on sessions for update using (can_see_exam(exam_id));

create policy events_read on events for select
  using (can_see_exam((select exam_id from sessions where id = events.session_id)));

create policy alerts_read on alerts for select
  using (can_see_exam((select s.exam_id from events e join sessions s on s.id = e.session_id
                        where e.id = alerts.event_id)));
create policy alerts_write on alerts for all
  using (can_see_exam((select s.exam_id from events e join sessions s on s.id = e.session_id
                        where e.id = alerts.event_id)));

create policy net_logs_read on net_logs for select using (can_see_exam(exam_id));
create policy audit_read on audit_log for select using (true);
create policy policies_read on policies for select using (true);

-- 에이전트는 anon 키로 직접 쓰지 않는다. heartbeat Edge Function 이 service_role 로
-- 서명을 검증한 뒤에만 쓴다 — 클라이언트를 믿지 않는다(설계서 P4).

-- ── 보관 기간 ────────────────────────────────────────────────────

create or replace function purge_expired() returns integer
language plpgsql security definer as $$
declare n integer;
begin
  with gone as (
    delete from sessions s
     using exams e
     where s.exam_id = e.id
       and e.ends_at < now() - (e.retention_days || ' days')::interval
    returning s.id
  )
  select count(*) into n from gone;

  insert into audit_log (actor, action, target, detail)
  values (null, 'purge', 'sessions', jsonb_build_object('deleted', n));
  return n;
end;
$$;

comment on function purge_expired is
  '기본 30일. 이의제기 중인 세션은 retention_days 를 늘려 보존한다. 삭제도 감사 로그에 남는다.';
