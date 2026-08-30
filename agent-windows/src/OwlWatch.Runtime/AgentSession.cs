using System.Text.Json.Nodes;
using OwlWatch.Collectors;
using OwlWatch.Core;
using OwlWatch.Rules;

namespace OwlWatch.Runtime;

/// <summary>설계서 09장 세션 상태 기계.</summary>
public enum SessionState
{
    Idle,      // 시작 전
    Precheck,  // L0 점검 + (L1) 원장 가동 확인 + 캡처 차단 자가검증
    Ready,     // 감독관의 시작을 기다림
    Armed,     // 감시 중
    Warn,      // 정황
    Crit,      // 확인 필요
    Offline,   // 하트비트 끊김
    Ended,
}

/// <summary>
/// L1 에이전트의 세션 하나. 수집기·규칙 엔진·저장소·하트비트를 묶는다.
///
/// 설계서 09장의 핵심 두 가지를 코드로 지킨다.
///   · PRECHECK 를 통과하지 못하면 READY 로 갈 수 없다 — 보호가 꺼진 채 시험이 시작되는
///     상황을 구조적으로 막는다.
///   · ARMED 진입은 감독관이 시작을 눌렀거나 60초 코드가 대조됐을 때만. 학생이 임의로 못 들어간다.
/// </summary>
public sealed class AgentSession : IDisposable
{
    private readonly SessionConfig _cfg;
    private readonly Policy _policy;
    private readonly SessionInfo _session;
    private readonly EngineState _engine = new();
    private readonly EventStore _store;
    private readonly Attestation _attest;
    private readonly HeartbeatClient _heartbeat;
    private readonly LedgerPoller _poller;
    private readonly EtwLedgerCollector _etw;
    private readonly CapsLockCollector _caps = new();
    private readonly string _workDir;

    private CaptureGuard? _guard;
    private bool _etwActive;
    private bool _lockdownEntered;
    private JsonObject _lastPosture;
    private int _ifaceCount = 1;
    private bool _beacon, _canary;

    public SessionState State { get; private set; } = SessionState.Idle;
    public string? PrecheckFailure { get; private set; }
    public IReadOnlyList<JsonObject> Events => _all;
    public string ChainHead => _engine.PrevHash;
    public string AttestationKind => _attest.Kind;
    public bool Online => _heartbeat.Online;
    public string? LastError => _heartbeat.LastError;
    public CaptureGuard.GuardStatus GuardStatus => _guard?.Status ?? CaptureGuard.GuardStatus.Off;

    /// <summary>kernel | fallback. 이 값이 S9 의 등급 상한을 정한다.</summary>
    public string LedgerMode => _session.Ledger;

    /// <summary>커널 원장을 못 쓴 이유. 폴백일 때만 채워진다.</summary>
    public string? LedgerFallbackReason { get; private set; }

    /// <summary>
    /// L2 락다운 진입. 화면이 전체화면 잠금으로 바뀌므로 사전 점검을 통과하고
    /// 감독관이 시작을 확인한 뒤에만 불러야 한다(설계서 06장).
    /// </summary>
    public bool EnterLockdown(string examUrl, out string error)
    {
        if (!LockdownCollector.Launch(examUrl, out error)) return false;
        _lockdownEntered = true;
        return true;
    }

    private readonly List<JsonObject> _all = new();

    public event Action<IReadOnlyList<JsonObject>>? EventsAdded;
    public event Action<SessionState>? StateChanged;

    public AgentSession(SessionConfig cfg, Policy policy)
    {
        _cfg = cfg;
        _policy = policy;
        _workDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "OwlWatch", Sanitize(cfg.SessionId));
        Directory.CreateDirectory(_workDir);

        _session = cfg.ToSessionInfo(ledger: "fallback", agentPid: Environment.ProcessId);
        _store = new EventStore(Path.Combine(_workDir, "events.jsonl"));
        _attest = Attestation.Create($"OwlWatch-{Sanitize(cfg.SessionId)}", _workDir);
        _heartbeat = new HeartbeatClient(cfg, _attest);
        _poller = new LedgerPoller();
        _etw = new EtwLedgerCollector(policy.CaptureStackModules);
        _lastPosture = _heartbeat.Posture(false, false, 1, "off");
    }

    private static string Sanitize(string s) =>
        string.Concat(s.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_'));

    public string WorkDir => _workDir;

    /// <summary>
    /// PRECHECK. 세 가지를 확인한다 — 기준선 점검, 원장 가동, 캡처 차단 자가검증.
    /// 하나라도 실패하면 READY 로 넘어가지 않는다.
    /// </summary>
    /// <param name="sentinelRect">시험 창이 센티넬 색으로 칠한 띠의 화면 좌표.</param>
    /// <param name="settle">기다리는 동안 메시지 펌프를 돌리는 콜백.</param>
    public async Task<bool> PrecheckAsync(
        IntPtr examWindow, Func<ScreenRect> sentinelRect, Action<int> settle, CancellationToken ct = default)
    {
        Transition(SessionState.Precheck);
        PrecheckFailure = null;

        // 1) 기준선 스캔. 이 결과가 원장 상관의 기준선이 된다.
        var scan = await Scanner.RunAsync(_cfg, _policy, Environment.ProcessId, ct).ConfigureAwait(false);
        RecordPosture(scan.Observations);
        Ingest(scan.Observations, scan.Scanned);

        // 2) 캡처 차단 자가검증 — L1 의 존재 이유다.
        if (_cfg.Level is "L1" or "L2")
        {
            _guard = new CaptureGuard(examWindow, sentinelRect, settle);
            if (!_guard.Arm(out var reason))
            {
                PrecheckFailure = $"캡처 차단을 걸지 못했다 — {reason}\n\n{_guard.Diagnostics}";
                Transition(SessionState.Idle);
                return false;
            }
            Ingest(new List<JsonObject> { _guard.Verify(DateTimeOffset.UtcNow) }, new List<string>());
        }

        // 3) 원장 가동. 커널을 먼저 시도하고, 안 되면 폴링으로 내려간다.
        //    이 선택이 S9 의 등급 상한을 정한다 — 커널이면 P0, 폴링이면 P1.
        //    도는 척하는 경로는 없다. 못 열면 못 열었다고 말하고 등급이 따라 내려간다.
        if (_etw.Start())
        {
            _session.Ledger = "kernel";
            _etwActive = true;
        }
        else
        {
            _session.Ledger = "fallback";
            LedgerFallbackReason = _etw.FailureReason;
            _poller.Prime(scan.Processes);
            _poller.Start();
        }
        _caps.Start();

        // 4) 서버 등록 (콘솔이 없으면 건너뛴다 — L0/L1 모두 콘솔 없이도 동작해야 한다)
        await _heartbeat.RegisterAsync(_session.Ledger, ct).ConfigureAwait(false);

        Transition(SessionState.Ready);
        return true;
    }

    /// <summary>감독관이 시작을 눌렀다. 학생이 임의로 부를 수 없는 경로여야 한다.</summary>
    public bool Arm()
    {
        if (State != SessionState.Ready) return false;
        Transition(SessionState.Armed);
        return true;
    }

    /// <summary>주기 작업 한 번 — 스캔·원장·Caps·자가검증을 모아 규칙 엔진에 넣고 하트비트를 보낸다.</summary>
    public async Task TickAsync(bool fullScan, CancellationToken ct = default)
    {
        if (State is SessionState.Idle or SessionState.Ended) return;

        var obs = new List<JsonObject>();
        var scanned = new List<string>();

        obs.AddRange(_etwActive ? _etw.Drain() : _poller.Drain());
        obs.AddRange(_caps.Drain());

        if (_guard is not null)
            obs.Add(_guard.Verify(DateTimeOffset.UtcNow));

        obs.Add(HostCollector.Integrity(DateTimeOffset.UtcNow, _heartbeat.ClockSkewMs));

        // L2 는 락다운이 유지되는지가 곧 보호 상태다. 빠져나가면 S7 (P0 crit).
        if (_cfg.Level == "L2" && _lockdownEntered)
            obs.Add(LockdownCollector.Observe(DateTimeOffset.UtcNow));
        obs.Add(_attest.Observation(DateTimeOffset.UtcNow, verified: true));

        if (fullScan)
        {
            var scan = await Scanner.RunAsync(_cfg, _policy, Environment.ProcessId, ct).ConfigureAwait(false);
            RecordPosture(scan.Observations);
            obs.AddRange(scan.Observations);
            scanned = scan.Scanned;
        }

        Ingest(obs, scanned);

        var ok = await _heartbeat.SendAsync(StateText(State), _lastPosture,
            _engine.Counters.ToJson(), ct).ConfigureAwait(false);

        // 감독관이 콘솔에서 시작을 눌렀는가. 학생 쪽에서 만들 수 없는 경로다.
        if (_heartbeat.TakeCommand() == "arm") Arm();

        if (!string.IsNullOrEmpty(_cfg.ConsoleBaseUrl))
        {
            if (!ok && State is SessionState.Armed or SessionState.Warn or SessionState.Crit)
                Transition(SessionState.Offline);
            else if (ok && State == SessionState.Offline)
                Transition(SessionState.Armed);
        }
    }

    private void RecordPosture(IEnumerable<JsonObject> obs)
    {
        foreach (var o in obs)
        {
            if (o.Str("kind") != "netPosture") continue;
            _beacon = o.Bool("beacon") ?? false;
            _canary = o.Bool("canary") ?? false;
            _ifaceCount = o.Int("ifaceCount") ?? 1;
        }
        _lastPosture = _heartbeat.Posture(_beacon, _canary, _ifaceCount,
            CaptureGuard.StatusText(_guard?.Status ?? CaptureGuard.GuardStatus.Off));
    }

    private void Ingest(List<JsonObject> obs, List<string> scanned)
    {
        if (obs.Count == 0 && scanned.Count == 0) return;

        var result = RuleEngine.Evaluate(obs, scanned, _policy, _session, _engine);
        if (result.Events.Count == 0) return;

        _store.Append(result.Events);
        _heartbeat.Enqueue(result.Events);
        _all.AddRange(result.Events);
        EventsAdded?.Invoke(result.Events);

        // 심각도가 상태를 끌어올린다. 내려가지는 않는다 — 한 번 확인이 필요했다는 사실은 남는다.
        if (State is SessionState.Armed or SessionState.Warn)
        {
            if (result.Events.Any(e => e.Str("severity") == "crit")) Transition(SessionState.Crit);
            else if (result.Events.Any(e => e.Str("severity") == "warn") && State == SessionState.Armed)
                Transition(SessionState.Warn);
        }
    }

    private void Transition(SessionState next)
    {
        if (State == next) return;
        State = next;
        StateChanged?.Invoke(next);
    }

    public static string StateText(SessionState s) => s switch
    {
        SessionState.Idle => "idle",
        SessionState.Precheck => "precheck",
        SessionState.Ready => "ready",
        SessionState.Armed => "armed",
        SessionState.Warn => "warn",
        SessionState.Crit => "crit",
        SessionState.Offline => "offline",
        _ => "ended",
    };

    public string Code() => SessionCode.Derive(_cfg.SessionCode ?? _cfg.SessionId, ChainHead, DateTimeOffset.UtcNow);

    public JsonObject ExportBundle() => _store.ExportBundle(_cfg);

    /// <summary>
    /// 종료. 설계서 09장: "에이전트는 스스로 종료하고 L1 구성 요소를 제거한다.
    /// 상주하지 않는다는 약속을 코드로 지킨다."
    /// 이벤트 로그는 남긴다 — 학생이 자기 기록을 내보낼 수 있어야 하고, 보관 기간 뒤 지워진다.
    /// </summary>
    public void End()
    {
        Transition(SessionState.Ended);
        _guard?.Release();
        _etw.Dispose();
        _poller.Dispose();
        _caps.Dispose();
        _attest.Dispose();   // TPM 세션 키·소프트웨어 키 삭제

        var audit = Path.Combine(_workDir, "..", "audit.log");
        using var w = new StreamWriter(audit, append: true, J.Utf8NoBom);
        EventStore.PurgeExpired(Path.GetDirectoryName(_store.FilePath)!, _cfg.RetentionDays, w);
        w.WriteLine($"{DateTimeOffset.UtcNow:O}\tsession-end\t{_cfg.SessionId}\t이벤트 {_all.Count}건, 체인 헤드 {ChainHead}");
    }

    public void Dispose() => End();
}
