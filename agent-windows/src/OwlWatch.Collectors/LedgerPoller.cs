using System.Text.Json.Nodes;
using OwlWatch.Core;

namespace OwlWatch.Collectors;

/// <summary>
/// S9 · 프로세스 원장 — M1 의 폴백 경로.
///
/// 설계서의 본 경로는 ETW Microsoft-Windows-Kernel-Process 실시간 세션이고, 그건
/// 관리자/Performance Log Users 권한이 필요해서 서비스로 돌려야 한다(M3, 14장 미결 2번).
/// 그때까지는 프로세스 스냅샷 차분으로 같은 종류의 사실을 만든다.
///
/// 등급은 자동으로 내려간다. source=userspace · degraded=true 이므로 규칙 엔진이
/// P0 을 P1 로 낮추고 그 이유를 증거에 적는다 — 폴링은 짧게 살았다 죽는 프로세스를
/// 놓치므로 "시험 구간의 모든 실행"을 봤다고 말할 수 없기 때문이다.
/// 이 강등이 코드 한 곳(RuleEngine.Push)에서만 일어나는 것이 요점이다. 수집기가
/// 등급을 주장하지 않는다.
/// </summary>
public sealed class LedgerPoller : IDisposable
{
    private readonly Dictionary<int, ProcInfo> _known = new();
    private readonly List<JsonObject> _pending = new();
    private readonly object _lock = new();
    private CancellationTokenSource? _cts;
    private Task? _loop;

    public TimeSpan Interval { get; init; } = TimeSpan.FromSeconds(1);

    /// <summary>PRECHECK 시점의 스냅샷을 기준선으로 잡는다. 이 pid 들은 exec 로 보고하지 않는다.</summary>
    public void Prime(IEnumerable<ProcInfo> baseline)
    {
        lock (_lock)
        {
            foreach (var p in baseline) _known[p.Pid] = p;
        }
    }

    public void Start()
    {
        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        _loop = Task.Run(async () =>
        {
            while (!token.IsCancellationRequested)
            {
                try { await Task.Delay(Interval, token); } catch (OperationCanceledException) { return; }
                try { Tick(); } catch { /* 한 번 실패해도 원장은 계속 돈다 */ }
            }
        }, token);
    }

    private void Tick()
    {
        var now = DateTimeOffset.UtcNow;
        var snapshot = ProcessCollector.Snapshot();
        var seen = new HashSet<int>();

        lock (_lock)
        {
            foreach (var p in snapshot)
            {
                seen.Add(p.Pid);
                if (_known.ContainsKey(p.Pid)) continue;
                _known[p.Pid] = p;
                _pending.Add(ExecObservation(p, now));
            }

            foreach (var pid in _known.Keys.Where(k => !seen.Contains(k)).ToList())
            {
                var p = _known[pid];
                _known.Remove(pid);
                _pending.Add(new JsonObject
                {
                    ["kind"] = "process",
                    ["source"] = "userspace",
                    ["signal"] = "S9",
                    ["collector"] = "process-diff-poll",
                    ["platform"] = "windows",
                    ["ts"] = Redaction.IsoSec(now),
                    ["pid"] = pid,
                    ["path"] = p.Path,
                    ["note"] = "exit",
                });
            }
        }
    }

    private static JsonObject ExecObservation(ProcInfo p, DateTimeOffset now)
    {
        var o = new JsonObject
        {
            ["kind"] = "exec",
            ["source"] = "userspace",       // 커널이 아니다 — 등급은 규칙 엔진이 내린다
            ["signal"] = "S9",
            ["collector"] = "process-diff-poll",
            ["platform"] = "windows",
            ["ts"] = Redaction.IsoSec(now),
            ["pid"] = p.Pid,
            ["path"] = p.Path,
            ["signed"] = p.Signed,
            ["degraded"] = true,            // 폴링은 단명 프로세스를 놓친다
        };
        o.Set("sha256", p.Sha256);
        if (p.Signer is null) o["signer"] = null; else o["signer"] = p.Signer;
        if (p.StartedAt.HasValue) o["startedAt"] = Redaction.IsoSec(p.StartedAt.Value);
        return o;
    }

    public List<JsonObject> Drain()
    {
        lock (_lock)
        {
            if (_pending.Count == 0) return new List<JsonObject>();
            var batch = new List<JsonObject>(_pending);
            _pending.Clear();
            return batch;
        }
    }

    public void Dispose()
    {
        _cts?.Cancel();
        try { _loop?.Wait(TimeSpan.FromSeconds(2)); } catch { /* 종료 중 */ }
        _cts?.Dispose();
    }
}
