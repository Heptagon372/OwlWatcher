using System.Text.Json.Nodes;
using OwlWatch.Core;

namespace OwlWatch.Collectors;

/// <summary>
/// S4 · Caps Lock 상태 전이.
///
/// 50Hz 로 GetKeyState(VK_CAPITAL) 의 토글 비트만 읽는다. 키보드 후킹이 아니다 —
/// 어떤 키가 눌렸는지는 알 수 없고, 알 수도 없어야 한다(설계서 10장 비수집 목록).
/// 기록하는 것은 "언제 상태가 뒤집혔는가" 뿐이고, 주기의 규칙성만 규칙 엔진이 본다.
///
/// Windows 에서 LED 만 켜려면 커널 경로가 필요하다. 그래서 실사용 커닝 도구는 실제
/// Caps Lock 상태를 토글하게 되고, 이 폴링이 사실상 LED 모드의 확정 관측이 된다
/// (설계서 S12 · 14장 미결 3번 — 비관리자 LED 전용 제어 가능성은 시뮬레이터로 확인 필요).
/// </summary>
public sealed class CapsLockCollector : IDisposable
{
    private readonly List<DateTimeOffset> _transitions = new();
    private readonly object _lock = new();
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private bool _last;

    public const int PollHz = 50;

    public void Start()
    {
        _last = CurrentState();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        _loop = Task.Run(async () =>
        {
            var period = TimeSpan.FromMilliseconds(1000.0 / PollHz);
            while (!token.IsCancellationRequested)
            {
                try { await Task.Delay(period, token); } catch (OperationCanceledException) { return; }
                var now = CurrentState();
                if (now == _last) continue;
                _last = now;
                lock (_lock) { _transitions.Add(DateTimeOffset.UtcNow); }
            }
        }, token);
    }

    private static bool CurrentState() => (Native.GetKeyState(Native.VK_CAPITAL) & 1) != 0;

    /// <summary>쌓인 전이를 가져가고 비운다. 규칙 엔진이 주기 판정을 한다.</summary>
    public List<JsonObject> Drain()
    {
        List<DateTimeOffset> batch;
        lock (_lock)
        {
            if (_transitions.Count == 0) return new List<JsonObject>();
            batch = new List<DateTimeOffset>(_transitions);
            _transitions.Clear();
        }

        var state = _last;
        var outp = new List<JsonObject>();
        for (var i = 0; i < batch.Count; i++)
        {
            outp.Add(new JsonObject
            {
                ["kind"] = "capsTransition",
                ["source"] = "userspace",
                ["signal"] = "S4",
                ["collector"] = "getkeystate-50hz",
                ["platform"] = "windows",
                ["ts"] = Redaction.Iso(batch[i]),
                // 전이 후 상태. 마지막 표본에서 역산한다.
                ["state"] = ((batch.Count - 1 - i) % 2 == 0) == state,
            });
        }
        return outp;
    }

    public void Dispose()
    {
        _cts?.Cancel();
        try { _loop?.Wait(TimeSpan.FromSeconds(1)); } catch { /* 종료 중 */ }
        _cts?.Dispose();
    }
}
