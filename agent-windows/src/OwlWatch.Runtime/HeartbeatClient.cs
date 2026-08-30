using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using OwlWatch.Collectors;
using OwlWatch.Core;

namespace OwlWatch.Runtime;

/// <summary>
/// 하트비트 전송. 설계서 08장 POST /functions/v1/heartbeat 계약 그대로.
///
/// 서버는 seq 단조 증가 · 시각 편차 ±30s · 서명 검증을 하고, 실패를 S14(P0)로 올린다.
/// 오프라인이면 로컬 해시체인에 쌓았다가 순서를 보존해 재전송한다.
///
/// 서명 대상은 sig 를 뺀 본문의 정규화 JSON이다 — 서버가 같은 규칙으로 재구성해야 검증된다.
/// </summary>
public sealed class HeartbeatClient
{
    private readonly HttpClient _http;
    private readonly SessionConfig _cfg;
    private readonly Attestation _attest;
    private readonly List<JsonObject> _queue = new();
    private readonly object _lock = new();

    public int Seq { get; private set; }
    /// <summary>서버가 하트비트 응답으로 내려보낸 명령. 설계서 09장: ARMED 진입은 감독관이 시작을 눌렀을 때만.</summary>
    public string? PendingCommand { get; private set; }
    public bool Online { get; private set; }
    public long ClockSkewMs { get; private set; }
    public string? LastError { get; private set; }

    public HeartbeatClient(SessionConfig cfg, Attestation attest)
    {
        _cfg = cfg;
        _attest = attest;
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
    }

    /// <summary>세션 등록. 공개키를 서버에 고정해 이후 하트비트를 검증하게 한다.</summary>
    /// <param name="ledger">kernel | fallback. 서버가 리포트에서 등급을 설명할 때 쓴다.</param>
    public async Task<bool> RegisterAsync(string ledger, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(_cfg.ConsoleBaseUrl)) return false;
        var body = new JsonObject
        {
            ["sessionId"] = _cfg.SessionId,
            ["seat"] = _cfg.Seat,
            ["os"] = "windows",
            ["agentVersion"] = AgentVersion,
            ["hwKeyPub"] = _attest.PublicKeyB64,
            ["attestation"] = _attest.Kind,
            ["ledger"] = ledger,
            ["examTitle"] = _cfg.ExamTitle,
            ["level"] = _cfg.Level,
        };
        if (!string.IsNullOrEmpty(_cfg.ExamId)) body["examId"] = _cfg.ExamId;
        try
        {
            using var res = await _http.PostAsync($"{_cfg.ConsoleBaseUrl}/functions/v1/session/register",
                new StringContent(body.ToJsonString(J.Compact), Encoding.UTF8, "application/json"), ct)
                .ConfigureAwait(false);
            Online = res.IsSuccessStatusCode;
            if (!Online) LastError = $"등록 실패 HTTP {(int)res.StatusCode}";
            return Online;
        }
        catch (Exception ex) { Online = false; LastError = ex.Message; return false; }
    }

    public const string AgentVersion = "0.2.0";

    public void Enqueue(IEnumerable<JsonObject> events)
    {
        lock (_lock) _queue.AddRange(events.Select(e => (JsonObject)e.DeepClone()));
    }

    /// <summary>
    /// 하트비트 한 번. 실패해도 큐는 비우지 않는다 — 다음 시도에 순서를 보존해 다시 보낸다.
    /// </summary>
    public async Task<bool> SendAsync(string state, JsonObject posture, JsonObject summary, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(_cfg.ConsoleBaseUrl)) { Online = false; return false; }

        List<JsonObject> batch;
        lock (_lock) batch = new List<JsonObject>(_queue);

        Seq++;
        var body = new JsonObject
        {
            ["sessionId"] = _cfg.SessionId,
            ["seq"] = Seq,
            ["ts"] = Redaction.IsoSec(DateTimeOffset.UtcNow),
            ["state"] = state,
            ["posture"] = posture,
            ["summary"] = summary,
            ["attestation"] = _attest.Kind,
            ["agentVersion"] = AgentVersion,
        };
        if (batch.Count > 0)
        {
            var arr = new JsonArray();
            foreach (var e in batch) arr.Add(e.DeepClone());
            body["events"] = arr;
        }

        // 서명 대상: sig 를 제외한 본문의 정규화 JSON.
        body["sig"] = _attest.Sign(Canonical.Write(body));

        try
        {
            using var res = await _http.PostAsync($"{_cfg.ConsoleBaseUrl}/functions/v1/heartbeat",
                new StringContent(body.ToJsonString(J.Compact), Encoding.UTF8, "application/json"), ct)
                .ConfigureAwait(false);

            if (!res.IsSuccessStatusCode)
            {
                Online = false;
                LastError = $"HTTP {(int)res.StatusCode}";
                Seq--; // 서버가 받지 못했으므로 같은 seq 로 다시 보낸다
                return false;
            }

            // 서버 시각으로 시계 편차를 잰다. 조작을 잡는 근거이자 S8 의 입력이다.
            if (res.Headers.Date is { } serverTime)
                ClockSkewMs = (long)(DateTimeOffset.UtcNow - serverTime).TotalMilliseconds;

            try
            {
                var text = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(text))
                    PendingCommand = J.Parse(text).Str("command");
            }
            catch { PendingCommand = null; }

            lock (_lock) _queue.RemoveRange(0, Math.Min(batch.Count, _queue.Count));
            Online = true;
            LastError = null;
            return true;
        }
        catch (Exception ex)
        {
            Online = false;
            LastError = ex.Message;
            Seq--;
            return false;
        }
    }

    public string? TakeCommand()
    {
        var c = PendingCommand;
        PendingCommand = null;
        return c;
    }

    public JsonObject Posture(bool beacon, bool canary, int ifaces, string captureGuard) => new()
    {
        ["beacon"] = beacon,
        ["canary"] = canary,
        ["ifaces"] = ifaces,
        ["captureGuard"] = captureGuard,
    };
}
