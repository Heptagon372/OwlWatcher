using System.Text.Json.Nodes;
using OwlWatch.Core;

namespace OwlWatch.Rules;

/// <summary>
/// 원장이 기록한 exec 하나. 원본 관측을 그대로 들고 있는다.
///
/// path/sha256/signer 를 string 으로만 떼어 두면 "키가 없었다"와 "값이 null 이었다"를
/// 구분할 수 없다. 스캔 회피 이벤트는 이 값들을 증거로 다시 실으므로, 그 차이가
/// 그대로 체인 해시 차이가 된다 — 레퍼런스 구현은 undefined 를 빼고 null 은 남긴다.
/// </summary>
public sealed class LedgerRec
{
    public required JsonObject Src;

    public string? Path => Src.Str("path");
    public string? Sha256 => Src.Str("sha256");
    public string? Signer => Src.Str("signer");

    /// <summary>{...rec, kind, source, ts} 를 재현한다. rec 는 path·sha256·signer 세 키만 갖는다.</summary>
    public JsonObject ToSynthetic(string ts)
    {
        var o = new JsonObject();
        foreach (var key in new[] { "path", "sha256", "signer" })
            if (Src.ContainsKey(key)) o[key] = Src[key]?.DeepClone();
        o["kind"] = "exec";
        o["source"] = "kernel";
        o["ts"] = ts;
        return o;
    }
}

public sealed class CapsSample
{
    public long TsMs;
    public JsonObject Obs = new();
}

public sealed class Counters
{
    public int LedgerExecs;
    public int UnknownProcs;
    public int StatusItems;
    public int CapsPatterns;

    public JsonObject ToJson() => new()
    {
        ["ledgerExecs"] = LedgerExecs,
        ["unknownProcs"] = UnknownProcs,
        ["statusItems"] = StatusItems,
        ["capsPatterns"] = CapsPatterns,
    };
}

/// <summary>
/// 세션 하나의 누적 상태. core-rules 의 initialState() 와 같은 필드를 갖는다.
///
/// SubjectOrder 가 따로 있는 이유: JS 객체는 문자열 키의 삽입 순서를 유지하지만
/// .NET Dictionary 는 보장하지 않는다. 에스컬레이션 이벤트의 발화 순서가 갈리면
/// seq 가 갈리고 체인 해시가 갈린다.
/// </summary>
public sealed class EngineState
{
    public int Seq;
    public string PrevHash = Canonical.Genesis;

    public Dictionary<string, long> Debounce = new(StringComparer.Ordinal);
    public Dictionary<string, List<string>> SubjectP1Rules = new(StringComparer.Ordinal);
    public List<string> SubjectOrder = new();
    public HashSet<string> Escalated = new(StringComparer.Ordinal);

    public Dictionary<int, LedgerRec> LedgerPids = new();
    public HashSet<int> LedgerExited = new();
    public HashSet<int> BaselinePids = new();
    public bool BaselineCaptured;

    public Dictionary<string, List<string>> Presence = new(StringComparer.Ordinal);
    public List<CapsSample> CapsBuffer = new();
    public Dictionary<string, List<string>> Mods = new(StringComparer.Ordinal);

    public Counters Counters = new();

    public void NoteP1(string subjectKey, string rule)
    {
        if (!SubjectP1Rules.TryGetValue(subjectKey, out var list))
        {
            list = new List<string>();
            SubjectP1Rules[subjectKey] = list;
            SubjectOrder.Add(subjectKey);
        }
        if (!list.Contains(rule)) list.Add(rule);
    }
}
