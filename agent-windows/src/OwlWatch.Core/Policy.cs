using System.Text.Json.Nodes;

namespace OwlWatch.Core;

/// <summary>판정 대상의 신원. 이름이 아니라 해시·서명자가 키다(설계서 P2 원칙).</summary>
public sealed class Subject
{
    public string? Path;
    public string? Sha256;
    public string? CdHash;
    public string? Signer;
    public string? TeamId;
    public bool? Signed;
    public bool? Notarized;
    public bool? PlatformBinary;
    public string? StartedAt;

    /// <summary>관측(JsonObject)에서 판정용 신원을 뽑는다. statusItem 은 ownerPath 가 경로다.</summary>
    public static Subject From(JsonObject o) => new()
    {
        Path = o.Str("path") ?? o.Str("ownerPath"),
        Sha256 = o.Str("sha256"),
        CdHash = o.Str("cdhash"),
        Signer = o.Str("signer"),
        TeamId = o.Str("teamId"),
        Signed = o.Bool("signed"),
        Notarized = o.Bool("notarized"),
        PlatformBinary = o.Bool("platformBinary"),
        StartedAt = o.Str("startedAt"),
    };
}

public sealed record DenyRule(string Id, string Signal, string? NameContains, string? Signer, string? Sha256, string? Note);

public sealed record AllowRule(
    string? TeamId, string? Signer, string? CdHash, string? Sha256, string? Path,
    string? Platform, string? Layer, string? Note, string? ExpiresAt);

public sealed record Verdict(bool Allowed, string? Layer = null, string? Note = null, DenyRule? Denied = null);

/// <summary>
/// 허용목록·거부목록 판정. core-rules/src/policy.js 의 포트.
/// 설계서 05장: OS 기본 → 학교 공용 → 강의별 → 세션 임시. deny 는 allow 를 이긴다.
/// </summary>
public sealed class Policy
{
    public string Id = "";
    public List<AllowRule> Allow = new();
    public List<DenyRule> Deny = new();
    public Dictionary<string, long> Thresholds = new();
    public List<string> CaptureStackModules = new();
    public bool VmAllowed;
    public string? PolicyText;

    public long Th(string key, long fallback) => Thresholds.TryGetValue(key, out var v) ? v : fallback;

    public static Policy Load(params string[] files)
    {
        var p = new Policy { Id = string.Join("+", files.Select(System.IO.Path.GetFileNameWithoutExtension)) };
        foreach (var f in files) p.MergeFrom(J.ParseFile(f));
        return p;
    }

    public void MergeFrom(JsonObject src)
    {
        if (src["allow"] is JsonArray allow)
            foreach (var n in allow.OfType<JsonObject>())
                Allow.Add(new AllowRule(
                    n.Str("teamId"), n.Str("signer"), n.Str("cdhash"), n.Str("sha256"), n.Str("path"),
                    n.Str("platform"), n.Str("layer"), n.Str("note"), n.Str("expiresAt")));

        if (src["deny"] is JsonArray deny)
            foreach (var n in deny.OfType<JsonObject>())
            {
                var m = n.Obj("match");
                Deny.Add(new DenyRule(n.Str("id") ?? "?", n.Str("signal") ?? "S6",
                    m.Str("nameContains"), m.Str("signer"), m.Str("sha256"), n.Str("note")));
            }

        if (src["thresholds"] is JsonObject th)
            foreach (var kv in th)
                if (kv.Value is not null && kv.Value.AsValue().TryGetValue<long>(out var v))
                    Thresholds[kv.Key] = v;

        if (src["captureStackModules"] is JsonArray mods)
        {
            CaptureStackModules.Clear();
            foreach (var m in mods) if (m is not null) CaptureStackModules.Add(m.GetValue<string>());
        }

        if (src.Obj("policyNotes") is { } notes)
        {
            VmAllowed = notes.Bool("vmAllowed") ?? VmAllowed;
            PolicyText = notes.Str("text") ?? PolicyText;
        }
    }

    private static bool WildcardEq(string pattern, string? value)
    {
        if (value is null) return false;
        if (pattern.EndsWith('*'))
            return value.StartsWith(pattern[..^1], StringComparison.OrdinalIgnoreCase);
        return string.Equals(pattern, value, StringComparison.OrdinalIgnoreCase);
    }

    private static bool KeyEq(string? a, string? b) =>
        string.Equals(a ?? "", b ?? "", StringComparison.OrdinalIgnoreCase);

    private static bool AllowEntryMatches(AllowRule e, Subject s, string platform, string? atTs)
    {
        if (!string.IsNullOrEmpty(e.Platform) && e.Platform != "any" && e.Platform != platform) return false;
        if (!string.IsNullOrEmpty(e.ExpiresAt) && atTs is not null
            && DateTimeOffset.Parse(atTs) > DateTimeOffset.Parse(e.ExpiresAt)) return false;

        var sawKey = false;
        if (!string.IsNullOrEmpty(e.TeamId)) { sawKey = true; if (!KeyEq(s.TeamId, e.TeamId)) return false; }
        if (!string.IsNullOrEmpty(e.CdHash)) { sawKey = true; if (!KeyEq(s.CdHash, e.CdHash)) return false; }
        if (!string.IsNullOrEmpty(e.Sha256)) { sawKey = true; if (!KeyEq(s.Sha256, e.Sha256)) return false; }
        if (!string.IsNullOrEmpty(e.Signer)) { sawKey = true; if (!WildcardEq(e.Signer, s.Signer)) return false; }
        if (!string.IsNullOrEmpty(e.Path)) { sawKey = true; if (!WildcardEq(e.Path, s.Path)) return false; }
        return sawKey;
    }

    public Verdict Classify(Subject s, string platform, string? atTs = null)
    {
        var name = (s.Path ?? "").ToLowerInvariant();

        foreach (var d in Deny)
        {
            var hit =
                (d.NameContains is not null && name.Contains(d.NameContains.ToLowerInvariant())) ||
                (d.Signer is not null && WildcardEq(d.Signer, s.Signer)) ||
                (d.Sha256 is not null && KeyEq(d.Sha256, s.Sha256));
            if (hit) return new Verdict(false, Denied: d);
        }

        // 커널이 is_platform_binary / 서명 체인으로 이미 보증한 값이다.
        if (s.PlatformBinary == true) return new Verdict(true, "os", "platform binary");

        foreach (var e in Allow)
            if (AllowEntryMatches(e, s, platform, atTs))
                return new Verdict(true, e.Layer ?? "school", e.Note);

        return new Verdict(false);
    }

    /// <summary>P2 맥락. 순서까지 core-rules 와 같아야 한다 — 이벤트 본문에 그대로 들어가 해시가 된다.</summary>
    public List<string> P2Contexts(Subject s, SessionInfo session)
    {
        var outp = new List<string>();
        var p = (s.Path ?? "").Replace('\\', '/').ToLowerInvariant();
        if (p.Contains("/downloads/") || p.Contains("/다운로드/")) outp.Add("downloadsPath");
        if (s.Signed == false) outp.Add("unsignedBinary");
        else if (s.Notarized == false) outp.Add("unnotarizedBinary");

        if (!string.IsNullOrEmpty(s.StartedAt) && !string.IsNullOrEmpty(session.ExamStartsAt))
        {
            var delta = (DateTimeOffset.Parse(session.ExamStartsAt) - DateTimeOffset.Parse(s.StartedAt)).TotalMilliseconds;
            var win = Th("preExamContextMs", 900000);
            if (delta >= 0 && delta <= win) outp.Add("startedNearExamStart");
            if (delta < 0) outp.Add("startedDuringExam");
        }
        return outp;
    }
}

/// <summary>세션 문맥. 규칙 엔진은 이 값 말고 어떤 외부 상태도 읽지 않는다.</summary>
public sealed class SessionInfo
{
    public string SessionId = "";
    public int? Seat;
    public string Platform = "windows";
    /// <summary>kernel | fallback | off. 커널 원장이 아니면 상관 규칙이 성립하지 않는다.</summary>
    public string Ledger = "fallback";
    public string ExamStartsAt = "";
    public string ExamEndsAt = "";
    public int TzOffsetMinutes = 540;
    public int? AgentPid;

    public static SessionInfo From(JsonObject o) => new()
    {
        SessionId = o.Str("sessionId") ?? "",
        Seat = o.Int("seat"),
        Platform = o.Str("platform") ?? "windows",
        Ledger = o.Str("ledger") ?? "fallback",
        ExamStartsAt = o.Str("examStartsAt") ?? "",
        ExamEndsAt = o.Str("examEndsAt") ?? "",
        TzOffsetMinutes = o.Int("tzOffsetMinutes") ?? 540,
        AgentPid = o.Int("agentPid"),
    };
}
