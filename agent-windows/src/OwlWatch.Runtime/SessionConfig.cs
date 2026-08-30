using System.Text.Json.Nodes;
using OwlWatch.Core;

namespace OwlWatch.Runtime;

/// <summary>
/// 좌석 하나의 설정. 감독관이 콘솔에서 세션을 만들면 내려오는 값이고,
/// L0(콘솔 없이 동작)에서는 파일로 준다.
/// </summary>
public sealed class SessionConfig
{
    public string SessionId = "local-session";
    /// <summary>콘솔의 exams.id. 콘솔 없이 쓰면 비어 있다.</summary>
    public string? ExamId;
    public int? Seat;
    public string ExamTitle = "이름 없는 시험";
    public string ExamStartsAt = "";
    public string ExamEndsAt = "";
    public int TzOffsetMinutes = 540;
    public string Level = "L0";                 // L0 | L1 | L2
    /// <summary>L2 에서 Take a Test 에 넘길 시험 URL. LMS 문항 화면.</summary>
    public string? ExamUrl;

    public string? ConsoleBaseUrl;
    public string? SessionCode;                 // 6자리 코드 파생과 하트비트 등록에 쓴다
    public string? BeaconUrl;
    public string? CanaryUrl;
    public string? ExpectedSalt;

    public List<string> PolicyRefs = new() { "school-common" };
    public string SpecDir = "";
    public int RetentionDays = 30;

    public SessionInfo ToSessionInfo(string ledger, int agentPid) => new()
    {
        SessionId = SessionId,
        Seat = Seat,
        Platform = "windows",
        Ledger = ledger,
        ExamStartsAt = string.IsNullOrEmpty(ExamStartsAt) ? DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") : ExamStartsAt,
        ExamEndsAt = ExamEndsAt,
        TzOffsetMinutes = TzOffsetMinutes,
        AgentPid = agentPid,
    };

    public static SessionConfig Load(string path)
    {
        var o = J.ParseFile(path);
        var c = new SessionConfig
        {
            SessionId = o.Str("sessionId") ?? "local-session",
            ExamId = o.Str("examId"),
            Seat = o.Int("seat"),
            ExamTitle = o.Str("examTitle") ?? "이름 없는 시험",
            ExamStartsAt = o.Str("examStartsAt") ?? "",
            ExamEndsAt = o.Str("examEndsAt") ?? "",
            TzOffsetMinutes = o.Int("tzOffsetMinutes") ?? 540,
            Level = o.Str("level") ?? "L0",
            ExamUrl = o.Str("examUrl"),
            SpecDir = o.Str("specDir") ?? "",
            RetentionDays = o.Int("retentionDays") ?? 30,
        };

        if (o.Obj("console") is { } con)
        {
            c.ConsoleBaseUrl = con.Str("baseUrl");
            c.SessionCode = con.Str("sessionCode");
        }
        if (o.Obj("network") is { } net)
        {
            c.BeaconUrl = net.Str("beaconUrl");
            c.CanaryUrl = net.Str("canaryUrl");
            c.ExpectedSalt = net.Str("expectedSalt");
        }
        if (o["policy"] is JsonArray pol && pol.Count > 0)
            c.PolicyRefs = pol.Select(n => n!.GetValue<string>()).ToList();

        return c;
    }

    /// <summary>spec/ 위치를 찾는다. 설정에 없으면 실행 파일에서 위로 올라가며 찾는다.</summary>
    public string ResolveSpecDir()
    {
        if (!string.IsNullOrEmpty(SpecDir) && Directory.Exists(SpecDir)) return SpecDir;

        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "spec");
            if (Directory.Exists(Path.Combine(candidate, "policy"))) return candidate;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException(
            "spec/ 을 찾지 못했다. 설정의 specDir 를 지정하거나 저장소 안에서 실행하라.");
    }

    public Policy LoadPolicy()
    {
        var spec = ResolveSpecDir();
        return Policy.Load(PolicyRefs.Select(r => Path.Combine(spec, "policy", r + ".json")).ToArray());
    }
}
