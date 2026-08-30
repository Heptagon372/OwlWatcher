using System.Text;
using System.Text.Json.Nodes;
using OwlWatch.Core;

namespace OwlWatch.Runtime;

/// <summary>
/// 로컬 append-only 이벤트 저장소(JSONL).
///
/// 설계서 08장의 events 테이블과 같은 해시체인을 기기 쪽에도 둔다. 오프라인이면 여기에
/// 쌓였다가 순서를 보존해 재전송되고, 시험 후에는 학생이 자기 로그를 그대로 내보낼 수 있다
/// (설계서 10장 "학생 상태창 · 시험 후 로컬 로그 내보내기 가능").
/// </summary>
public sealed class EventStore
{
    private readonly string _path;
    private readonly object _lock = new();

    public EventStore(string path)
    {
        _path = path;
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
    }

    public string FilePath => _path;

    public void Append(IEnumerable<JsonObject> events)
    {
        lock (_lock)
        {
            using var w = new StreamWriter(_path, append: true, J.Utf8NoBom);
            foreach (var e in events) w.WriteLine(e.ToJsonString(J.Compact));
        }
    }

    public List<JsonObject> ReadAll()
    {
        lock (_lock)
        {
            if (!File.Exists(_path)) return new List<JsonObject>();
            var outp = new List<JsonObject>();
            foreach (var line in File.ReadLines(_path))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try { outp.Add(J.Parse(line)); } catch { /* 잘린 줄은 건너뛴다 — 체인 검증이 잡아낸다 */ }
            }
            return outp;
        }
    }

    public Canonical.ChainResult Verify() => Canonical.VerifyChain(ReadAll());

    /// <summary>
    /// 증거 번들. 리포트는 P0/P1/P2 를 절대 섞지 않고 세 절로 낸다(설계서 08장).
    /// 여기서는 그 세 절로 나눈 구조와 체인 검증값을 함께 낸다.
    /// </summary>
    public JsonObject ExportBundle(SessionConfig cfg)
    {
        var events = ReadAll();
        var chain = Canonical.VerifyChain(events);

        JsonArray Section(string grade)
        {
            var a = new JsonArray();
            foreach (var e in events.Where(e => e.Str("grade") == grade)) a.Add(e.DeepClone());
            return a;
        }

        return new JsonObject
        {
            ["exam"] = new JsonObject
            {
                ["sessionId"] = cfg.SessionId,
                ["title"] = cfg.ExamTitle,
                ["seat"] = cfg.Seat,
                ["startsAt"] = cfg.ExamStartsAt,
                ["endsAt"] = cfg.ExamEndsAt,
                ["level"] = cfg.Level,
                ["retentionDays"] = cfg.RetentionDays,
            },
            ["chain"] = new JsonObject
            {
                ["ok"] = chain.Ok,
                ["head"] = chain.Head,
                ["brokenAt"] = chain.Ok ? null : chain.BrokenAt,
                ["reason"] = chain.Ok ? null : chain.Reason,
            },
            // 설계서 02장: 처분 문서에 P1을 사실처럼 쓰지 않는다. 구조로 강제한다.
            ["확인된_사실_P0"] = Section("P0"),
            ["정황_P1"] = Section("P1"),
            ["참고_P2"] = Section("P2"),
            ["주의"] = "이 문서는 부정행위를 판정하지 않는다. P0만이 확인된 사실이며, " +
                       "P1은 정황, P2는 참고다. 처분은 사람과 위원회가 한다.",
        };
    }

    /// <summary>보관 기간이 지난 세션 로그를 지운다. 삭제도 감사 대상이다(설계서 10장).</summary>
    public static int PurgeExpired(string dir, int retentionDays, TextWriter? audit = null)
    {
        if (!Directory.Exists(dir)) return 0;
        var cutoff = DateTime.UtcNow.AddDays(-retentionDays);
        var n = 0;
        foreach (var f in Directory.GetFiles(dir, "*.jsonl"))
        {
            if (File.GetLastWriteTimeUtc(f) >= cutoff) continue;
            try
            {
                File.Delete(f);
                n++;
                audit?.WriteLine($"{DateTimeOffset.UtcNow:O}\tpurge\t{System.IO.Path.GetFileName(f)}\t보관기간 {retentionDays}일 경과");
            }
            catch { /* 잠긴 파일은 다음 실행에서 */ }
        }
        return n;
    }
}
