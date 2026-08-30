using System.Text.Json.Nodes;
using OwlWatch.Core;
using OwlWatch.Rules;

namespace OwlWatch.SpecRunner;

/// <summary>
/// 패리티 테스트. 설계서 12장:
/// "같은 픽스처가 macOS·Windows 양쪽 수집기에서 나와야 하며, 등급이 어긋나면 실패로 처리한다."
///
/// core-rules(JS)가 구운 spec/fixtures/*.json 의 expect 를 C# 엔진이 그대로 재현하는지 본다.
/// 이벤트의 규칙·등급·심각도·대상·맥락뿐 아니라 최종 체인 해시까지 맞아야 통과다 —
/// 해시가 맞는다는 건 알림 문구 한 글자까지 같다는 뜻이다.
/// </summary>
public static class Program
{
    public static int Main(string[] args)
    {
        try { Console.OutputEncoding = System.Text.Encoding.UTF8; } catch { }

        if (args.Contains("--sleep"))
        {
            // --ledger 검사가 띄우는 대상. 아무것도 하지 않고 잠깐 살아 있기만 한다.
            var i = Array.IndexOf(args, "--sleep");
            var secs = i + 1 < args.Length && int.TryParse(args[i + 1], out var n) ? n : 3;
            Thread.Sleep(secs * 1000);
            return 0;
        }

        if (args.Contains("--etw")) return EtwCheck.Run(args.Contains("--require-session"));

        if (args.Contains("--heartbeat"))
        {
            var i = Array.IndexOf(args, "--heartbeat");
            var url = i + 1 < args.Length && args[i + 1].StartsWith("http") ? args[i + 1] : "http://127.0.0.1:8787";
            return HeartbeatCheck.RunAsync(url).GetAwaiter().GetResult();
        }

        var specDir = args.Length > 0 && !args[0].StartsWith("--") ? args[0] : FindSpecDir();
        if (specDir is null)
        {
            Console.Error.WriteLine("spec/ 디렉터리를 찾지 못했다. 경로를 인자로 넘겨라.");
            return 2;
        }

        if (args.Contains("--ledger")) return LedgerCheck.Run(specDir, args.Contains("--require-kernel"));

        var fixDir = Path.Combine(specDir, "fixtures");
        var files = Directory.GetFiles(fixDir, "*.json").OrderBy(f => f, StringComparer.Ordinal).ToList();
        var failed = 0;

        Console.WriteLine($"spec: {specDir}");
        Console.WriteLine($"픽스처 {files.Count}건 — C# 엔진 vs core-rules 레퍼런스\n");

        foreach (var file in files)
        {
            var name = Path.GetFileName(file);
            JsonObject fx;
            try { fx = J.ParseFile(file); }
            catch (Exception ex) { failed++; Console.Error.WriteLine($"✗ {name}\n    픽스처 파싱 실패: {ex.Message}"); continue; }

            var expect = fx.Obj("expect");
            if (expect is null) { Console.WriteLine($"? {name} 기대값 없음 — core-rules 에서 npm run bless"); continue; }

            List<JsonObject> events;
            string chainHead;
            try
            {
                (events, chainHead) = Run(fx, specDir);
            }
            catch (Exception ex)
            {
                failed++;
                Console.Error.WriteLine($"✗ {name}\n    실행 중 예외: {ex.GetType().Name}: {ex.Message}");
                continue;
            }

            var actual = events.Select(Compact).ToList();
            var wanted = (expect["events"] as JsonArray)?.OfType<JsonObject>().ToList() ?? new();
            var problems = new List<string>();

            if (actual.Count != wanted.Count)
                problems.Add($"이벤트 수 불일치 — 기대 {wanted.Count}건, 실제 {actual.Count}건");

            for (var i = 0; i < Math.Max(actual.Count, wanted.Count); i++)
            {
                var a = i < actual.Count ? Canonical.Write(actual[i]) : "(없음)";
                var w = i < wanted.Count ? Canonical.Write(wanted[i]) : "(없음)";
                if (a != w) problems.Add($"  [{i}] 기대 {w}\n       실제 {a}");
            }

            var wantHead = expect.Str("chainHead");
            if (wantHead is not null && wantHead != chainHead)
                problems.Add($"체인 헤드 불일치 — 알림 문구나 증거 내용이 레퍼런스와 다르다\n" +
                             $"  기대 {wantHead}\n  실제 {chainHead}");

            var chain = Canonical.VerifyChain(events);
            if (!chain.Ok) problems.Add($"자체 체인 검증 실패 seq={chain.BrokenAt} ({chain.Reason})");

            // 전송·저장 경로까지 확인한다. 정규화는 통과하면서 ToJsonString 만 던지는
            // 조합이 실제로 있었다(JsonArray.Add 제네릭 오버로드) — 그건 배포 후에야 드러난다.
            foreach (var e in events)
            {
                try { _ = e.ToJsonString(J.Compact); }
                catch (Exception ex) { problems.Add($"이벤트 seq={e.Int("seq")} 직렬화 실패: {ex.Message}"); break; }
            }

            if (problems.Count > 0)
            {
                failed++;
                Console.Error.WriteLine($"✗ {name}\n    {string.Join("\n    ", problems)}");
            }
            else
            {
                Console.WriteLine($"✓ {name}  이벤트 {actual.Count}건  head {chainHead[..12]}");
            }
        }

        Console.WriteLine($"\n{files.Count - failed}/{files.Count} 통과");
        return failed == 0 ? 0 : 1;
    }

    private static (List<JsonObject> Events, string ChainHead) Run(JsonObject fx, string specDir)
    {
        var refs = (fx["policyRefs"] as JsonArray)?.Select(n => n!.GetValue<string>()).ToArray()
                   ?? new[] { "school-common" };
        var policy = Policy.Load(refs.Select(r => Path.Combine(specDir, "policy", r + ".json")).ToArray());
        if (fx.Obj("policyOverride") is { } ov) policy.MergeFrom(ov);

        var session = SessionInfo.From(fx.Obj("session") ?? new JsonObject());
        var state = new EngineState();
        var all = new List<JsonObject>();

        foreach (var step in (fx["steps"] as JsonArray)?.OfType<JsonObject>() ?? Enumerable.Empty<JsonObject>())
        {
            var obs = (step["observations"] as JsonArray)?.OfType<JsonObject>().ToList() ?? new();
            var scanned = (step["scanned"] as JsonArray)?.Select(n => n!.GetValue<string>()).ToList() ?? new();
            all.AddRange(RuleEngine.Evaluate(obs, scanned, policy, session, state).Events);
        }
        return (all, state.PrevHash);
    }

    /// <summary>run-fixtures.js 의 compact() 와 같은 축약형.</summary>
    private static JsonObject Compact(JsonObject e) => new()
    {
        ["rule"] = e.Str("rule"),
        ["grade"] = e.Str("grade"),
        ["severity"] = e.Str("severity"),
        ["subjectKey"] = e.Obj("subject").Str("key"),
        ["contexts"] = e["contexts"]?.DeepClone() ?? new JsonArray(),
    };

    private static string? FindSpecDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "spec", "fixtures");
            if (Directory.Exists(candidate)) return Path.Combine(dir.FullName, "spec");
            dir = dir.Parent;
        }
        return null;
    }
}
