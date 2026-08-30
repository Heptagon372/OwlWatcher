using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;
using OwlWatch.Collectors;
using OwlWatch.Core;
using OwlWatch.Rules;
using OwlWatch.Runtime;
using OwlWatch.Runtime.Ui;

namespace OwlWatch.ExamCheck;

/// <summary>
/// L0 · ExamCheck — 설치 없는 점검.
///
/// 설계서 03장: "시험 직전 30초 스캔 → 결과 화면 + 6자리 코드. 상주 없음. 콘솔 없이도 동작.
/// 서명된 단일 .exe, 관리자 불필요." 얻는 등급은 P1·P2 다 — 커널 원장이 없으므로
/// 이 도구는 P0 을 만들지 않는다. 그 사실을 결과 화면에 그대로 적는다.
/// </summary>
public static class Program
{
    [DllImport("kernel32.dll")] private static extern bool AttachConsole(int pid);
    private const int AttachParentProcess = -1;

    [STAThread]
    public static int Main(string[] args)
    {
        var json = args.Contains("--json");
        var noUi = args.Contains("--no-ui") || json;
        var emitAllowlist = ArgValue(args, "--emit-allowlist");
        var configPath = ArgValue(args, "--config");
        var outPath = ArgValue(args, "--out");

        if (noUi || emitAllowlist is not null || args.Contains("--help") || args.Contains("--capture-test"))
        {
            AttachConsole(AttachParentProcess);
            try { Console.OutputEncoding = Encoding.UTF8; } catch { /* 리다이렉트된 스트림 */ }
        }

        if (args.Contains("--help"))
        {
            Console.WriteLine(Help);
            return 0;
        }

        if (args.Contains("--capture-test"))
        {
            // M1 의 주력 기능만 따로 확인한다. 이 기기에서 WDA_EXCLUDEFROMCAPTURE 가
            // 실제로 먹는가 — 원격 데스크톱 세션이나 일부 가상 디스플레이에서는 안 먹는다
            // (설계서 14장 미결 4번). 추측하지 않고 직접 찍어서 답한다.
            ApplicationConfiguration.Initialize();
            var (status, detail) = CaptureProbe.Run();
            Console.WriteLine($"캡처 차단 자가검증: {CaptureGuard.StatusText(status)}");
            Console.WriteLine($"  {detail}");
            Console.WriteLine(status == CaptureGuard.GuardStatus.Ok
                ? "  → 이 기기에서 L1 캡처 차단을 쓸 수 있다."
                : "  → 이 기기에서는 L1 캡처 차단을 신뢰할 수 없다. 좌석을 초록불로 두면 안 된다.");
            return status == CaptureGuard.GuardStatus.Ok ? 0 : 2;
        }

        SessionConfig cfg;
        try
        {
            cfg = configPath is not null ? SessionConfig.Load(configPath) : Defaults();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"설정을 읽지 못했다: {ex.Message}");
            return 3;
        }

        Policy policy;
        try { policy = cfg.LoadPolicy(); }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"정책을 읽지 못했다: {ex.Message}");
            return 3;
        }

        if (emitAllowlist is not null)
        {
            var procs = ProcessCollector.Snapshot();
            var draft = Scanner.EmitAllowlistDraft(procs, Environment.MachineName);
            J.WriteFile(emitAllowlist, draft.ToJsonString(J.Pretty));
            var signers = (draft["policy"]!["allow"] as JsonArray)!.Count;
            var unsigned = (draft["review"]!["unsigned"] as JsonArray)!.Count;
            Console.WriteLine($"허용목록 초안 → {emitAllowlist}");
            Console.WriteLine($"  서명 검증된 인증서 주체 {signers}종, 미서명 검토 대상 {unsigned}건");
            Console.WriteLine("  검토 없이 school-common.json 에 그대로 합치지 마라.");
            return 0;
        }

        if (!noUi)
        {
            // 첫 창이 만들어지기 전에 한 번만. 두 번 부르면 예외가 난다.
            ApplicationConfiguration.Initialize();
            if (new ConsentForm(cfg, "이 점검은 설치 없이 한 번 실행되고 끝난다. 상주하지 않는다.").ShowDialog() != DialogResult.OK)
            {
                return 4; // 동의하지 않으면 아무것도 수집하지 않는다
            }
        }

        var self = Environment.ProcessId;
        ScanResult scan;
        RuleEngine.Result verdict;
        CaptureGuard.GuardStatus captureCapability = CaptureGuard.GuardStatus.Off;
        string captureDetail = "확인하지 않음";

        try
        {
            scan = Scanner.RunAsync(cfg, policy, self).GetAwaiter().GetResult();
            scan.Observations.Add(HostCollector.Integrity(DateTimeOffset.UtcNow, 0));

            if (!noUi)
            {
                (captureCapability, captureDetail) = CaptureProbe.Run();
            }

            var session = cfg.ToSessionInfo(ledger: "off", agentPid: self);
            var state = new EngineState();
            verdict = RuleEngine.Evaluate(scan.Observations, scan.Scanned, policy, session, state);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"점검 중 오류: {ex.Message}");
            return 3;
        }

        var report = BuildReport(cfg, scan, verdict, captureCapability, captureDetail);

        if (outPath is not null) J.WriteFile(outPath, report.ToJsonString(J.Pretty));
        if (json) Console.WriteLine(report.ToJsonString(J.Pretty));
        else if (noUi) PrintText(report);

        var code = ExitCode(verdict.Events);

        if (!noUi) Application.Run(new ResultForm(cfg, report, verdict.Events));
        return code;
    }

    private const string Help = """
        OwlWatch ExamCheck (L0) — 설치 없는 시험 전 점검

          owlwatch-examcheck [옵션]

          --config <경로>            세션 설정 JSON
          --json                     결과를 JSON 으로 stdout 에 (UI 없음)
          --no-ui                    UI 없이 텍스트 요약만
          --out <경로>               결과 JSON 을 파일로
          --emit-allowlist <경로>    이 기기의 상주 앱에서 허용목록 초안 생성
          --capture-test             이 기기에서 캡처 차단이 실제로 동작하는지만 확인
          --help

        종료 코드: 0 정상 · 1 정황(warn) · 2 확인 필요(crit) · 3 오류 · 4 동의 거부

        이 도구는 P0(확정) 근거를 만들지 않는다. 커널 원장이 없기 때문이고,
        그건 L1 에이전트의 몫이다.
        """;

    private static string? ArgValue(string[] args, string name)
    {
        var i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    private static SessionConfig Defaults()
    {
        var now = DateTimeOffset.UtcNow;
        return new SessionConfig
        {
            SessionId = $"examcheck-{now:yyyyMMdd-HHmmss}",
            ExamTitle = "사전 점검 (세션 없음)",
            ExamStartsAt = Redaction.IsoSec(now),
            ExamEndsAt = Redaction.IsoSec(now.AddHours(2)),
            Level = "L0",
        };
    }

    private static int ExitCode(IEnumerable<JsonObject> events)
    {
        var worst = 0;
        foreach (var e in events)
        {
            var sev = e.Str("severity");
            if (sev == "crit") return 2;
            if (sev == "warn") worst = 1;
        }
        return worst;
    }

    private static JsonObject BuildReport(SessionConfig cfg, ScanResult scan, RuleEngine.Result verdict,
        CaptureGuard.GuardStatus capture, string captureDetail)
    {
        var events = new JsonArray();
        foreach (var e in verdict.Events) events.Add(e.DeepClone());

        var chainHead = verdict.Events.Count > 0
            ? verdict.Events[^1].Str("hash")!
            : Canonical.Genesis;

        var notes = J.Arr(scan.Notes);

        return new JsonObject
        {
            ["tool"] = "owlwatch-examcheck",
            ["version"] = HeartbeatClient.AgentVersion,
            ["level"] = "L0",
            ["sessionId"] = cfg.SessionId,
            ["examTitle"] = cfg.ExamTitle,
            ["seat"] = cfg.Seat,
            ["scannedAt"] = Redaction.IsoSec(DateTimeOffset.UtcNow),
            ["elapsedMs"] = (int)scan.Elapsed.TotalMilliseconds,
            ["machine"] = Environment.MachineName,
            ["processCount"] = scan.Processes.Count,
            ["observationCount"] = scan.Observations.Count,
            ["captureBlockCapability"] = new JsonObject
            {
                ["status"] = CaptureGuard.StatusText(capture),
                ["detail"] = captureDetail,
                ["note"] = "L1 에이전트를 쓸 때 이 기기에서 시험 창 캡처 차단이 실제로 동작하는지의 사전 확인이다.",
            },
            ["lockdownCapability"] = LockdownJson(),
            ["code"] = SessionCode.Derive(cfg.SessionCode ?? cfg.SessionId, chainHead, DateTimeOffset.UtcNow),
            ["chainHead"] = chainHead,
            ["events"] = events,
            ["collectorNotes"] = notes,
            ["한계"] = "L0 는 커널 원장이 없어 P0(확정) 근거를 만들지 못한다. 여기 나온 것은 " +
                       "전부 정황(P1)이거나 참고(P2)이며, 부정행위 판정이 아니다.",
        };
    }

    /// <summary>L2 를 쓸 수 있는 기기인지. 승인이 필요 없어 오늘 켤 수 있는 유일한 락다운이다.</summary>
    private static JsonObject LockdownJson()
    {
        var p = LockdownCollector.Probe();
        return new JsonObject
        {
            ["available"] = p.Available,
            ["protocolRegistered"] = p.ProtocolRegistered,
            ["packagePresent"] = p.PackagePresent,
            ["detail"] = p.Detail,
        };
    }

    private static void PrintText(JsonObject report)
    {
        Console.WriteLine($"OwlWatch ExamCheck — {report.Str("examTitle")}");
        Console.WriteLine($"기기 {report.Str("machine")} · 프로세스 {report.Int("processCount")}개 · " +
                          $"관측 {report.Int("observationCount")}건 · {report.Int("elapsedMs")}ms");
        var cap = report.Obj("captureBlockCapability");
        Console.WriteLine($"캡처 차단 가능 여부: {cap.Str("status")} — {cap.Str("detail")}");
        var l2 = report.Obj("lockdownCapability");
        Console.WriteLine($"L2 락다운(Take a Test): {(l2.Bool("available") == true ? "가능" : "불가")} — {l2.Str("detail")}");
        Console.WriteLine($"코드: {report.Str("code")}\n");

        var events = report["events"] as JsonArray ?? new JsonArray();
        if (events.Count == 0)
        {
            Console.WriteLine("확인이 필요한 항목 없음.");
        }
        else
        {
            foreach (var e in events.OfType<JsonObject>())
                Console.WriteLine($"  [{e.Str("severity")}] {e.Str("summary")}");
        }
        Console.WriteLine($"\n{report.Str("한계")}");
    }
}
