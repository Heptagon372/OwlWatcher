using System.Diagnostics;
using System.Text.Json.Nodes;
using OwlWatch.Collectors;
using OwlWatch.Core;
using OwlWatch.Rules;

namespace OwlWatch.SpecRunner;

/// <summary>
/// 원장 전 구간 검사.
///
///   owlwatch-specrunner --ledger
///
/// 검증하려는 것은 "원장이 프로세스를 잡는가"가 아니라 **등급이 출처를 정직하게 반영하는가**다.
/// 커널 세션을 열 수 있으면 exec 이 P0/crit 으로, 못 열면 P1/warn 으로 나와야 하고,
/// 후자에는 강등 이유가 증거에 남아야 한다. 이 성질이 깨지면 등급 모델 전체가 거짓말이 된다.
///
/// 이 검사는 실제로 프로세스를 하나 띄우고, 원장이 그것을 보고, 규칙 엔진까지 통과시킨다.
/// </summary>
public static class LedgerCheck
{
    public static int Run(string specDir)
    {
        Console.WriteLine("원장 전 구간 검사 (S9)\n");

        var policy = Policy.Load(Path.Combine(specDir, "policy", "school-common.json"));
        var self = Environment.ProcessPath;
        if (self is null) { Console.Error.WriteLine("자기 경로를 알 수 없다."); return 3; }

        // ── 원장 선택. AgentSession 과 같은 순서로 고른다.
        using var etw = new EtwLedgerCollector(policy.CaptureStackModules);
        using var poller = new LedgerPoller();

        var kernel = etw.Start();
        var ledgerMode = kernel ? "kernel" : "fallback";

        Console.WriteLine($"── 원장: {ledgerMode}");
        if (kernel)
        {
            Console.WriteLine("   커널 세션이 열렸다. exec 은 P0 근거가 된다.");
        }
        else
        {
            Console.WriteLine($"   커널 세션 실패 — {etw.FailureReason}");
            Console.WriteLine("   폴링으로 내려간다. exec 의 등급이 P1 로 내려가야 한다.");
            poller.Prime(ProcessCollector.Snapshot());
            poller.Start();
        }

        // ── 프로세스를 하나 띄운다. 자기 자신이라 미서명이고, 허용목록 밖이다.
        Console.WriteLine("\n── 프로세스 실행");
        using var child = Process.Start(new ProcessStartInfo(self, "--sleep 4")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
        });
        Console.WriteLine($"   pid {child?.Id} — {Path.GetFileName(self)} (미서명)");

        Thread.Sleep(6000);
        var observations = kernel ? etw.Drain() : poller.Drain();
        Console.WriteLine($"   원장이 낸 관측 {observations.Count}건");

        var target = Path.GetFileName(self).ToLowerInvariant();
        var execs = observations
            .Where(o => o.Str("kind") == "exec" && (o.Str("path") ?? "").ToLowerInvariant().EndsWith(target))
            .ToList();

        var failed = 0;

        if (execs.Count == 0)
        {
            failed++;
            Console.Error.WriteLine($"   ✗ 방금 띄운 프로세스의 exec 관측이 없다");
            if (!kernel)
                Console.Error.WriteLine("     폴링은 짧게 사는 프로세스를 놓칠 수 있지만, 4초는 놓치면 안 된다");
        }
        else
        {
            var o = execs[0];
            Console.WriteLine($"   ✓ exec 관측 — source={o.Str("source")} collector={o.Str("collector")}" +
                              (o.Bool("degraded") == true ? " degraded" : ""));

            var wantSource = kernel ? "kernel" : "userspace";
            if (o.Str("source") != wantSource)
            {
                failed++;
                Console.Error.WriteLine($"   ✗ source 가 {o.Str("source")} — {wantSource} 이어야 한다");
            }
        }

        // ── 규칙 엔진까지. 등급이 출처를 따라가는지가 핵심이다.
        Console.WriteLine("\n── 등급 판정");
        var session = new SessionInfo
        {
            SessionId = "ledger-check",
            Seat = 1,
            Platform = "windows",
            Ledger = ledgerMode,
            ExamStartsAt = Redaction.IsoSec(DateTimeOffset.UtcNow.AddMinutes(-1)),
            ExamEndsAt = Redaction.IsoSec(DateTimeOffset.UtcNow.AddHours(1)),
            AgentPid = Environment.ProcessId,
        };

        var result = RuleEngine.Evaluate(observations, new List<string>(), policy, session, new EngineState());
        var events = result.Events.Where(e => e.Str("rule") == "R-S9-UNKNOWN-EXEC").ToList();

        if (events.Count == 0)
        {
            failed++;
            Console.Error.WriteLine("   ✗ R-S9-UNKNOWN-EXEC 이벤트가 없다");
        }
        else
        {
            var e = events[0];
            var wantGrade = kernel ? "P0" : "P1";
            var wantSeverity = kernel ? "crit" : "warn";
            var grade = e.Str("grade");
            var severity = e.Str("severity");

            Console.WriteLine($"   {grade}/{severity} {e.Str("summary")}");

            if (grade != wantGrade || severity != wantSeverity)
            {
                failed++;
                Console.Error.WriteLine($"   ✗ {wantGrade}/{wantSeverity} 이어야 한다");
            }
            else
            {
                Console.WriteLine($"   ✓ 등급이 출처를 따라간다 ({ledgerMode} → {grade})");
            }

            // 폴백이면 강등 이유가 증거에 남아야 한다. 사람이 리포트에서 읽을 문장이다.
            if (!kernel)
            {
                var notes = (e.Obj("evidence")?["notes"] as JsonArray)?
                    .Select(n => n!.GetValue<string>()).ToList() ?? new List<string>();
                var hasNote = notes.Any(n => n.Contains("P0에서 P1로 낮춤"));
                if (hasNote)
                {
                    Console.WriteLine($"   ✓ 강등 이유가 증거에 남았다");
                    Console.WriteLine($"     \"{notes.First(n => n.Contains("P0에서 P1로 낮춤"))}\"");
                }
                else
                {
                    failed++;
                    Console.Error.WriteLine("   ✗ 강등 이유가 증거에 없다 — 리포트에서 왜 P1 인지 설명할 수 없다");
                }
            }
        }

        try { child?.WaitForExit(3000); } catch { }

        Console.WriteLine();
        if (failed == 0)
        {
            Console.WriteLine(kernel
                ? "원장 전 구간 통과 — 커널 원장이 P0 근거를 만든다."
                : "원장 전 구간 통과 — 커널이 없을 때 등급이 정직하게 내려간다.");
            return 0;
        }
        Console.Error.WriteLine($"{failed}건 실패");
        return 1;
    }
}
