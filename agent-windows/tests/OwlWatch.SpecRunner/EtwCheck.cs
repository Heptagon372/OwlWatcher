using OwlWatch.Collectors.Etw;

namespace OwlWatch.SpecRunner;

/// <summary>
/// ETW 커널 원장 자가 진단.
///
///   owlwatch-specrunner --etw
///
/// 실시간 세션은 관리자 권한이 필요해서 권한 없는 개발 기기에서는 끝까지 못 돌린다.
/// 그렇다고 "안 해봤다"로 두면 승격된 서비스에서 처음 돌 때 레이아웃 오류가 터지고,
/// 그건 시험 중에 드러난다. 그래서 권한 없이 검증 가능한 것을 전부 검증한다.
/// </summary>
public static class EtwCheck
{
    public static int Run()
    {
        Console.WriteLine("ETW 커널 원장 자가 진단 (S9 · S11)\n");
        var failed = 0;

        // 1) 구조체 레이아웃 — 어긋나면 OpenTrace 가 조용히 이상하게 동작한다
        Console.WriteLine("── 1. 구조체 레이아웃 (x64)");
        foreach (var c in EtwDiagnostics.CheckLayouts())
        {
            if (c.Ok) Console.WriteLine($"   ✓ {c.Name,-26} {c.Actual}");
            else { failed++; Console.Error.WriteLine($"   ✗ {c.Name,-26} {c.Actual} (기대 {c.Expected})"); }
        }

        // 2) TDH 배관 + 매니페스트 조회 — 세션 없이 확인 가능한 부분
        Console.WriteLine("\n── 2. TDH 매니페스트 조회 (세션 불필요)");
        var resolved = 0;
        foreach (var (id, name) in EtwDiagnostics.LedgerEvents)
        {
            var probe = EtwDiagnostics.ProbeManifest(id);
            if (probe is null)
            {
                failed++;
                Console.Error.WriteLine($"   ✗ 이벤트 {id} ({name}) — 매니페스트를 찾지 못했다");
                continue;
            }
            resolved++;
            Console.WriteLine($"   ✓ 이벤트 {id} v{probe.Version} ({name})");
            Console.WriteLine($"       속성 {probe.Properties.Count}개: {string.Join(", ", probe.Properties.Take(8))}" +
                              (probe.Properties.Count > 8 ? " …" : ""));

            // 원장이 실제로 읽는 속성이 매니페스트에 있는지 확인한다.
            // 이름이 바뀌면 값을 못 뽑는데, 그건 조용한 실패라 여기서 잡아야 한다.
            var required = id == 5 ? new[] { "ProcessID", "ImageName" }
                                   : new[] { "ProcessID", "ImageName" };
            foreach (var r in required)
            {
                if (probe.Properties.Contains(r)) continue;
                failed++;
                Console.Error.WriteLine($"       ✗ 필수 속성 \"{r}\" 이 없다 — EtwLedgerCollector 가 값을 못 뽑는다");
            }
            if (id == 1 && !probe.Properties.Contains("ParentProcessID"))
                Console.WriteLine("       · ParentProcessID 없음 — ppid 는 비워진다 (치명적이지 않음)");
        }

        // 3) 실시간 세션 — 실제로 열어 본다
        Console.WriteLine("\n── 3. 실시간 세션 개시");
        var session = EtwDiagnostics.ProbeSession();
        if (session.Started)
        {
            Console.WriteLine($"   ✓ {session.Message}");
            Console.WriteLine("     → 에이전트가 ledger=kernel 로 동작하고 S9 이 P0 등급을 만든다.");
        }
        else
        {
            Console.WriteLine($"   · 열지 못했다 (Win32 {session.Win32Error})");
            Console.WriteLine($"     {session.Message}");
            Console.WriteLine("     → 에이전트는 LedgerPoller 로 폴백하고, 관측의 source 가 userspace 가 되어");
            Console.WriteLine("       S9 의 등급이 P0 에서 P1 로 자동으로 내려간다. 감추지 않는다.");
        }

        Console.WriteLine();
        if (failed == 0)
        {
            Console.WriteLine($"레이아웃·TDH 검증 통과 ({resolved}/{EtwDiagnostics.LedgerEvents.Length} 이벤트 해석)");
            Console.WriteLine(session.Started
                ? "커널 원장을 쓸 수 있다."
                : "커널 원장 배관은 정상이고, 남은 것은 권한뿐이다.");
            return 0;
        }

        Console.Error.WriteLine($"{failed}건 실패 — 커널 원장을 이 상태로 배포하면 안 된다.");
        return 1;
    }
}
