using System.Diagnostics;
using System.Text;

namespace OwlWatchSim;

/// <summary>
/// owlwatch-sim — OwlWatch 탐지기의 회귀 테스트용 시뮬레이터.
///
/// 설계서 12장이 요구하는 (a)~(g) 시나리오를 만든다. 이 프로그램은 커닝 도구의
/// **관측 가능한 부수 효과만** 흉내 낸다 — 화면을 읽지 않고, 어떤 AI에도 붙지 않고,
/// 정답을 만들지도 표시하지도 않는다. 그런 기능은 설계상 여기 들어올 수 없다.
/// 존재 이유는 하나다: 탐지가 실패했을 때 그것을 수정 이슈로 만들 수 있게 하는 것.
///
/// 설계서 12장 레드팀 항목: "결과는 우회 방법이 아니라 '탐지 실패 → 수정' 이슈로만 기록."
/// </summary>
public static class Program
{
    private const string Banner = """
        ┌─────────────────────────────────────────────────────────────────────┐
        │ owlwatch-sim — 탐지기 회귀 테스트용 시뮬레이터                       │
        │                                                                     │
        │ 커닝 도구의 관측 가능한 부수 효과만 재현한다.                       │
        │ 화면을 읽지 않고, AI에 붙지 않고, 정답을 만들지 않는다.             │
        │ 용도: 본인이 관리하는 기기에서 OwlWatch 탐지 회귀를 돌리는 것뿐.     │
        └─────────────────────────────────────────────────────────────────────┘
        """;

    private const string Help = """
        owlwatch-sim <시나리오> [옵션]

        시나리오 (설계서 12장)
          a  tray            상태 영역 아이콘을 주기적으로 교체        → S2
          b  caps            Caps Lock 을 250ms 주기로 토글           → S4   [--confirm 필요]
          c  hid             HID 키보드 장치를 열고 아무것도 안 하기  → S12  [--confirm 필요]
          d  canary          차단돼야 할 목적지에 요청                → S5
          e  excluded        캡처 제외 창 생성                        → S3
          f  unsigned        Downloads 경로에서 미서명 바이너리 실행  → S1·S9
          g  evade           사전점검 직전 종료 → 30초 뒤 재실행      → S9 (v0.2 핵심 회귀)

        옵션
          --seconds <n>      시나리오 지속 시간 (기본 60)
          --canary <url>     canary 목적지 (기본 http://127.0.0.1:8787/canary)
          --confirm          키보드·HID 를 실제로 건드리는 시나리오에 필요
          --help

        (b)와 (c)는 실제 키보드 상태와 장치 핸들을 건드린다. 그래서 --confirm 없이는 돌지 않는다.
        """;

    public static int Main(string[] args)
    {
        try { Console.OutputEncoding = Encoding.UTF8; } catch { }
        Console.WriteLine(Banner);
        Console.WriteLine();

        if (args.Length == 0 || args.Contains("--help"))
        {
            Console.WriteLine(Help);
            return args.Length == 0 ? 1 : 0;
        }

        var scenario = args[0].ToLowerInvariant();
        if (scenario == "idle")
        {
            // (f)(g) 가 재실행하는 대기 모드. 아무것도 하지 않고 상주만 한다 —
            // 그게 이 시나리오에서 관측 대상인 전부다.
            var idleFor = int.TryParse(Value(args, "--seconds"), out var n) ? n : 60;
            Console.WriteLine($"대기 모드 — {idleFor}초 동안 상주만 한다. 정답 기능은 없다.");

            // 보이지 않는 최상위 창을 하나 만든다. 콘솔 프로세스로 두면 S1 의 "에이전트형"
            // 조건(최상위 창은 있는데 보이는 창이 없다)에 걸리지 않아 시나리오가 성립하지 않는다 —
            // 트레이 아이콘을 띄우는 실제 도구는 반드시 창을 가진다.
            using var hidden = new Form { ShowInTaskbar = false, WindowState = FormWindowState.Minimized };
            hidden.Load += (_, _) => hidden.Visible = false;
            hidden.Show();
            hidden.Hide();

            Countdown("대기", idleFor);
            return 0;
        }
        var seconds = int.TryParse(Value(args, "--seconds"), out var s) ? s : 60;
        var canary = Value(args, "--canary") ?? "http://127.0.0.1:8787/canary";
        var confirmed = args.Contains("--confirm");

        try
        {
            return scenario switch
            {
                "a" or "tray" => Scenarios.Tray(seconds),
                "b" or "caps" => Guarded(confirmed, "(b) 는 실제 Caps Lock 상태를 토글한다",
                                    () => Scenarios.CapsPattern(seconds)),
                "c" or "hid" => Guarded(confirmed, "(c) 는 실제 HID 장치를 연다",
                                    () => Scenarios.HidOpen(seconds)),
                "d" or "canary" => Scenarios.Canary(canary, seconds),
                "e" or "excluded" => Scenarios.ExcludedWindow(seconds),
                "f" or "unsigned" => Scenarios.UnsignedFromDownloads(seconds),
                "g" or "evade" => Scenarios.ScanEvasion(seconds),
                _ => Unknown(scenario),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"실패: {ex.GetType().Name}: {ex.Message}");
            return 3;
        }
    }

    private static int Guarded(bool confirmed, string what, Func<int> run)
    {
        if (confirmed) return run();
        Console.Error.WriteLine($"{what}. --confirm 을 붙여야 실행된다.");
        return 2;
    }

    private static int Unknown(string s)
    {
        Console.Error.WriteLine($"모르는 시나리오: {s}\n");
        Console.Error.WriteLine(Help);
        return 1;
    }

    private static string? Value(string[] args, string name)
    {
        var i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    internal static void Countdown(string label, int seconds, Action? each = null)
    {
        var end = DateTime.UtcNow.AddSeconds(seconds);
        while (DateTime.UtcNow < end)
        {
            each?.Invoke();
            Application.DoEvents(); // 트레이 아이콘·창이 실제로 그려지려면 펌프가 돌아야 한다
            var left = (int)(end - DateTime.UtcNow).TotalSeconds;
            Console.Write($"\r{label} — {Math.Max(0, left)}초 남음   ");
            Thread.Sleep(500);
        }
        Console.WriteLine();
    }
}
