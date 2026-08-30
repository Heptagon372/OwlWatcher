using System.Runtime.InteropServices;
using System.Text;
using OwlWatch.Collectors;
using OwlWatch.Core;
using OwlWatch.Runtime;
using OwlWatch.Runtime.Ui;

namespace OwlWatch.Agent;

/// <summary>
/// L1 · OwlWatch 에이전트.
///
/// 설계서 03장 L1: "시험 시간 동안 상주. 커널 실행 원장, 캡처 차단 + 자가검증,
/// HID 접근 관측, HW 키 서명 하트비트, 종료 시 자기 삭제."
///
/// M1 에서 실제로 도는 것:
///   · 캡처 차단 + 30초 자가검증 (S13)      — 관리자 불필요, 이것이 M1 의 주력
///   · 프로세스 원장 폴백 (S9, 등급 P1)      — ETW 서비스는 M3
///   · S1·S2·S3·S4·S5·S6·S8 관측
///   · TPM 서명 하트비트 (S14)
///   · 종료 시 세션 키 삭제
///
/// 아직 없는 것: 커널 ETW 원장(M3), macOS ESF·AAC(M4·Apple 승인 대기), Take a Test(L2, M6).
/// </summary>
public static class Program
{
    [DllImport("kernel32.dll")] private static extern bool AttachConsole(int pid);

    [STAThread]
    public static int Main(string[] args)
    {
        AttachConsole(-1);
        try { Console.OutputEncoding = Encoding.UTF8; } catch { /* 리다이렉트 */ }

        if (args.Contains("--help")) { Console.WriteLine(Help); return 0; }

        var configPath = ArgValue(args, "--config") ?? FindDefaultConfig();
        if (configPath is null)
        {
            Console.Error.WriteLine("세션 설정을 찾지 못했다. --config <경로> 로 지정하라.");
            Console.Error.WriteLine("예시는 agent-windows/owlwatch.config.example.json 에 있다.");
            return 3;
        }

        SessionConfig cfg;
        Policy policy;
        try
        {
            cfg = SessionConfig.Load(configPath);
            policy = cfg.LoadPolicy();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"설정/정책을 읽지 못했다: {ex.Message}");
            return 3;
        }

        if (cfg.Level == "L0")
        {
            Console.Error.WriteLine("이 설정은 level=L0 다. 상주 없는 점검은 owlwatch-examcheck 를 써라.");
            return 3;
        }

        ApplicationConfiguration.Initialize();

        var consentNote = $"{cfg.Level} · 시험 시간 동안만 상주하고, 종료하면 세션 키를 지우고 보호를 해제한다.";
        if (new ConsentForm(cfg, consentNote).ShowDialog() != DialogResult.OK)
        {
            Console.Error.WriteLine("동의하지 않았다. 아무것도 수집하지 않고 종료한다.");
            return 4;
        }

        using var session = new AgentSession(cfg, policy);
        var window = new ExamWindow(cfg, session);

        // 창 핸들이 만들어진 뒤에 PRECHECK 를 돌린다 — 캡처 차단은 대상 창이 있어야 건다.
        window.Shown += async (_, _) =>
        {
            var ok = await session.PrecheckAsync(window.Handle, () => window.SentinelScreenRect, window.Pump)
                .ConfigureAwait(true);
            if (!ok)
            {
                MessageBox.Show(window,
                    $"사전 점검을 통과하지 못했다.\n\n{session.PrecheckFailure}\n\n" +
                    "보호가 꺼진 채로는 시험을 시작하지 않는다. 감독관에게 알려라.",
                    "사전 점검 실패", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            // 콘솔이 없으면 감독관이 이 기기에서 직접 시작한다.
            // 있으면 콘솔의 arm 명령이 하트비트 응답으로 내려온다.
            if (string.IsNullOrEmpty(cfg.ConsoleBaseUrl)) PromptProctorStart(window, session, cfg);
        };

        var guardIntervalMs = (int)policy.Th("captureGuardIntervalMs", 30000);
        var beat = new System.Windows.Forms.Timer { Interval = Math.Max(5000, guardIntervalMs / 3) };
        var scan = new System.Windows.Forms.Timer { Interval = 60_000 };
        var busy = false;

        async void Tick(bool full)
        {
            if (busy) return;
            busy = true;
            try { await session.TickAsync(full).ConfigureAwait(true); }
            catch (Exception ex) { Console.Error.WriteLine($"주기 작업 오류: {ex.Message}"); }
            finally { busy = false; }
        }

        beat.Tick += (_, _) => Tick(false);
        scan.Tick += (_, _) => Tick(true);
        beat.Start();
        scan.Start();

        Application.Run(window);

        beat.Stop();
        scan.Stop();
        session.End();

        Console.WriteLine($"세션 종료. 이벤트 {session.Events.Count}건, 체인 헤드 {session.ChainHead}");
        Console.WriteLine($"로컬 기록: {session.WorkDir}");
        return session.Events.Any(e => e.Str("severity") == "crit") ? 2
             : session.Events.Any(e => e.Str("severity") == "warn") ? 1 : 0;
    }

    /// <summary>
    /// 콘솔 없이 쓸 때의 시작 경로. 설계서 09장은 학생이 임의로 ARMED 에 들어가지 못하게 하라고
    /// 하므로, 감독관만 아는 세션 코드를 입력하게 한다. 콘솔이 있으면 이 경로를 쓰지 않는다.
    /// </summary>
    private static void PromptProctorStart(Form owner, AgentSession session, SessionConfig cfg)
    {
        var secret = cfg.SessionCode;
        if (string.IsNullOrEmpty(secret))
        {
            // 세션 비밀이 없으면 감독관 확인을 흉내 낼 방법이 없다. 그 사실을 말하고 시작한다.
            MessageBox.Show(owner,
                "콘솔도 세션 코드도 없다. 감독관 확인 없이 감시를 시작한다 — " +
                "이 상태의 기록은 '감독관이 시작을 확인했다'를 증명하지 못한다.",
                "감독관 확인 없음", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            session.Arm();
            EnterLockdownIfL2(owner, session, cfg);
            return;
        }

        using var dlg = new ProctorStartDialog(cfg);
        if (dlg.ShowDialog(owner) != DialogResult.OK) return;
        session.Arm();
        EnterLockdownIfL2(owner, session, cfg);
    }

    /// <summary>
    /// L2 진입. 설계서 06장: "진입 전 L0 스캔을 강제하고, 창이 사라지면 S7 crit."
    /// 사전 점검을 통과하고 감독관이 시작을 확인한 뒤에만 여기 온다.
    /// 진입하면 화면이 잠금 화면 위 전체화면으로 바뀌므로 학생에게 먼저 알린다.
    /// </summary>
    private static void EnterLockdownIfL2(Form owner, AgentSession session, SessionConfig cfg)
    {
        if (cfg.Level != "L2") return;

        if (string.IsNullOrEmpty(cfg.ExamUrl))
        {
            MessageBox.Show(owner,
                "level 이 L2 인데 examUrl 이 없다. 락다운 없이 계속한다 — 이 세션은 L1 수준이다.",
                "L2 설정 누락", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        var r = MessageBox.Show(owner,
            """
            지금부터 시험 잠금 모드로 들어간다.

            화면 전체가 시험 화면으로 바뀌고, 다른 앱과 캡처가 차단되며 클립보드가 비워진다.
            시험이 끝나기 전에 빠져나오면 감독관 화면에 기록된다.
            """,
            "시험 잠금 모드", MessageBoxButtons.OKCancel, MessageBoxIcon.Information);
        if (r != DialogResult.OK) return;

        if (!session.EnterLockdown(cfg.ExamUrl, out var error))
            MessageBox.Show(owner,
                $"""
                잠금 모드로 들어가지 못했다.

                {error}

                감독관에게 알려라.
                """,
                "L2 진입 실패", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }

    private const string Help = """
        OwlWatch 에이전트 (L1) — 시험 창 캡처 차단 + 자가검증

          owlwatch-agent --config <세션설정.json>

        설정 예시: agent-windows/owlwatch.config.example.json
        종료 코드: 0 정상 · 1 정황 · 2 확인 필요 · 3 오류 · 4 동의 거부

        이 도구는 부정행위를 판정하지 않는다. 확인 요청을 만들고 증거를 보관할 뿐이다.
        """;

    private static string? ArgValue(string[] args, string name)
    {
        var i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    private static string? FindDefaultConfig()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var p = Path.Combine(dir.FullName, "owlwatch.config.json");
            if (File.Exists(p)) return p;
            dir = dir.Parent;
        }
        return null;
    }
}
