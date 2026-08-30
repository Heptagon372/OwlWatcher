using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Text;

namespace OwlWatchSim;

/// <summary>
/// 설계서 12장 (a)~(g). 각 시나리오는 하나의 신호만 겨냥한다 —
/// 탐지가 실패했을 때 어떤 신호가 실패했는지 바로 알 수 있어야 하기 때문이다.
/// </summary>
internal static class Scenarios
{
    // ── (a) 상태 영역 아이콘 주기 교체 → S2

    public static int Tray(int seconds)
    {
        Console.WriteLine("(a) 트레이 아이콘을 2초마다 교체한다. OwlWatch 는 S2 로 소유 프로세스를 봐야 한다.");
        Console.WriteLine("    아이콘 모양이 아니라 소유 프로세스가 근거다 — 모양을 바꿔도 신호는 같아야 한다.\n");

        using var icon = new NotifyIcon { Visible = true, Text = "owlwatch-sim (a)" };
        var i = 0;
        Program.Countdown("트레이 시나리오", seconds, () =>
        {
            var old = icon.Icon;
            icon.Icon = MakeIcon(i++ % 2 == 0 ? Color.OrangeRed : Color.SteelBlue);
            if (old is not null) { Native.DestroyIcon(old.Handle); old.Dispose(); }
        });
        icon.Visible = false;
        return 0;
    }

    private static Icon MakeIcon(Color c)
    {
        using var bmp = new Bitmap(16, 16);
        using (var g = Graphics.FromImage(bmp))
        {
            g.Clear(Color.Transparent);
            using var b = new SolidBrush(c);
            g.FillEllipse(b, 2, 2, 12, 12);
        }
        return Icon.FromHandle(bmp.GetHicon());
    }

    // ── (b) Caps Lock 비인간 패턴 → S4

    [DllImport("user32.dll")]
    private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    private const byte VK_CAPITAL = 0x14;
    private const uint KEYEVENTF_KEYUP = 0x0002;

    public static int CapsPattern(int seconds)
    {
        Console.WriteLine("(b) Caps Lock 을 250ms 주기로 토글한다. OwlWatch 는 S4 로 잡아야 한다.");
        Console.WriteLine("    사람의 타이핑과 구분되는 것은 값이 아니라 주기의 규칙성이다.\n");

        var end = DateTime.UtcNow.AddSeconds(seconds);
        var burst = 0;
        while (DateTime.UtcNow < end)
        {
            // 4회 연속 250ms 간격 → 임계값(1.5초 내 2회 이상, ≤300ms 주기)을 넘긴다
            for (var i = 0; i < 4; i++)
            {
                Toggle();
                Thread.Sleep(250);
            }
            burst++;
            Console.Write($"\r버스트 {burst}회 — 남은 {Math.Max(0, (int)(end - DateTime.UtcNow).TotalSeconds)}초   ");
            Thread.Sleep(4000); // 디바운스(5분)를 넘기지 않으므로 알림은 한 번만 나야 정상이다
        }
        Console.WriteLine("\n원래 상태로 되돌린다.");
        if ((Native.GetKeyState(VK_CAPITAL) & 1) != 0) Toggle();
        return 0;
    }

    private static void Toggle()
    {
        keybd_event(VK_CAPITAL, 0, 0, UIntPtr.Zero);
        keybd_event(VK_CAPITAL, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
    }

    // ── (c) HID 장치 오픈 → S12 · 설계서 14장 미결 3번

    public static int HidOpen(int seconds)
    {
        Console.WriteLine("(c) HID 키보드 장치를 열고 아무것도 하지 않는다.");
        Console.WriteLine("    설계서 14장 미결 3번을 함께 확인한다 — 비관리자 앱이 Caps Lock 상태를 바꾸지 않고");
        Console.WriteLine("    LED 만 켤 수 있는가. 가능하다면 Windows 의 S12 에 구멍이 있는 것이다.\n");

        var result = Hid.ProbeKeyboards();
        Console.WriteLine($"HID 인터페이스 {result.Total}개 발견, 키보드 사용 페이지 {result.Keyboards}개");
        Console.WriteLine($"  읽기/쓰기로 열린 것: {result.Opened}개");
        Console.WriteLine($"  LED 출력 리포트 전송 성공: {result.LedWrites}개");
        Console.WriteLine();
        Console.WriteLine(result.LedWrites > 0
            ? "→ 미결 3번의 답: 이 기기에서는 비관리자 앱이 LED 출력 리포트를 보낼 수 있다.\n" +
              "   Windows S12 에 구멍이 있다는 뜻이므로 설계서 05장 S12 의 Windows 칸을 고쳐야 한다."
            : "→ 미결 3번의 답: 이 기기에서는 LED 출력 리포트가 통하지 않았다.\n" +
              "   실사용 도구는 실제 Caps Lock 상태를 토글하게 되고, 그건 S4 폴링이 잡는다.");
        Console.WriteLine();

        if (result.Handles.Count > 0)
        {
            Console.WriteLine($"핸들 {result.Handles.Count}개를 {seconds}초 동안 열어 둔다 — 열어 두는 것 자체가 관측 대상이다.");
            Program.Countdown("HID 시나리오", seconds);
            foreach (var h in result.Handles) Native.CloseHandle(h);
        }
        return 0;
    }

    // ── (d) canary → S5

    public static int Canary(string url, int seconds)
    {
        Console.WriteLine($"(d) 차단돼야 할 목적지에 요청한다: {url}");
        Console.WriteLine("    시험망 이그레스 정책이 제대로 걸려 있으면 이 요청은 실패해야 한다.");
        Console.WriteLine("    성공한다면 그건 핫스팟이거나 정책이 적용되지 않은 것이고, OwlWatch 는 crit 를 내야 한다.\n");

        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
        var end = DateTime.UtcNow.AddSeconds(seconds);
        var reached = 0;
        var blocked = 0;

        while (DateTime.UtcNow < end)
        {
            try
            {
                using var res = http.GetAsync(url).GetAwaiter().GetResult();
                if (res.IsSuccessStatusCode) reached++; else blocked++;
            }
            catch { blocked++; }
            Console.Write($"\r도달 {reached} · 차단 {blocked}   ");
            Thread.Sleep(3000);
        }
        Console.WriteLine();
        Console.WriteLine(reached > 0
            ? "→ canary 에 도달했다. 이 좌석은 시험망 밖이다."
            : "→ canary 가 차단됐다. 이그레스 정책이 적용된 상태다.");
        return 0;
    }

    // ── (e) 캡처 제외 창 → S3

    public static int ExcludedWindow(int seconds)
    {
        Console.WriteLine("(e) 캡처에서 제외된 창을 만든다 (Cluely 형 오버레이).");
        Console.WriteLine("    OwlWatch 는 S3 로 '우리 창이 아닌데 캡처에서 빠진 창'을 봐야 한다.\n");

        using var form = new Form
        {
            Text = "owlwatch-sim (e)",
            Size = new Size(320, 160),
            StartPosition = FormStartPosition.CenterScreen,
            TopMost = true,
            BackColor = Color.MidnightBlue,
            ForeColor = Color.White,
        };
        form.Controls.Add(new Label
        {
            Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter,
            Text = "캡처 제외 창 (시뮬레이터)\n이 창은 정답을 표시하지 않는다",
            Font = SystemFonts.DefaultFont,
        });

        form.Shown += (_, _) =>
        {
            var ok = Native.SetWindowDisplayAffinity(form.Handle, Native.WDA_EXCLUDEFROMCAPTURE);
            Console.WriteLine(ok ? "  캡처 제외 설정 완료" : "  캡처 제외 설정 실패");
        };

        var timer = new System.Windows.Forms.Timer { Interval = seconds * 1000 };
        timer.Tick += (_, _) => { timer.Stop(); form.Close(); };
        timer.Start();
        Application.Run(form);
        return 0;
    }

    // ── (f) Downloads 경로 미서명 실행 → S1 · S9

    public static int UnsignedFromDownloads(int seconds)
    {
        var downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        var stage = Path.Combine(downloads, "owlwatch-sim-helper");

        Console.WriteLine("(f) 다운로드 경로에 미서명 바이너리를 복사해 실행한다.");
        Console.WriteLine($"    대상: {stage}");
        Console.WriteLine("    OwlWatch 는 S9(커널 원장) 또는 S1 로 잡고, P2 맥락에 downloadsPath·unsignedBinary 를 붙여야 한다.");
        Console.WriteLine();

        var self = Environment.ProcessPath;
        if (self is null) { Console.Error.WriteLine("자기 경로를 알 수 없다."); return 3; }

        // .NET 앱은 exe 하나만 옮기면 못 돈다 — apphost 가 옆의 .dll·runtimeconfig 를 찾는다.
        // 실기기에서 바로 드러난 문제라 디렉터리째 옮긴다. 커닝 도구도 보통 이렇게 배포된다.
        var srcDir = AppContext.BaseDirectory;
        Directory.CreateDirectory(stage);
        foreach (var f in Directory.GetFiles(srcDir))
            File.Copy(f, Path.Combine(stage, Path.GetFileName(f)), overwrite: true);

        var exe = Path.Combine(stage, Path.GetFileName(self));
        var psi = new ProcessStartInfo(exe, $"idle --seconds {seconds}")
        {
            UseShellExecute = false,
            WorkingDirectory = stage,
        };

        using var child = Process.Start(psi);
        Console.WriteLine($"  pid {child?.Id} 로 실행됨. {seconds}초 후 종료된다.");
        child?.WaitForExit((seconds + 15) * 1000);

        try { Directory.Delete(stage, recursive: true); Console.WriteLine("  정리 완료."); }
        catch (Exception ex) { Console.WriteLine($"  정리 실패({ex.GetType().Name}) — 다음 실행에서 덮어쓴다."); }
        return 0;
    }

    // ── (g) 스캔 회피 → S9. v0.2 의 핵심 회귀.

    public static int ScanEvasion(int seconds)
    {
        Console.WriteLine("(g) 스캔 회피 — v0.1 의 최대 구멍이었던 시나리오.");
        Console.WriteLine("    사전점검 직전에 종료했다가 시험 중에 다시 실행한다.");
        Console.WriteLine("    사용자 공간 스캔만 있으면 이 회피가 통하지만, 커널 원장(S9)이 있으면 재실행이 기록된다.");
        Console.WriteLine("    M1 의 폴링 폴백에서도 잡혀야 하며, 다만 등급은 P1 로 내려가는 것이 정상이다.\n");

        Console.WriteLine("[1/3] 지금이 '사전점검 직전 종료' 시점이다. 30초 동안 아무것도 하지 않는다.");
        Program.Countdown("종료 상태 유지", 30);

        Console.WriteLine("[2/3] 시험 중 재실행 — 다운로드 경로에서 미서명으로.");
        var rc = UnsignedFromDownloads(seconds);

        Console.WriteLine("[3/3] 확인할 것:");
        Console.WriteLine("  · 사전점검 결과에는 이 프로세스가 없어야 한다");
        Console.WriteLine("  · 시험 중 이벤트에는 R-S9-UNKNOWN-EXEC 가 있어야 한다");
        Console.WriteLine("  · 원장이 커널이면 P0/crit, 폴링 폴백이면 P1/warn — 등급이 출처를 정직하게 반영해야 한다");
        return rc;
    }
}
