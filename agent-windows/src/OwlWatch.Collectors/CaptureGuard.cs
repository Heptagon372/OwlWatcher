using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using OwlWatch.Core;

namespace OwlWatch.Collectors;

/// <summary>화면 좌표 사각형. Native.RECT 는 internal 이라 밖으로 내보낼 수 없다.</summary>
public readonly record struct ScreenRect(int Left, int Top, int Right, int Bottom);

/// <summary>
/// S13 · 캡처 차단 + 자가검증. M1 의 주력이다.
///
/// SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) 는 창을 모니터에만 표시하고
/// 캡처 결과에는 남기지 않는다(Win10 2004+). 관리자도, 어떤 승인도 필요 없다 —
/// 그래서 2주 안에 실전에 들어갈 수 있는 유일한 차단 수단이다(설계서 06장).
///
/// Microsoft 는 이 플래그가 보안 기능이 아니라고 명시하고 우회 기법도 공개돼 있다.
/// 그래서 "설정했다"로 끝내지 않는다. 커닝 도구가 쓰는 것과 같은 GDI 경로로 우리가 직접
/// 화면을 찍어 내용이 새지 않는지 30초마다 확인하고, 실패를 P0 crit 로 올린다.
///
/// ── 판정 기준을 왜 이렇게 잡았는가 (실기기에서 처음 것이 틀렸다)
///
/// 처음에는 "캡처 결과가 균일한 검정인가"로 봤다. 실기기에서 100% 실패가 나왔고,
/// 원인은 환경이 아니라 판정 기준이었다. 두 플래그의 동작이 다르다.
///   WDA_MONITOR            캡처에 창이 내용 없이(검게) 나타난다
///   WDA_EXCLUDEFROMCAPTURE 캡처에 창이 아예 없다 → 창 뒤의 배경이 찍힌다
/// 제대로 차단된 캡처는 검은 화면이 아니라 바탕화면이다. 검정을 기대하면
/// 정상 동작을 영원히 실패로 읽는다.
///
/// 그래서 배경색이 아니라 우리 창이 칠한 고유색(센티넬)이 캡처에 나타나는지를 본다.
/// 창이 캡처에서 빠졌으면 센티넬은 한 픽셀도 나오지 않는다. 이 기준은 두 플래그와
/// 앞으로 나올 다른 차단 방식에도 그대로 통한다 — 확인하려는 것은 색이 아니라
/// "우리 창의 내용이 캡처에 새는가"이기 때문이다.
/// </summary>
public sealed class CaptureGuard
{
    /// <summary>
    /// 센티넬 색. 시험 창이 이 색으로 띠를 칠하고, 자가검증은 이 색이 캡처에 있는지만 본다.
    /// 자연스러운 UI 나 바탕화면에서 나오기 어려운 값을 고른다.
    /// </summary>
    public const int SentinelR = 0x0B;
    public const int SentinelG = 0xF5;
    public const int SentinelB = 0x8C;

    /// <summary>손실 없는 GDI 경로지만 스케일링을 감안해 약간의 오차를 허용한다.</summary>
    private const int ColorTolerance = 8;

    /// <summary>센티넬이 이 비율 이상 보이면 창 내용이 캡처에 새고 있는 것으로 본다.</summary>
    private const double LeakThreshold = 0.05;

    /// <summary>대조 실험에서 이 비율은 넘어야 "이 경로로 캡처가 된다"고 말할 수 있다.</summary>
    private const double ControlThreshold = 0.50;

    private readonly IntPtr _hwnd;
    private readonly Func<ScreenRect> _sentinelRect;
    private readonly Action<int> _settle;

    public GuardStatus Status { get; private set; } = GuardStatus.Off;
    public string? Detail { get; private set; }

    /// <summary>진단값. 실패했을 때 왜 실패했는지를 말할 수 있어야 한다.</summary>
    public string Diagnostics { get; private set; } = "";

    public enum GuardStatus { Off, Ok, Failed, Unsupported }

    /// <param name="sentinelRect">
    /// 창이 센티넬 색으로 칠한 띠의 화면 좌표. 호출자가 준다 —
    /// WinForms 가 DPI 스케일을 처리한 실제 좌표여야 한다.
    /// </param>
    /// <param name="settle">
    /// 지정한 밀리초만큼 기다리되 그동안 메시지 펌프를 돌리는 콜백.
    /// 그냥 Thread.Sleep 을 하면 UI 스레드가 막혀 창이 다시 그려지지도, 합성기가
    /// 어피니티 변경을 반영하지도 못한 채로 캡처하게 된다.
    /// </param>
    public CaptureGuard(IntPtr hwnd, Func<ScreenRect> sentinelRect, Action<int>? settle = null)
    {
        _hwnd = hwnd;
        _sentinelRect = sentinelRect;
        _settle = settle ?? Thread.Sleep;
    }

    public static string StatusText(GuardStatus s) => s switch
    {
        GuardStatus.Ok => "ok",
        GuardStatus.Failed => "failed",
        GuardStatus.Unsupported => "unsupported",
        _ => "off",
    };

    /// <summary>
    /// 대조 실험 후 보호를 건다. PRECHECK 에서 한 번 통과해야 READY 로 갈 수 있다
    /// (설계서 09장: 보호가 꺼진 채 시험이 시작되는 상황을 구조적으로 막는다).
    /// </summary>
    public bool Arm(out string reason)
    {
        var remote = Native.GetSystemMetrics(Native.SM_REMOTESESSION) != 0;

        // 대조군: 플래그 없이 찍으면 센티넬이 보여야 한다. 안 보이면 이 캡처 경로가
        // 애초에 창을 못 보는 것이고, 그러면 "차단됐다"는 판정에 아무 의미가 없다.
        Native.SetWindowDisplayAffinity(_hwnd, Native.WDA_NONE);
        _settle(250);
        var control = SentinelRatio();

        Diagnostics = $"원격세션 {(remote ? "예" : "아니오")} · 대조군 센티넬 {control:P1}";

        if (control < ControlThreshold)
        {
            Status = GuardStatus.Unsupported;
            Detail = reason =
                $"대조 실험이 성립하지 않는다 — 차단하지 않은 상태에서도 시험 창이 캡처에 잡히지 않는다({control:P1}). " +
                (remote ? "원격 데스크톱 세션이다. " : "") +
                "이 환경에서는 캡처 차단이 동작한다고 말할 수 없다.";
            return false;
        }

        if (!Native.SetWindowDisplayAffinity(_hwnd, Native.WDA_EXCLUDEFROMCAPTURE))
        {
            Status = GuardStatus.Unsupported;
            Detail = reason = $"WDA_EXCLUDEFROMCAPTURE 설정 실패 (Win10 2004+ 필요, err={Marshal.GetLastWin32Error()})";
            return false;
        }

        _settle(250);
        var leak = SentinelRatio();
        Diagnostics += $" · 차단 후 {leak:P1}";

        if (leak >= LeakThreshold)
        {
            Status = GuardStatus.Failed;
            Detail = reason =
                $"플래그를 걸었는데도 시험 창 내용이 캡처에 남는다({leak:P1}). " +
                (remote
                    ? "원격 데스크톱 세션에서는 WDA_EXCLUDEFROMCAPTURE 가 기대대로 동작하지 않는다(설계서 14장 미결 4번)."
                    : "이 기기·드라이버 조합을 한계 목록에 기록해야 한다.");
            return false;
        }

        Status = GuardStatus.Ok;
        Detail = reason = "캡처 차단 확인 — 시험 창 내용이 캡처에 남지 않는다";
        return true;
    }

    /// <summary>30초 주기 자가검증. 설계서 06장 "지금도 유효함을 계속 증명한다".</summary>
    public JsonObject Verify(DateTimeOffset now)
    {
        var affinityOk = Native.GetWindowDisplayAffinity(_hwnd, out var affinity)
                         && affinity == Native.WDA_EXCLUDEFROMCAPTURE;

        var leak = SentinelRatio();
        var blank = leak < LeakThreshold;
        var ok = affinityOk && blank;

        Status = Status == GuardStatus.Unsupported ? GuardStatus.Unsupported
               : ok ? GuardStatus.Ok : GuardStatus.Failed;

        return new JsonObject
        {
            ["kind"] = "captureGuard",
            ["source"] = "selfverify",
            ["signal"] = "S13",
            ["collector"] = "wda-sentinel-selfcheck",
            ["platform"] = "windows",
            ["ts"] = Redaction.IsoSec(now),
            ["windowAffinityOk"] = affinityOk,
            ["selfCaptureBlank"] = blank,
            ["ok"] = ok,
        };
    }

    public void Release() => Native.SetWindowDisplayAffinity(_hwnd, Native.WDA_NONE);

    /// <summary>
    /// 센티넬 띠 영역을 GDI BitBlt 으로 찍어 센티넬 색 픽셀의 비율을 잰다.
    /// 커닝 도구가 쓰는 것과 같은 경로여야 의미가 있으므로 화면 DC 에서 직접 찍는다.
    /// 캡처 자체가 실패하면 1.0 — "확인하지 못했다"를 "안전하다"로 읽지 않는다.
    /// </summary>
    private double SentinelRatio()
    {
        ScreenRect r;
        try { r = _sentinelRect(); }
        catch { return 1.0; }

        var w = r.Right - r.Left;
        var h = r.Bottom - r.Top;
        if (w <= 4 || h <= 2) return 1.0;

        var screen = Native.GetDC(IntPtr.Zero);
        var mem = IntPtr.Zero;
        var bmp = IntPtr.Zero;
        try
        {
            mem = Native.CreateCompatibleDC(screen);
            bmp = Native.CreateCompatibleBitmap(screen, w, h);
            var old = Native.SelectObject(mem, bmp);
            var blitted = Native.BitBlt(mem, 0, 0, w, h, screen, r.Left, r.Top, Native.SRCCOPY);
            Native.SelectObject(mem, old);
            if (!blitted) return 1.0;

            var bmi = new Native.BITMAPINFO
            {
                bmiHeader = new Native.BITMAPINFOHEADER
                {
                    biSize = Marshal.SizeOf<Native.BITMAPINFOHEADER>(),
                    biWidth = w,
                    biHeight = -h, // 위에서 아래로
                    biPlanes = 1,
                    biBitCount = 32,
                    biCompression = 0,
                },
            };

            var bytes = new byte[w * h * 4];
            if (Native.GetDIBits(screen, bmp, 0, (uint)h, bytes, ref bmi, Native.DIB_RGB_COLORS) == 0) return 1.0;

            long hit = 0, sampled = 0;
            for (var i = 0; i + 3 < bytes.Length; i += 4)
            {
                sampled++;
                // BGRA 순서
                if (Math.Abs(bytes[i] - SentinelB) <= ColorTolerance &&
                    Math.Abs(bytes[i + 1] - SentinelG) <= ColorTolerance &&
                    Math.Abs(bytes[i + 2] - SentinelR) <= ColorTolerance) hit++;
            }
            return sampled == 0 ? 1.0 : (double)hit / sampled;
        }
        catch
        {
            return 1.0;
        }
        finally
        {
            if (bmp != IntPtr.Zero) Native.DeleteObject(bmp);
            if (mem != IntPtr.Zero) Native.DeleteDC(mem);
            if (screen != IntPtr.Zero) Native.ReleaseDC(IntPtr.Zero, screen);
        }
    }
}
