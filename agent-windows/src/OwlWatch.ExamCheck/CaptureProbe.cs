using System.Drawing;
using OwlWatch.Collectors;

namespace OwlWatch.ExamCheck;

/// <summary>
/// 이 기기에서 시험 창 캡처 차단이 실제로 동작하는지 미리 확인한다.
///
/// L0 는 차단하지 않지만, L1 을 켤 수 있는 기기인지는 시험 전에 알아야 한다.
/// WDA_EXCLUDEFROMCAPTURE 는 Win10 2004+ 이고, 원격 데스크톱 세션이나 일부 가상 디스플레이
/// 환경에서는 기대대로 동작하지 않는다(설계서 14장 미결 4번). 추측하지 않고 직접 찍어 본다.
///
/// 작은 창을 잠깐 띄워 대조 실험을 한다 — 플래그 없이 찍으면 센티넬 띠가 보이고,
/// 걸고 찍으면 안 보여야 한다. 둘 중 하나라도 어긋나면 통과가 아니다.
/// </summary>
public static class CaptureProbe
{
    /// <summary>기다리되 메시지 펌프를 돌린다 — 막힌 UI 스레드로는 창이 그려지지 않는다.</summary>
    private static void Pump(int ms)
    {
        var until = Environment.TickCount64 + ms;
        while (Environment.TickCount64 < until)
        {
            Application.DoEvents();
            Thread.Sleep(15);
        }
    }

    public static (CaptureGuard.GuardStatus Status, string Detail) Run()
    {
        using var probe = new ProbeForm();
        try
        {
            probe.Show();
            probe.Activate();
            Pump(300);

            var guard = new CaptureGuard(probe.Handle, () => probe.SentinelScreenRect, Pump);
            var ok = guard.Arm(out var reason);
            guard.Release();
            var detail = ok ? "이 기기에서 시험 창 캡처 차단이 동작한다" : reason;
            return (guard.Status, $"{detail}  [{guard.Diagnostics}]");
        }
        catch (Exception ex)
        {
            return (CaptureGuard.GuardStatus.Unsupported, $"확인 실패: {ex.Message}");
        }
        finally
        {
            probe.Hide();
        }
    }

    /// <summary>대조 실험용 창. 센티넬 띠와 사람이 볼 무늬를 함께 그린다.</summary>
    private sealed class ProbeForm : Form
    {
        private static readonly Color Sentinel =
            Color.FromArgb(CaptureGuard.SentinelR, CaptureGuard.SentinelG, CaptureGuard.SentinelB);

        private Rectangle SentinelBand => new(16, 60, ClientSize.Width - 32, 26);

        /// <summary>센티넬 띠의 화면 좌표. WinForms 가 DPI 스케일을 처리한 값이다.</summary>
        public ScreenRect SentinelScreenRect
        {
            get
            {
                var r = RectangleToScreen(SentinelBand);
                return new ScreenRect(r.Left, r.Top, r.Right, r.Bottom);
            }
        }

        public ProbeForm()
        {
            FormBorderStyle = FormBorderStyle.None;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.Manual;
            var wa = Screen.PrimaryScreen?.WorkingArea ?? new Rectangle(0, 0, 800, 600);
            Size = new Size(380, 200);
            Location = new Point(wa.Left + (wa.Width - Width) / 2, wa.Top + (wa.Height - Height) / 2);
            BackColor = Color.White;
            TopMost = true;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            var g = e.Graphics;
            g.Clear(Color.White);

            using var f = new Font("Malgun Gothic", 10f, FontStyle.Bold);
            using var small = new Font("Consolas", 8f);
            g.DrawString("캡처 차단 확인 중…", f, Brushes.Black, 18, 22);

            using var sentinel = new SolidBrush(Sentinel);
            g.FillRectangle(sentinel, SentinelBand);

            g.DrawString("이 띠가 캡처 결과에 보이면 차단이 안 된 것이다", small, Brushes.DimGray, 18, 100);
        }
    }
}
