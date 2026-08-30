using System.Drawing;
using System.Text;
using System.Text.Json.Nodes;
using System.Drawing.Drawing2D;
using OwlWatch.Collectors;
using OwlWatch.Core;
using OwlWatch.Runtime;

namespace OwlWatch.Agent;

/// <summary>
/// L1 시험 창.
///
/// 왼쪽이 시험 화면이고 여기에 WDA_EXCLUDEFROMCAPTURE 가 걸린다 — 화면에는 보이지만
/// 어떤 캡처에도 내용이 나오지 않는다. 오른쪽은 학생 상태창이다.
///
/// 설계서 10장: "학생 상태창 — 전송된 이벤트를 감독관이 보는 것과 동일한 형식·등급으로
/// 학생도 본다." 감독관에게만 보이는 화면을 따로 만들지 않는다.
/// </summary>
public sealed class ExamWindow : Form
{
    private static readonly Color Paper = Color.FromArgb(250, 250, 247);
    private static readonly Color Ink = Color.FromArgb(27, 30, 35);
    private static readonly Color Muted = Color.FromArgb(105, 113, 124);
    private static readonly Color Crit = Color.FromArgb(179, 38, 30);
    private static readonly Color Warn = Color.FromArgb(164, 106, 12);
    private static readonly Color Ok = Color.FromArgb(43, 122, 75);
    private static readonly Color Accent = Color.FromArgb(31, 78, 122);

    private readonly SessionConfig _cfg;
    private readonly AgentSession _session;

    private readonly Label _state = new();
    private readonly Label _stateDetail = new();
    private readonly Label _code = new();
    private readonly Label _codeTimer = new();
    private readonly Label _guard = new();
    private readonly Label _net = new();
    private readonly FlowLayoutPanel _feed = new();
    private readonly Label _empty = new();
    private readonly Button _endButton = new();

    private readonly System.Windows.Forms.Timer _uiTick = new() { Interval = 1000 };

    private Panel? _examBody;

    private static readonly Color SentinelColor =
        Color.FromArgb(CaptureGuard.SentinelR, CaptureGuard.SentinelG, CaptureGuard.SentinelB);

    /// <summary>
    /// 캡처 차단 자가검증이 볼 센티넬 띠. 시험 화면 안쪽에 있으므로,
    /// 이 띠가 캡처에 보인다는 것은 곧 문제도 보인다는 뜻이다.
    /// </summary>
    public ScreenRect SentinelScreenRect
    {
        get
        {
            if (_examBody is null) return new ScreenRect(0, 0, 0, 0);
            var band = new Rectangle(14, 6, Math.Max(8, _examBody.ClientSize.Width - 28), 10);
            var r = _examBody.RectangleToScreen(band);
            return new ScreenRect(r.Left, r.Top, r.Right, r.Bottom);
        }
    }

    /// <summary>기다리되 메시지 펌프를 돌린다. 막힌 UI 스레드로는 창이 그려지지 않는다.</summary>
    public void Pump(int ms)
    {
        var until = Environment.TickCount64 + ms;
        while (Environment.TickCount64 < until)
        {
            Application.DoEvents();
            Thread.Sleep(15);
        }
    }

    public ExamWindow(SessionConfig cfg, AgentSession session)
    {
        _cfg = cfg;
        _session = session;

        Text = $"OwlWatch — {cfg.ExamTitle}";
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(1180, 760);
        MinimumSize = new Size(980, 640);
        BackColor = Paper;
        Font = new Font("Malgun Gothic", 9.5f);

        var split = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Paper,
            Padding = new Padding(16),
        };
        split.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 62));
        split.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 38));
        split.Controls.Add(BuildExamSurface(), 0, 0);
        split.Controls.Add(BuildStatusPanel(), 1, 0);
        Controls.Add(split);

        _session.EventsAdded += OnEvents;
        _session.StateChanged += _ => BeginInvoke(RefreshStatus);
        _uiTick.Tick += (_, _) => RefreshStatus();
        _uiTick.Start();
        RefreshStatus();
    }

    // ── 시험 화면 ────────────────────────────────────────────────

    /// <summary>
    /// 실제 배포에서는 여기에 WebView2 로 LMS 를 띄운다(설계서 06장).
    /// WebView2 는 NuGet 패키지와 런타임 배포가 필요해 M1 범위 밖으로 뒀고,
    /// 지금은 캡처 차단이 실제로 동작하는지 눈으로 확인할 수 있는 대조 무늬를 그린다 —
    /// 빈 창이 캡처에 안 잡히는 것은 아무것도 증명하지 못하기 때문이다.
    /// 맨 위 얇은 띠가 자가검증용 센티넬이다.
    /// </summary>
    private Control BuildExamSurface()
    {
        var host = new Panel { Dock = DockStyle.Fill, BackColor = Color.White, Margin = new Padding(0, 0, 12, 0) };

        var banner = new Label
        {
            Dock = DockStyle.Top, Height = 40, BackColor = Accent, ForeColor = Color.White,
            TextAlign = ContentAlignment.MiddleLeft, Padding = new Padding(16, 0, 0, 0),
            Text = "이 영역은 화면 캡처에서 제외된다 — 스크린샷·녹화·캡처 도구에는 이 창이 아예 찍히지 않는다",
            Font = new Font("Malgun Gothic", 9.5f, FontStyle.Bold),
        };

        var body = new Panel { Dock = DockStyle.Fill, BackColor = Color.White, Padding = new Padding(28, 22, 28, 22) };
        _examBody = body;
        body.Paint += (_, e) =>
        {
            var g = e.Graphics;
            var w = body.ClientSize.Width;

            // 센티넬 띠. 자가검증은 이 색이 캡처에 나타나는지만 본다 —
            // 캡처 결과가 검은지 보는 방식은 WDA_EXCLUDEFROMCAPTURE 에서 성립하지 않는다.
            using (var sentinel = new SolidBrush(SentinelColor))
                g.FillRectangle(sentinel, 14, 6, Math.Max(8, w - 28), 10);

            using var h1 = new Font("Malgun Gothic", 15f, FontStyle.Bold);
            using var norm = new Font("Malgun Gothic", 11f);
            using var mono = new Font("Consolas", 10.5f);
            using var dim = new SolidBrush(Muted);
            using var ink = new SolidBrush(Ink);

            g.DrawString($"{_cfg.ExamTitle}", h1, ink, 28, 26);
            g.DrawString(string.IsNullOrEmpty(_cfg.ConsoleBaseUrl)
                ? "LMS 연동 자리 — 실제 배포에서는 이 영역이 WebView2 로 대체된다"
                : $"LMS 연동 자리 · 콘솔 {_cfg.ConsoleBaseUrl}", norm, dim, 28, 56);

            // 캡처 차단이 실제로 걸렸는지 눈으로 확인하려면 대조할 무늬가 있어야 한다.
            var y = 100;
            using var stripe = new SolidBrush(Color.FromArgb(227, 236, 245));
            for (var i = 0; i < 7; i++)
            {
                g.FillRectangle(stripe, 28, y, Math.Max(120, w - 56), 34);
                g.DrawString($"{i + 1}. 이 줄이 캡처 결과에 보이면 차단이 깨진 것이다.", norm, ink, 40, y + 7);
                y += 44;
            }

            g.DrawString("지금 PrintScreen 이나 캡처 도구로 찍어 보라 — 이 창이 없는 것처럼 뒤 배경만 찍힌다.",
                mono, dim, 28, y + 12);
        };

        host.Controls.Add(body);
        host.Controls.Add(banner);
        return host;
    }

    // ── 학생 상태창 ──────────────────────────────────────────────

    private Control BuildStatusPanel()
    {
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, BackColor = Paper,
        };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        // 상태
        var head = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown, AutoSize = true, Dock = DockStyle.Fill,
            BackColor = Color.White, Padding = new Padding(16, 13, 16, 13), Margin = new Padding(0, 0, 0, 10),
        };
        _state.Font = new Font("Malgun Gothic", 16f, FontStyle.Bold);
        _state.AutoSize = true;
        _state.Margin = new Padding(0, 0, 0, 3);
        _stateDetail.ForeColor = Muted;
        _stateDetail.AutoSize = true;
        _stateDetail.MaximumSize = new Size(370, 0);
        head.Controls.Add(_state);
        head.Controls.Add(_stateDetail);
        root.Controls.Add(head, 0, 0);

        // 코드
        var codeBox = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown, AutoSize = true, Dock = DockStyle.Fill,
            BackColor = Color.White, Padding = new Padding(16, 13, 16, 13), Margin = new Padding(0, 0, 0, 10),
        };
        codeBox.Controls.Add(new Label
        {
            Text = "감독관 확인 코드", ForeColor = Muted, AutoSize = true,
            Font = new Font("Consolas", 8.5f), Margin = new Padding(0, 0, 0, 4),
        });
        _code.Font = new Font("Consolas", 26f, FontStyle.Bold);
        _code.ForeColor = Accent;
        _code.AutoSize = true;
        _code.Margin = new Padding(0);
        _codeTimer.ForeColor = Muted;
        _codeTimer.AutoSize = true;
        codeBox.Controls.Add(_code);
        codeBox.Controls.Add(_codeTimer);
        root.Controls.Add(codeBox, 0, 1);

        // 보호 상태
        var guardBox = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown, AutoSize = true, Dock = DockStyle.Fill,
            BackColor = Color.White, Padding = new Padding(16, 13, 16, 13), Margin = new Padding(0, 0, 0, 10),
        };
        _guard.AutoSize = true;
        _guard.MaximumSize = new Size(370, 0);
        _net.AutoSize = true;
        _net.ForeColor = Muted;
        _net.MaximumSize = new Size(370, 0);
        _net.Margin = new Padding(0, 4, 0, 0);
        guardBox.Controls.Add(_guard);
        guardBox.Controls.Add(_net);
        root.Controls.Add(guardBox, 0, 2);

        // 이벤트 피드 — 감독관이 보는 것과 같은 형식
        _feed.Dock = DockStyle.Fill;
        _feed.FlowDirection = FlowDirection.TopDown;
        _feed.WrapContents = false;
        _feed.AutoScroll = true;
        _feed.BackColor = Color.White;
        _feed.Padding = new Padding(14, 12, 14, 12);
        _empty.Text = "전송된 항목이 없다.\n\n여기 보이는 것은 감독관 화면과 같다 — " +
                      "따로 보내는 것도, 감추는 것도 없다.";
        _empty.ForeColor = Muted;
        _empty.AutoSize = true;
        _empty.MaximumSize = new Size(350, 0);
        _feed.Controls.Add(_empty);
        root.Controls.Add(_feed, 0, 3);

        // 종료
        _endButton.Text = "시험 종료 · 보호 해제";
        _endButton.AutoSize = true;
        _endButton.Padding = new Padding(14, 7, 14, 7);
        _endButton.FlatStyle = FlatStyle.Flat;
        _endButton.Margin = new Padding(0, 10, 0, 0);
        _endButton.Click += (_, _) => Close();

        var save = new Button
        {
            Text = "내 기록 내보내기", AutoSize = true, Padding = new Padding(14, 7, 14, 7),
            FlatStyle = FlatStyle.Flat, Margin = new Padding(0, 10, 8, 0),
        };
        save.Click += (_, _) => Export();

        var buttons = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill, AutoSize = true,
            BackColor = Paper,
        };
        buttons.Controls.Add(_endButton);
        buttons.Controls.Add(save);
        root.Controls.Add(buttons, 0, 4);

        return root;
    }

    private void OnEvents(IReadOnlyList<JsonObject> events)
    {
        if (IsDisposed) return;
        BeginInvoke(() =>
        {
            if (_empty.Parent is not null) _feed.Controls.Remove(_empty);
            foreach (var e in events) _feed.Controls.Add(EventRow(e));
            _feed.ScrollControlIntoView(_feed.Controls[^1]);
            RefreshStatus();
        });
    }

    private static Control EventRow(JsonObject e)
    {
        var sev = e.Str("severity") ?? "info";
        var color = sev switch { "crit" => Crit, "warn" => Warn, _ => Muted };

        var row = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false,
            Margin = new Padding(0, 0, 0, 10), Padding = new Padding(11, 8, 11, 8),
            BackColor = Color.FromArgb(248, 249, 251), Width = 350,
        };
        row.Controls.Add(new Label
        {
            Text = e.Str("summary"), ForeColor = Ink, AutoSize = true, MaximumSize = new Size(325, 0),
            Font = new Font("Malgun Gothic", 9.5f, sev == "crit" ? FontStyle.Bold : FontStyle.Regular),
        });
        row.Controls.Add(new Label
        {
            Text = $"{e.Str("grade")} · {e.Str("rule")}", ForeColor = color, AutoSize = true,
            Font = new Font("Consolas", 8f), Margin = new Padding(0, 4, 0, 0),
        });
        return row;
    }

    private void RefreshStatus()
    {
        if (IsDisposed) return;

        var (text, color, detail) = _session.State switch
        {
            SessionState.Precheck => ("사전 점검 중", Muted, "커널 원장과 캡처 차단이 실제로 켜졌는지 확인하고 있다."),
            SessionState.Ready => ("시작 대기", Accent, "감독관이 시작을 확인하면 감시가 시작된다. 학생이 임의로 들어갈 수 없다."),
            SessionState.Armed => ("감시 중", Ok, "시험 창이 캡처에서 제외돼 있고 보호가 유효하다."),
            SessionState.Warn => ("정황 있음", Warn, "감독관이 한 번 확인하면 되는 단계다. 부정행위 판정이 아니다."),
            SessionState.Crit => ("확인 필요", Crit, "감독관이 좌석으로 온다. 아래 항목을 함께 확인하면 된다."),
            SessionState.Offline => ("콘솔 연결 끊김", Warn, "기록은 이 기기에 계속 쌓이고, 연결되면 순서대로 전송된다."),
            SessionState.Ended => ("종료됨", Muted, "보호를 해제했고 세션 키를 지웠다."),
            _ => ("대기", Muted, ""),
        };
        _state.Text = text;
        _state.ForeColor = color;
        _stateDetail.Text = _session.PrecheckFailure ?? detail;

        var now = DateTimeOffset.UtcNow;
        _code.Text = _session.Code();
        _codeTimer.Text = $"{SessionCode.SecondsRemaining(now)}초 후 갱신 · 체인 {_session.ChainHead[..8]}";

        var g = _session.GuardStatus;
        _guard.Text = g switch
        {
            CaptureGuard.GuardStatus.Ok => "캡처 차단 유효 — 30초마다 직접 찍어 확인하고 있다",
            CaptureGuard.GuardStatus.Failed => "캡처 차단이 깨졌다 — 감독관 확인 필요",
            CaptureGuard.GuardStatus.Unsupported => "이 기기에서는 캡처 차단을 확인할 수 없다",
            _ => "캡처 차단 꺼짐 (L0)",
        };
        _guard.ForeColor = g switch
        {
            CaptureGuard.GuardStatus.Ok => Ok,
            CaptureGuard.GuardStatus.Failed => Crit,
            CaptureGuard.GuardStatus.Unsupported => Warn,
            _ => Muted,
        };

        var attest = _session.AttestationKind == "hw"
            ? "기기 키: TPM"
            : "기기 키: 소프트웨어 폴백 — 이 기기는 하드웨어로 신원을 증명하지 못한다";

        var ledger = _session.LedgerMode == "kernel"
            ? "실행 기록: 커널 원장 — 시험 중 실행이 전부 기록된다"
            : "실행 기록: 폴링 폴백 — 짧게 실행되는 프로그램은 놓칠 수 있어 등급이 낮게 표기된다";
        var console = string.IsNullOrEmpty(_cfg.ConsoleBaseUrl)
            ? "콘솔 없음 (로컬 기록만)"
            : _session.Online ? "콘솔 연결됨" : $"콘솔 미연결 — {_session.LastError}";
        _net.Text = $"{attest} · {console}\n{ledger}";
    }

    private void Export()
    {
        using var dlg = new SaveFileDialog
        {
            Filter = "JSON|*.json",
            FileName = $"owlwatch-{_cfg.SessionId}-{DateTime.Now:yyyyMMdd-HHmmss}.json",
        };
        if (dlg.ShowDialog() != DialogResult.OK) return;
        J.WriteFile(dlg.FileName, _session.ExportBundle().ToJsonString(J.Pretty));
        MessageBox.Show(this,
            "저장했다. P0(확인된 사실)·P1(정황)·P2(참고)가 섞이지 않게 세 절로 나뉘어 있다.",
            "내보내기", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (_session.State is SessionState.Armed or SessionState.Warn or SessionState.Crit)
        {
            var r = MessageBox.Show(this,
                "시험이 진행 중이다. 지금 닫으면 캡처 차단이 풀리고 감독관 화면에 종료로 기록된다. 닫을까?",
                "시험 종료", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (r != DialogResult.Yes) { e.Cancel = true; return; }
        }
        _uiTick.Stop();
        base.OnFormClosing(e);
    }
}
