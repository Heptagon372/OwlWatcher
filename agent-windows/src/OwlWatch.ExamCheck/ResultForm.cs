using System.Drawing;
using System.Text;
using System.Text.Json.Nodes;
using OwlWatch.Core;
using OwlWatch.Runtime;

namespace OwlWatch.ExamCheck;

/// <summary>
/// 결과 화면. 설계서 05장 문구 규칙과 08장 알림 피드의 L0 판이다.
/// 등급 배지를 문장 앞에 두고, P0/P1/P2 를 섞지 않는다.
/// </summary>
public sealed class ResultForm : Form
{
    private static readonly Color Paper = Color.FromArgb(250, 250, 247);
    private static readonly Color Ink = Color.FromArgb(27, 30, 35);
    private static readonly Color Muted = Color.FromArgb(105, 113, 124);
    private static readonly Color Crit = Color.FromArgb(179, 38, 30);
    private static readonly Color Warn = Color.FromArgb(164, 106, 12);
    private static readonly Color Ok = Color.FromArgb(43, 122, 75);
    private static readonly Color Accent = Color.FromArgb(31, 78, 122);

    private readonly JsonObject _report;
    private readonly SessionConfig _cfg;
    private readonly Label _code = new();
    private readonly Label _codeTimer = new();
    private readonly System.Windows.Forms.Timer _tick = new() { Interval = 1000 };

    public ResultForm(SessionConfig cfg, JsonObject report, IReadOnlyList<JsonObject> events)
    {
        _cfg = cfg;
        _report = report;

        Text = "OwlWatch 점검 결과";
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(880, 660);
        MinimumSize = new Size(760, 560);
        BackColor = Paper;
        Font = new Font("Malgun Gothic", 9.5f);

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5,
            Padding = new Padding(28, 22, 28, 18), BackColor = Color.Transparent,
        };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        root.Controls.Add(Header(events), 0, 0);
        root.Controls.Add(Stats(), 0, 1);
        root.Controls.Add(Feed(events), 0, 2);
        root.Controls.Add(Limits(), 0, 3);
        root.Controls.Add(Buttons(), 0, 4);
        Controls.Add(root);

        _tick.Tick += (_, _) => RefreshCode();
        _tick.Start();
        RefreshCode();
    }

    private Control Header(IReadOnlyList<JsonObject> events)
    {
        var crit = events.Count(e => e.Str("severity") == "crit");
        var warn = events.Count(e => e.Str("severity") == "warn");

        var (text, color) = crit > 0
            ? ($"확인이 필요한 항목 {crit}건", Crit)
            : warn > 0
                ? ($"정황 {warn}건 — 감독관 확인 권장", Warn)
                : ("확인이 필요한 항목 없음", Ok);

        var box = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, BackColor = Color.Transparent };
        box.Controls.Add(new Label
        {
            Text = text, Font = new Font("Malgun Gothic", 19f, FontStyle.Bold),
            ForeColor = color, AutoSize = true, Margin = new Padding(0, 0, 0, 4),
        });
        box.Controls.Add(new Label
        {
            Text = $"{_cfg.ExamTitle} · {_report.Str("machine")} · {_report.Str("scannedAt")}",
            ForeColor = Muted, AutoSize = true, Margin = new Padding(0, 0, 0, 14),
        });
        return box;
    }

    private Control Stats()
    {
        var cap = _report.Obj("captureBlockCapability");
        var capStatus = cap.Str("status") ?? "off";
        var (capText, capColor) = capStatus switch
        {
            "ok" => ("가능", Ok),
            "failed" => ("차단 안 됨", Crit),
            "unsupported" => ("확인 불가", Warn),
            _ => ("확인 안 함", Muted),
        };

        var grid = new TableLayoutPanel
        {
            ColumnCount = 4, RowCount = 1, Dock = DockStyle.Top, AutoSize = true,
            BackColor = Color.Transparent, Margin = new Padding(0, 0, 0, 14),
        };
        for (var i = 0; i < 4; i++) grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25));

        grid.Controls.Add(Tile("프로세스", _report.Int("processCount")?.ToString() ?? "-", "검사한 실행 중 프로세스", Ink), 0, 0);
        grid.Controls.Add(Tile("관측", _report.Int("observationCount")?.ToString() ?? "-",
            $"{_report.Int("elapsedMs")}ms 소요", Ink), 1, 0);
        grid.Controls.Add(Tile("캡처 차단", capText, cap.Str("detail") ?? "", capColor), 2, 0);

        var codeBox = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown, AutoSize = true, BackColor = Color.White,
            Padding = new Padding(14, 11, 14, 11), Margin = new Padding(1), Dock = DockStyle.Fill,
        };
        codeBox.Controls.Add(new Label
        {
            Text = "확인 코드", ForeColor = Muted, AutoSize = true,
            Font = new Font("Consolas", 8.5f), Margin = new Padding(0, 0, 0, 4),
        });
        _code.Font = new Font("Consolas", 22f, FontStyle.Bold);
        _code.ForeColor = Accent;
        _code.AutoSize = true;
        _code.Margin = new Padding(0);
        codeBox.Controls.Add(_code);
        _codeTimer.ForeColor = Muted;
        _codeTimer.AutoSize = true;
        _codeTimer.Margin = new Padding(0, 2, 0, 0);
        codeBox.Controls.Add(_codeTimer);
        grid.Controls.Add(codeBox, 3, 0);

        return grid;
    }

    private static Control Tile(string key, string value, string detail, Color valueColor)
    {
        var box = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown, AutoSize = true, BackColor = Color.White,
            Padding = new Padding(14, 11, 14, 11), Margin = new Padding(1), Dock = DockStyle.Fill,
        };
        box.Controls.Add(new Label
        {
            Text = key, ForeColor = Muted, AutoSize = true,
            Font = new Font("Consolas", 8.5f), Margin = new Padding(0, 0, 0, 4),
        });
        box.Controls.Add(new Label
        {
            Text = value, Font = new Font("Malgun Gothic", 15f, FontStyle.Bold),
            ForeColor = valueColor, AutoSize = true, Margin = new Padding(0),
        });
        box.Controls.Add(new Label
        {
            Text = detail, ForeColor = Muted, AutoSize = true, MaximumSize = new Size(190, 0),
            Margin = new Padding(0, 3, 0, 0),
        });
        return box;
    }

    private Control Feed(IReadOnlyList<JsonObject> events)
    {
        var panel = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false,
            AutoScroll = true, BackColor = Color.White, Padding = new Padding(16, 14, 16, 14),
        };

        if (events.Count == 0)
        {
            panel.Controls.Add(new Label
            {
                Text = "허용목록 밖 프로세스도, 설명되지 않는 상태 영역 항목도 없다.\n" +
                       "시험 중에 새 프로그램이 실행되면 이 점검은 그것을 보지 못한다 — 그건 L1 에이전트의 몫이다.",
                ForeColor = Muted, AutoSize = true, MaximumSize = new Size(780, 0),
            });
            return panel;
        }

        // 심각도 순, 같으면 발생 순. 설계서: 등급을 먼저 말한다.
        var order = new Dictionary<string, int> { ["crit"] = 0, ["warn"] = 1, ["info"] = 2 };
        foreach (var e in events.OrderBy(e => order.GetValueOrDefault(e.Str("severity") ?? "info", 3))
                                .ThenBy(e => e.Int("seq") ?? 0))
        {
            panel.Controls.Add(EventRow(e));
        }
        return panel;
    }

    private static Control EventRow(JsonObject e)
    {
        var sev = e.Str("severity") ?? "info";
        var color = sev switch { "crit" => Crit, "warn" => Warn, _ => Muted };

        var row = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false,
            Margin = new Padding(0, 0, 0, 12), Padding = new Padding(12, 9, 12, 9),
            BackColor = Color.FromArgb(248, 249, 251), Width = 780,
        };
        row.Controls.Add(new Label
        {
            Text = e.Str("summary"), ForeColor = Ink, AutoSize = true, MaximumSize = new Size(750, 0),
            Font = new Font("Malgun Gothic", 10f, sev == "crit" ? FontStyle.Bold : FontStyle.Regular),
        });

        var contexts = (e["contexts"] as JsonArray)?.Select(n => n!.GetValue<string>()).ToList() ?? new();
        var meta = $"{e.Str("grade")} · {e.Str("rule")} · 신호 " +
                   string.Join("+", (e["signals"] as JsonArray)?.Select(n => n!.GetValue<string>()) ?? Array.Empty<string>());
        if (contexts.Count > 0) meta += " · 맥락 " + string.Join(", ", contexts.Select(KoreanContext));

        row.Controls.Add(new Label
        {
            Text = meta, ForeColor = color, AutoSize = true, Font = new Font("Consolas", 8.5f),
            Margin = new Padding(0, 5, 0, 0),
        });
        return row;
    }

    private static string KoreanContext(string id) => id switch
    {
        "downloadsPath" => "다운로드 경로",
        "unsignedBinary" => "미서명",
        "unnotarizedBinary" => "미공증",
        "startedNearExamStart" => "시험 직전 시작",
        "startedDuringExam" => "시험 중 시작",
        "multipleInterfaces" => "인터페이스 2개 이상",
        "softwareAttestation" => "소프트웨어 키",
        _ => id,
    };

    private Control Limits() => new Label
    {
        Text = _report.Str("한계") + " 휴대폰·2차 기기·AI 안경은 이 도구의 범위 밖이다.",
        ForeColor = Muted, AutoSize = true, MaximumSize = new Size(820, 0),
        Margin = new Padding(0, 14, 0, 12),
    };

    private Control Buttons()
    {
        var row = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill, AutoSize = true,
            BackColor = Color.Transparent,
        };

        var close = new Button
        {
            Text = "닫기", AutoSize = true, Padding = new Padding(14, 6, 14, 6),
            BackColor = Accent, ForeColor = Color.White, FlatStyle = FlatStyle.Flat,
        };
        close.FlatAppearance.BorderSize = 0;
        close.Click += (_, _) => Close();

        var save = new Button
        {
            Text = "결과 내보내기", AutoSize = true, Padding = new Padding(14, 6, 14, 6), FlatStyle = FlatStyle.Flat,
        };
        save.Click += (_, _) => Export();

        row.Controls.Add(close);
        row.Controls.Add(save);
        return row;
    }

    private void Export()
    {
        using var dlg = new SaveFileDialog
        {
            Filter = "JSON|*.json",
            FileName = $"owlwatch-examcheck-{DateTime.Now:yyyyMMdd-HHmmss}.json",
        };
        if (dlg.ShowDialog() != DialogResult.OK) return;
        J.WriteFile(dlg.FileName, _report.ToJsonString(J.Pretty));
        MessageBox.Show(this, "저장했다. 이 파일은 본인 기기에만 남는다.", "내보내기",
            MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void RefreshCode()
    {
        var now = DateTimeOffset.UtcNow;
        var head = _report.Str("chainHead") ?? Canonical.Genesis;
        _code.Text = SessionCode.Derive(_cfg.SessionCode ?? _cfg.SessionId, head, now);
        _codeTimer.Text = $"{SessionCode.SecondsRemaining(now)}초 후 갱신";
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        _tick.Stop();
        _tick.Dispose();
        base.OnFormClosed(e);
    }
}
