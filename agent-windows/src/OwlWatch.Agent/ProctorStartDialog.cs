using System.Drawing;
using OwlWatch.Runtime;

namespace OwlWatch.Agent;

/// <summary>
/// 콘솔 없이 쓸 때의 감독관 시작 확인.
///
/// 설계서 09장: "ARMED 진입은 감독관이 콘솔에서 시작을 누르거나, 학생 화면의 60초 코드가
/// 콘솔과 일치함을 감독관이 확인했을 때만. 학생이 임의로 들어가지 못한다."
///
/// 콘솔이 있으면 이 창은 뜨지 않는다 — 하트비트 응답의 arm 명령이 정식 경로다.
/// 여기서 쓰는 세션 비밀은 인증이 아니라 감독관 대조용 표식이다. 학생이 알면 우회된다.
/// </summary>
public sealed class ProctorStartDialog : Form
{
    private readonly TextBox _input = new();
    private readonly Label _error = new();
    private readonly string _secret;

    public ProctorStartDialog(SessionConfig cfg)
    {
        _secret = cfg.SessionCode ?? "";

        Text = "감독관 시작 확인";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MaximizeBox = false;
        MinimizeBox = false;
        ClientSize = new Size(480, 250);
        BackColor = Color.FromArgb(250, 250, 247);
        Font = new Font("Malgun Gothic", 9.5f);

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, Padding = new Padding(24, 20, 24, 16),
        };
        for (var i = 0; i < 5; i++) root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        root.Controls.Add(new Label
        {
            Text = "감독관 확인", Font = new Font("Malgun Gothic", 14f, FontStyle.Bold),
            AutoSize = true, Margin = new Padding(0, 0, 0, 6),
        }, 0, 0);

        root.Controls.Add(new Label
        {
            Text = $"{cfg.ExamTitle} · 좌석 {cfg.Seat?.ToString() ?? "미지정"}\n" +
                   "감독관이 세션 코드를 입력해야 감시가 시작된다. 학생은 이 단계를 건너뛸 수 없다.",
            ForeColor = Color.FromArgb(105, 113, 124), AutoSize = true,
            MaximumSize = new Size(420, 0), Margin = new Padding(0, 0, 0, 14),
        }, 0, 1);

        _input.Font = new Font("Consolas", 14f);
        _input.Width = 420;
        _input.UseSystemPasswordChar = true;
        _input.Margin = new Padding(0, 0, 0, 8);
        root.Controls.Add(_input, 0, 2);

        _error.ForeColor = Color.FromArgb(179, 38, 30);
        _error.AutoSize = true;
        _error.Margin = new Padding(0, 0, 0, 10);
        root.Controls.Add(_error, 0, 3);

        var ok = new Button
        {
            Text = "시험 시작", AutoSize = true, Padding = new Padding(16, 6, 16, 6),
            BackColor = Color.FromArgb(31, 78, 122), ForeColor = Color.White, FlatStyle = FlatStyle.Flat,
        };
        ok.FlatAppearance.BorderSize = 0;
        ok.Click += (_, _) =>
        {
            if (_input.Text == _secret) { DialogResult = DialogResult.OK; Close(); }
            else { _error.Text = "코드가 다르다."; _input.SelectAll(); _input.Focus(); }
        };

        var cancel = new Button
        {
            Text = "나중에", AutoSize = true, Padding = new Padding(16, 6, 16, 6),
            FlatStyle = FlatStyle.Flat, DialogResult = DialogResult.Cancel,
        };

        var buttons = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill, AutoSize = true,
        };
        buttons.Controls.Add(ok);
        buttons.Controls.Add(cancel);
        root.Controls.Add(buttons, 0, 4);

        AcceptButton = ok;
        CancelButton = cancel;
        Controls.Add(root);
    }
}
