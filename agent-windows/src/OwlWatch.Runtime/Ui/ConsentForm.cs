using System.Drawing;
namespace OwlWatch.Runtime.Ui;

/// <summary>
/// 동의 화면. 설계서 10장: "위 표를 그대로 보여주고 '시험 응시 조건으로 동의'."
///
/// 수집·비수집 목록은 설계서의 표를 옮긴 것이고, 코드가 실제로 그 범위 안에 있다는 것은
/// Native.cs 의 P/Invoke 목록으로 확인할 수 있다. 동의하지 않으면 아무 관측도 만들지 않는다.
/// </summary>
public sealed class ConsentForm : Form
{
    private static readonly string[] Collect =
    {
        "실행 파일 경로(홈 디렉터리는 ~ 로 치환) · 해시 · 서명자 · 시작 시각",
        "상태 영역(트레이) 항목의 소유 프로세스",
        "창의 캡처 공유 상태 — 창 제목은 읽지 않는다",
        "Caps Lock 상태가 뒤집힌 시각",
        "네트워크 인터페이스 수 · 시험망 비콘 도달 여부 · 프로세스별 원격 host:port",
        "가상머신 여부 · 에이전트 자기 서명 검증 결과",
    };

    private static readonly string[] DontCollect =
    {
        "키 입력 — 어떤 키를 눌렀는지는 알 수 없다",
        "화면 내용 · 스크린샷 · 창 제목",
        "클립보드 · 파일 내용 · 파일 목록",
        "브라우저 방문 기록",
        "카메라 · 마이크",
        "위치 · Wi-Fi SSID",
        "학생 이름 — 좌석 번호만 쓴다",
        "실행 인자(argv) · 환경변수",
    };

    public ConsentForm(SessionConfig cfg, string levelNote)
    {
        Text = "OwlWatch 점검 — 수집 항목 안내";
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(760, 620);
        MinimumSize = new Size(680, 560);
        BackColor = Color.FromArgb(250, 250, 247);
        Font = new Font("Malgun Gothic", 9.5f);

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 5,
            Padding = new Padding(28, 24, 28, 20),
            BackColor = Color.Transparent,
        };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        root.Controls.Add(new Label
        {
            Text = "OwlWatch 사전 점검",
            Font = new Font("Malgun Gothic", 17f, FontStyle.Bold),
            ForeColor = Color.FromArgb(27, 30, 35),
            AutoSize = true,
            Margin = new Padding(0, 0, 0, 6),
        }, 0, 0);

        root.Controls.Add(new Label
        {
            Text = $"{cfg.ExamTitle} · {levelNote}",
            ForeColor = Color.FromArgb(105, 113, 124),
            AutoSize = true,
            MaximumSize = new Size(700, 0),
            Margin = new Padding(0, 0, 0, 16),
        }, 0, 1);

        var cols = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Color.Transparent,
        };
        cols.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        cols.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        cols.Controls.Add(Panel("수집하는 것", Collect, Color.FromArgb(31, 78, 122)), 0, 0);
        cols.Controls.Add(Panel("수집하지 않는 것", DontCollect, Color.FromArgb(181, 69, 27)), 1, 0);
        root.Controls.Add(cols, 0, 2);

        root.Controls.Add(new Label
        {
            Text = "점검 결과는 이 기기에 남고 기본 30일 후 삭제된다. 이 도구는 부정행위를 판정하지 않는다 — " +
                   "확인 요청을 만들 뿐이고, 판단은 사람과 위원회가 한다.",
            ForeColor = Color.FromArgb(62, 69, 78),
            AutoSize = true,
            MaximumSize = new Size(700, 0),
            Margin = new Padding(0, 16, 0, 12),
        }, 0, 3);

        var buttons = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill, AutoSize = true,
            BackColor = Color.Transparent,
        };
        var ok = new Button
        {
            Text = "동의하고 점검 시작", AutoSize = true, Padding = new Padding(14, 7, 14, 7),
            BackColor = Color.FromArgb(31, 78, 122), ForeColor = Color.White, FlatStyle = FlatStyle.Flat,
            DialogResult = DialogResult.OK,
        };
        ok.FlatAppearance.BorderSize = 0;
        var no = new Button
        {
            Text = "동의하지 않음", AutoSize = true, Padding = new Padding(14, 7, 14, 7),
            DialogResult = DialogResult.Cancel, FlatStyle = FlatStyle.Flat,
        };
        buttons.Controls.Add(ok);
        buttons.Controls.Add(no);
        root.Controls.Add(buttons, 0, 4);

        AcceptButton = ok;
        CancelButton = no;
        Controls.Add(root);
    }

    private static Control Panel(string title, IEnumerable<string> items, Color accent)
    {
        var box = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, AutoScroll = true,
            BackColor = Color.White, Margin = new Padding(0, 0, 10, 0), Padding = new Padding(14, 12, 14, 12),
        };
        box.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        box.Controls.Add(new Label
        {
            Text = title, Font = new Font("Malgun Gothic", 10.5f, FontStyle.Bold),
            ForeColor = accent, AutoSize = true, Margin = new Padding(0, 0, 0, 8),
        });
        foreach (var s in items)
        {
            box.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            box.Controls.Add(new Label
            {
                Text = "· " + s, AutoSize = true, MaximumSize = new Size(310, 0),
                ForeColor = Color.FromArgb(45, 50, 58), Margin = new Padding(0, 0, 0, 6),
            });
        }
        return box;
    }
}
