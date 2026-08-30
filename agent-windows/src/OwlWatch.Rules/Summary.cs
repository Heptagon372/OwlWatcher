using System.Globalization;
using System.Text.Json.Nodes;
using OwlWatch.Core;

namespace OwlWatch.Rules;

/// <summary>
/// 알림 문구. core-rules/src/summary.js 의 포트 — 글자 하나만 달라도 체인 해시가 갈린다.
/// 설계서 05장: 등급을 먼저 말한다 · 아이콘 모양 추정·부정행위 단정 금지 ·
/// G5 알림은 "어디 가서 무엇을 확인하라"를 말한다.
/// </summary>
public static class Summaries
{
    public static string GradeLabel(string grade) => grade switch
    {
        "P0" => "확정",
        "P1" => "정황",
        "P2" => "참고",
        _ => "정황",
    };

    /// <summary>세션 표준시 기준 HH:mm. 오프셋을 직접 더해 언어 간 결과를 고정한다.</summary>
    public static string FormatHm(string? ts, int tzOffsetMinutes = 540)
    {
        if (string.IsNullOrEmpty(ts)) return "--:--";
        var ms = DateTimeOffset.Parse(ts, CultureInfo.InvariantCulture).ToUnixTimeMilliseconds()
                 + (long)tzOffsetMinutes * 60000;
        var d = DateTimeOffset.FromUnixTimeMilliseconds(ms).UtcDateTime;
        return $"{d.Hour:D2}:{d.Minute:D2}";
    }

    private static string SeatLabel(SessionInfo s) => s.Seat.HasValue ? $"좌석 {s.Seat.Value}" : "좌석 미지정";

    private static readonly Dictionary<string, string?> Hints = new()
    {
        ["R-S9-UNKNOWN-EXEC"] = "화면 오른쪽 위 상태 영역과 작업표시줄 확인",
        ["R-DENY-PROCESS"] = "해당 프로그램을 종료시키고 사유 확인",
        ["R-S10-SCREENCAPTURE-GRANT"] = "화면 기록 권한을 받은 앱이 무엇인지 학생과 함께 확인",
        ["R-S12-HID-OPEN"] = "키보드 표시등(Caps Lock) 확인",
        ["R-S13-CAPTURE-GUARD-FAIL"] = "즉시 좌석으로 이동. 시험 창 보호가 꺼진 상태",
        ["R-S14-ATTESTATION-FAIL"] = "기기 신원 확인. 다른 기기의 하트비트일 수 있음",
        ["R-S7-LOCKDOWN-EXIT"] = "평가 모드 재진입 안내",
        ["R-S1-UNKNOWN-AGENT-PROC"] = "작업표시줄에 보이지 않는 프로그램. 실행 목록 확인",
        ["R-S2-UNKNOWN-STATUS-ITEM"] = "화면 오른쪽 위 상태 영역 확인",
        ["R-S3-CAPTURE-EXCLUDED-WINDOW"] = "화면에 보이는 창과 캡처 결과가 다른지 확인",
        ["R-S4-CAPS-PATTERN"] = "키보드 Caps Lock 표시등 점멸 확인",
        ["R-S11-CAPTURE-STACK"] = "화면 녹화·회의 앱이 켜져 있는지 확인",
        ["R-S6-VM"] = "가상머신 사용 여부 확인. 시험 정책 고지",
        ["R-S5-CANARY-REACHED"] = "휴대폰 테더링·핫스팟 사용 여부 확인",
        ["R-S5-BEACON-MISS"] = "네트워크 확인(조치 아님)",
        ["R-S8-INTEGRITY"] = "기기 상태 확인",
        ["R-CORR-LEDGER-BYPASS"] = "실행 기록에 없는 프로그램이 화면에 있다. 좌석 확인",
        ["R-CORR-SCAN-EVASION"] = "실행 기록에는 있으나 목록에서 숨은 프로그램. 좌석 확인",
        ["R-P1-ESCALATION"] = "정황이 겹쳤다. 좌석 확인",
        ["R-SUBJECT-CLEARED"] = null,
    };

    public static string Build(string rule, SessionInfo session, string grade, JsonObject? obs, string detail)
    {
        var ts = obs.Str("ts") ?? session.ExamStartsAt;
        var head = $"[{GradeLabel(grade)}] {SeatLabel(session)} · {FormatHm(ts, session.TzOffsetMinutes)}";
        var hint = Hints.TryGetValue(rule, out var h) ? h : null;
        return hint is null ? $"{head} {detail}" : $"{head} {detail} → {hint}";
    }

    /// <summary>engine.js 의 qual(). 근거의 성질을 괄호로 덧붙인다.</summary>
    public static string Qual(JsonObject o)
    {
        var q = new List<string>();
        var signed = o.Bool("signed");
        var notarized = o.Bool("notarized");
        var signer = o.Str("signer");
        if (signed == false) q.Add("미서명");
        else if (notarized == false) q.Add("미공증");
        else if (!string.IsNullOrEmpty(signer)) q.Add($"서명자 {signer}");

        switch (o.Str("source"))
        {
            case "kernel": q.Add("커널 기록"); break;
            case "selfverify": q.Add("자가검증"); break;
            case "userspace": q.Add("사용자 공간 열거"); break;
        }
        return q.Count > 0 ? $"({string.Join(", ", q)})" : "";
    }

    // ── DETAIL — summary.js 의 문자열과 한 글자도 달라선 안 된다.

    public static string Exec(JsonObject o, string q) => $"{o.Str("path")} 실행{q}";
    public static string StatusItem(JsonObject o, string q) => $"상태 영역 항목의 소유 프로세스가 허용목록 밖 — {o.Str("ownerPath")}{q}";
    public static string AgentProc(JsonObject o, string q) => $"창 없이 상주하는 프로세스 {o.Str("path")}{q}";
    public static string ExcludedWindow(JsonObject o, string q) => $"화면 캡처에서 제외된 창 — {o.Str("ownerPath")}{q}";
    public static string Caps(int n, long ms) => $"Caps Lock이 {ms}ms 간격으로 {n}회 전환 — 사람의 타이핑으로 보기 어려운 주기";
    public static string CaptureStack(JsonObject o, IEnumerable<string> mods) => $"화면 캡처 모듈 {string.Join(", ", mods)} 로드 — {o.Str("path")}";

    public static string Vm(JsonObject o)
    {
        var v = o.Str("vendor");
        var tail = string.IsNullOrEmpty(v) ? "" : $" ({v})";
        return $"가상머신 안에서 응시 중{tail} — 이 시험은 VM 응시를 금지한다";
    }

    public static string Remote(JsonObject o, string denyId) => $"원격제어 도구로 분류된 프로세스 실행 — {o.Str("path")} [{denyId}]";
    public static string Canary() => "시험망 밖 목적지에 연결됨 — 테더링·핫스팟으로 시험망을 우회한 상태";
    public static string BeaconMiss() => "시험망 비콘에 도달하지 못함 — 네트워크 확인 필요(조치 아님)";
    public static string Tcc(JsonObject o) => $"화면 기록 권한이 허용됨 — 대상 {o.Str("identity")}";

    public static string Hid(JsonObject o)
    {
        var who = o.Str("path") ?? $"pid {o.Int("pid")}";
        return $"키보드 HID 장치를 연 프로세스 — {who} ({o.Str("userClientClass")})";
    }

    public static string GuardFail(JsonObject o) =>
        o.Bool("windowAffinityOk") == false
            ? "시험 창의 캡처 제외 설정이 되돌려짐 — 누군가 보호를 껐다"
            : "시험 창 캡처 결과에 내용이 보임 — 캡처 차단이 무력화됐다";

    public static string AttestFail() => "하트비트 서명 검증 실패 — 등록된 기기 키로 서명되지 않았다";
    public static string LockdownExit(JsonObject o) => $"평가 모드({o.Str("mode")})에서 이탈 — 시험 시간 중 락다운이 풀렸다";

    public static string Integrity(JsonObject o) =>
        o.Bool("debuggerPresent") == true ? "에이전트에 디버거가 부착됨"
        : o.Bool("selfSignatureValid") == false ? "에이전트 자기 서명 검증 실패"
        : $"시계 편차 {o.Int("clockSkewMs")}ms";

    public static string LedgerBypass(JsonObject o) => $"화면에는 있으나 커널 실행 기록에 없는 프로세스 — {o.Str("ownerPath") ?? o.Str("path")}";
    public static string ScanEvasion(string? path) => $"커널 기록에는 살아 있으나 프로세스 목록에서 보이지 않음 — {path}";
    public static string Escalation(string label, List<string> rules) => $"{label} 에 정황 {rules.Count}건이 겹침 — {string.Join(", ", rules)}";
    public static string Cleared(string label) => $"{label} 이(가) 사라짐 — 상태 변화 기록";
}
