using System.Security.Cryptography;
using System.Text;

namespace OwlWatch.Runtime;

/// <summary>
/// 60초 코드. 설계서 08장(좌석 칩에 60초 코드 표시) · 09장(ARMED 진입은 학생 화면의
/// 코드가 콘솔과 일치함을 감독관이 확인했을 때만).
///
/// 코드는 세션 비밀과 이벤트 체인 헤드에 묶인다. 그래서 두 가지를 동시에 말한다 —
/// "이 화면은 이 세션의 것이다"와 "이 좌석의 이벤트 기록이 콘솔이 아는 것과 같다".
/// 체인이 다르면(이벤트가 빠졌거나 조작됐으면) 코드가 어긋난다.
///
/// 이건 인증이 아니다. 감독관 육안 대조용 표식이고, 세션 비밀을 아는 사람은 만들 수 있다.
/// </summary>
public static class SessionCode
{
    public const int PeriodSeconds = 60;

    public static string Derive(string sessionSecret, string chainHead, DateTimeOffset at)
    {
        var bucket = at.ToUnixTimeSeconds() / PeriodSeconds;
        var material = $"{sessionSecret}|{chainHead}|{bucket}";
        var h = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        var n = ((uint)h[0] << 24 | (uint)h[1] << 16 | (uint)h[2] << 8 | h[3]) & 0x7FFFFFFF;
        return (n % 1_000_000).ToString("D6");
    }

    /// <summary>시계가 조금 어긋나도 통과시킨다. 앞뒤 한 구간까지.</summary>
    public static bool Matches(string sessionSecret, string chainHead, DateTimeOffset at, string candidate)
    {
        for (var d = -1; d <= 1; d++)
            if (Derive(sessionSecret, chainHead, at.AddSeconds(d * PeriodSeconds)) == candidate) return true;
        return false;
    }

    public static int SecondsRemaining(DateTimeOffset at) =>
        PeriodSeconds - (int)(at.ToUnixTimeSeconds() % PeriodSeconds);
}
