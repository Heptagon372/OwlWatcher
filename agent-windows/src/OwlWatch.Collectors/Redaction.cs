using System.Security.Cryptography;

namespace OwlWatch.Collectors;

/// <summary>
/// 저장 전 축약. 설계서 10장 "실행 파일 경로(홈은 ~로 치환)".
///
/// 여기를 지나지 않은 경로는 이벤트에 실리지 않는다. 사용자 이름이 그대로 남는
/// C:\Users\hongildong\... 같은 경로가 리포트와 학사위원회 문서에 흘러가는 것을 막는다.
/// </summary>
public static class Redaction
{
    private static readonly string Home =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).Replace('\\', '/');

    /// <summary>홈 아래면 ~ 로, 경로 구분자는 / 로. 대소문자는 보존한다(표시용).</summary>
    public static string Path(string? raw)
    {
        if (string.IsNullOrEmpty(raw)) return "";
        var p = raw.Replace('\\', '/');
        if (!string.IsNullOrEmpty(Home) && p.StartsWith(Home, StringComparison.OrdinalIgnoreCase))
            return "~" + p[Home.Length..];
        return p;
    }

    /// <summary>실제 파일 접근용 — 축약된 경로를 되돌린다.</summary>
    public static string Expand(string redacted) =>
        redacted.StartsWith('~') ? Home + redacted[1..] : redacted;

    private sealed record HashEntry(long Length, DateTime Written, string Sha256);

    private static readonly Dictionary<string, HashEntry> HashCache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>200MB 를 넘는 파일은 해시하지 않는다 — 30초 점검 예산 안에 못 들어온다.</summary>
    private const long MaxHashBytes = 200L * 1024 * 1024;

    public static string? Sha256OfFile(string fullPath)
    {
        try
        {
            var fi = new FileInfo(fullPath);
            if (!fi.Exists || fi.Length > MaxHashBytes) return null;

            lock (HashCache)
            {
                if (HashCache.TryGetValue(fullPath, out var c) && c.Length == fi.Length && c.Written == fi.LastWriteTimeUtc)
                    return c.Sha256;
            }

            using var fs = File.OpenRead(fullPath);
            var hex = Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();

            lock (HashCache) { HashCache[fullPath] = new HashEntry(fi.Length, fi.LastWriteTimeUtc, hex); }
            return hex;
        }
        catch
        {
            return null; // 접근 거부·잠김. degraded 로 표기된다.
        }
    }

    public static string Iso(DateTimeOffset t) => t.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
    public static string IsoSec(DateTimeOffset t) => t.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ");
}
