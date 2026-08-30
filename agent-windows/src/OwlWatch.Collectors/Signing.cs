using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace OwlWatch.Collectors;

/// <summary>
/// Authenticode 서명 확인. 허용목록의 키는 이름이 아니라 인증서 주체다(설계서 P2 원칙) —
/// macOS 의 Team ID 에 대응한다.
///
/// 두 경로를 본다.
///   1) 임베디드 서명 — 대부분의 서드파티 앱
///   2) 카탈로그(.cat) 서명 — Windows 시스템 바이너리 대부분
/// 2를 빼먹으면 conhost.exe · ctfmon.exe · sihost.exe 가 전부 미서명으로 나와
/// 좌석마다 수십 건의 오탐이 된다. 실기기에서 바로 드러난 문제라 여기 남겨 둔다.
/// </summary>
public static class Signing
{
    public readonly record struct Info(bool Signed, string? Signer, bool Verified, bool FromCatalog);

    private static readonly Dictionary<string, Info> Cache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<string, string?> CatalogSignerCache = new(StringComparer.OrdinalIgnoreCase);

    public static Info Of(string path)
    {
        if (string.IsNullOrEmpty(path)) return new Info(false, null, false, false);
        lock (Cache) { if (Cache.TryGetValue(path, out var hit)) return hit; }

        var info = Compute(path);
        lock (Cache) { Cache[path] = info; }
        return info;
    }

    private static Info Compute(string path)
    {
        // 1) 임베디드 서명
        try
        {
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            var subject = ExtractCn(cert.Subject);
            return new Info(true, subject, VerifyEmbedded(path), false);
        }
        catch
        {
            // 임베디드 서명이 없다. 카탈로그를 본다.
        }

        // 2) 카탈로그 서명
        try
        {
            var cat = FindCatalog(path);
            if (cat is not null)
            {
                var signer = CatalogSigner(cat);
                return new Info(true, signer, true, true);
            }
        }
        catch
        {
            // 카탈로그 조회 실패는 미서명과 같이 취급한다. 없는 사실을 지어내지 않는다.
        }

        return new Info(false, null, false, false);
    }

    /// <summary>주체 DN 에서 CN 값만. 예: CN="Microsoft Windows", O=... → Microsoft Windows</summary>
    internal static string? ExtractCn(string subject)
    {
        foreach (var raw in SplitDn(subject))
        {
            var part = raw.Trim();
            if (!part.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)) continue;
            var v = part[3..].Trim();
            if (v.Length >= 2 && v[0] == '"' && v[^1] == '"') v = v[1..^1].Replace("\"\"", "\"");
            return v;
        }
        return null;
    }

    private static IEnumerable<string> SplitDn(string dn)
    {
        var start = 0;
        var inQuotes = false;
        for (var i = 0; i < dn.Length; i++)
        {
            if (dn[i] == '"') inQuotes = !inQuotes;
            else if (dn[i] == ',' && !inQuotes) { yield return dn[start..i]; start = i + 1; }
        }
        if (start < dn.Length) yield return dn[start..];
    }

    /// <summary>
    /// 임베디드 서명의 체인 검증. 인증서를 읽을 수 있다는 것과 서명이 유효하다는 것은 다르다 —
    /// 만료·변조된 서명을 허용목록에 태우면 "정상 서명을 단 위장"이 그대로 통과한다.
    /// </summary>
    private static bool VerifyEmbedded(string path)
    {
        var fileInfo = new Native.WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<Native.WINTRUST_FILE_INFO>(),
            pcwszFilePath = path,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };

        var pFile = Marshal.AllocHGlobal(Marshal.SizeOf<Native.WINTRUST_FILE_INFO>());
        var pData = IntPtr.Zero;
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            var data = new Native.WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<Native.WINTRUST_DATA>(),
                dwUIChoice = Native.WTD_UI_NONE,
                // 시험장 망은 기본 거부다. 폐기 조회로 30초 예산을 태울 수 없다.
                fdwRevocationChecks = Native.WTD_REVOKE_NONE,
                dwUnionChoice = Native.WTD_CHOICE_FILE,
                pFile = pFile,
                dwStateAction = Native.WTD_STATEACTION_VERIFY,
                dwProvFlags = Native.WTD_SAFER_FLAG,
            };
            pData = Marshal.AllocHGlobal(Marshal.SizeOf<Native.WINTRUST_DATA>());
            Marshal.StructureToPtr(data, pData, false);

            var result = Native.WinVerifyTrust(IntPtr.Zero, Native.WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

            var close = Marshal.PtrToStructure<Native.WINTRUST_DATA>(pData);
            close.dwStateAction = Native.WTD_STATEACTION_CLOSE;
            Marshal.StructureToPtr(close, pData, false);
            Native.WinVerifyTrust(IntPtr.Zero, Native.WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

            return result == 0;
        }
        catch { return false; }
        finally
        {
            if (pData != IntPtr.Zero) Marshal.FreeHGlobal(pData);
            Marshal.FreeHGlobal(pFile);
        }
    }

    /// <summary>파일 해시로 이 파일을 담고 있는 .cat 을 찾는다. 없으면 null.</summary>
    private static string? FindCatalog(string path)
    {
        var hFile = NativeCatalog.CreateFile(path, NativeCatalog.GENERIC_READ,
            NativeCatalog.FILE_SHARE_READ | NativeCatalog.FILE_SHARE_WRITE | NativeCatalog.FILE_SHARE_DELETE,
            IntPtr.Zero, NativeCatalog.OPEN_EXISTING, 0, IntPtr.Zero);
        if (hFile == NativeCatalog.INVALID_HANDLE_VALUE) return null;

        var hCatAdmin = IntPtr.Zero;
        var hCatInfo = IntPtr.Zero;
        try
        {
            var useV2 = NativeCatalog.CryptCATAdminAcquireContext2(
                out hCatAdmin, NativeCatalog.DriverActionVerify, "SHA256", IntPtr.Zero, 0);
            if (!useV2 && !NativeCatalog.CryptCATAdminAcquireContext(
                    out hCatAdmin, NativeCatalog.DriverActionVerify, 0))
                return null;

            uint cbHash = 0;
            if (useV2) NativeCatalog.CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref cbHash, null, 0);
            else NativeCatalog.CryptCATAdminCalcHashFromFileHandle(hFile, ref cbHash, null, 0);
            if (cbHash == 0) return null;

            var hash = new byte[cbHash];
            var ok = useV2
                ? NativeCatalog.CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref cbHash, hash, 0)
                : NativeCatalog.CryptCATAdminCalcHashFromFileHandle(hFile, ref cbHash, hash, 0);
            if (!ok) return null;

            hCatInfo = NativeCatalog.CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, cbHash, 0, IntPtr.Zero);
            if (hCatInfo == IntPtr.Zero) return null;

            var info = new NativeCatalog.CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<NativeCatalog.CATALOG_INFO>(),
                wszCatalogFile = "",
            };
            if (!NativeCatalog.CryptCATCatalogInfoFromContext(hCatInfo, ref info, 0)) return null;

            var file = info.wszCatalogFile;
            // 접두사 \\?\ 가 붙어 나오는 경우가 있다.
            if (file.StartsWith(@"\\?\", StringComparison.Ordinal)) file = file[4..];
            return string.IsNullOrEmpty(file) ? null : file;
        }
        catch { return null; }
        finally
        {
            if (hCatInfo != IntPtr.Zero && hCatAdmin != IntPtr.Zero)
                NativeCatalog.CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            if (hCatAdmin != IntPtr.Zero) NativeCatalog.CryptCATAdminReleaseContext(hCatAdmin, 0);
            Native.CloseHandle(hFile);
        }
    }

    /// <summary>카탈로그 파일 자체의 서명자. 시스템 바이너리는 여기서 "Microsoft Windows" 가 나온다.</summary>
    private static string? CatalogSigner(string catalogPath)
    {
        lock (CatalogSignerCache)
        {
            if (CatalogSignerCache.TryGetValue(catalogPath, out var hit)) return hit;
        }

        string? signer = null;
        try
        {
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(catalogPath));
            signer = ExtractCn(cert.Subject);
        }
        catch { /* 카탈로그를 읽을 수 없다 */ }

        lock (CatalogSignerCache) { CatalogSignerCache[catalogPath] = signer; }
        return signer;
    }
}
