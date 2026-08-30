using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using OwlWatch.Core;

namespace OwlWatch.Collectors;

/// <summary>
/// S14 · 하드웨어 키 검증. macOS 의 Secure Enclave 에 대응하는 Windows 경로.
///
/// TPM 2.0 이 있으면 CNG "Microsoft Platform Crypto Provider" 로 ECDSA P-256 키를 만든다.
/// 개인키가 TPM 밖으로 나오지 않으므로, 하트비트 서명은 "이 기기에서 나왔다"를 증명한다 —
/// 세션 키를 복사해 다른 노트북에서 대신 하트비트를 쏘는 공격이 막힌다.
///
/// TPM 이 없는 구형 PC 는 소프트웨어 키로 폴백하고 attestation="sw" 로 보고한다.
/// 이때 이 서명은 기기를 증명하지 못한다 — 키 파일을 복사하면 그만이다. 그래서
/// 콘솔 UI 에 그대로 표기하고 등급을 낮춘다. 설계서 S14: "속이지 않는다".
/// </summary>
public sealed class Attestation : IDisposable
{
    private const string TpmProvider = "Microsoft Platform Crypto Provider";

    private readonly ECDsa _ecdsa;
    private readonly CngKey? _cngKey;
    private readonly string? _softKeyPath;

    public string Kind { get; }       // "hw" | "sw"
    public string Provider { get; }
    public string PublicKeyB64 { get; }

    private Attestation(ECDsa ecdsa, CngKey? cngKey, string kind, string provider, string? softKeyPath)
    {
        _ecdsa = ecdsa;
        _cngKey = cngKey;
        _softKeyPath = softKeyPath;
        Kind = kind;
        Provider = provider;
        PublicKeyB64 = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());
    }

    /// <param name="keyName">세션 단위 키 이름. 시험이 끝나면 지운다(설계서 09장 "상주하지 않는다").</param>
    /// <param name="workDir">소프트웨어 폴백 키를 둘 곳.</param>
    public static Attestation Create(string keyName, string workDir)
    {
        try
        {
            var provider = new CngProvider(TpmProvider);
            CngKey key;
            if (CngKey.Exists(keyName, provider))
            {
                key = CngKey.Open(keyName, provider);
            }
            else
            {
                key = CngKey.Create(CngAlgorithm.ECDsaP256, keyName, new CngKeyCreationParameters
                {
                    Provider = provider,
                    ExportPolicy = CngExportPolicies.None,  // 개인키는 TPM 밖으로 나가지 않는다
                    KeyUsage = CngKeyUsages.Signing,
                });
            }
            return new Attestation(new ECDsaCng(key), key, "hw", TpmProvider, null);
        }
        catch (Exception ex) when (ex is CryptographicException or PlatformNotSupportedException or NotSupportedException)
        {
            // TPM 없음 / 사용 불가. 폴백하되 등급으로 정직하게 말한다.
            return CreateSoftware(keyName, workDir);
        }
    }

    private static Attestation CreateSoftware(string keyName, string workDir)
    {
        Directory.CreateDirectory(workDir);
        var path = Path.Combine(workDir, $"{Sanitize(keyName)}.softkey");

        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        if (File.Exists(path))
        {
            try { ecdsa.ImportPkcs8PrivateKey(File.ReadAllBytes(path), out _); }
            catch { File.Delete(path); WritePkcs8(path, ecdsa); }
        }
        else
        {
            WritePkcs8(path, ecdsa);
        }

        return new Attestation(ecdsa, null, "sw", "software-fallback", path);
    }

    /// <summary>
    /// 평문 저장이다. 이 키는 기기를 증명하지 못한다는 전제 위에 있으므로 감추는 시늉을
    /// 하지 않는다 — 복사되면 끝인 키를 "보호된 것처럼" 보이게 하는 쪽이 더 위험하다.
    /// 시험 종료 시 Dispose 에서 지운다.
    /// </summary>
    private static void WritePkcs8(string path, ECDsa ecdsa) =>
        File.WriteAllBytes(path, ecdsa.ExportPkcs8PrivateKey());

    private static string Sanitize(string s) =>
        string.Concat(s.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_'));

    /// <summary>정규화 JSON 바이트에 서명한다. base64(ECDSA-P256-SHA256).</summary>
    public string Sign(string canonicalPayload) =>
        Convert.ToBase64String(_ecdsa.SignData(Encoding.UTF8.GetBytes(canonicalPayload), HashAlgorithmName.SHA256));

    public JsonObject Observation(DateTimeOffset now, bool verified) => new()
    {
        ["kind"] = "attestation",
        ["source"] = "selfverify",
        ["signal"] = "S14",
        ["collector"] = Kind == "hw" ? "tpm-cng" : "software-fallback",
        ["platform"] = "windows",
        ["ts"] = Redaction.IsoSec(now),
        ["attestationKind"] = Kind,
        ["provider"] = Provider,
        ["verified"] = verified,
    };

    /// <summary>시험이 끝나면 키를 없앤다. 학기 단위 보관 여부는 설계서 14장 미결 7번.</summary>
    public void Dispose()
    {
        try { _cngKey?.Delete(); } catch { /* 이미 없음 */ }
        _cngKey?.Dispose();
        _ecdsa.Dispose();
        if (_softKeyPath is not null && File.Exists(_softKeyPath))
        {
            try { File.Delete(_softKeyPath); } catch { /* 다음 실행에서 덮어쓴다 */ }
        }
    }
}
