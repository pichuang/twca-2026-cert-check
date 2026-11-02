$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../check-twca-cert.ps1')

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-Rejected {
    param([scriptblock]$Action)
    $wasRejected = $false
    try { & $Action | Out-Null } catch { $wasRejected = $true }
    Assert-True $wasRejected '未拒絕無效輸入。'
}

foreach ($accepted in @('https://www.twca.com.tw/', 'example.com:00443', 'xn--fiqs8s.example', 'a.example')) {
    $endpoint = ConvertTo-TwcaTarget $accepted
    Assert-True ($endpoint.Port -eq 443) '連接埠解析錯誤。'
}
foreach ($rejected in @('http://example.com', 'https://user@example.com', 'https://', '-evil.example',
    'example..com', 'example.com:0', 'example.com:65536', 'example.com:443:443', '127.0.0.1',
    'https://[::1]/', 'https://example.com/a b', 'example.com.', 'example.com/', "https://example.com/`n")) {
    Assert-Rejected { ConvertTo-TwcaTarget $rejected }
}
foreach ($case in @(
    @($true, $false, $true, $true, 'REPLACE_RECOMMENDED', 1),
    @($true, $true, $true, $false, 'REPLACE_RECOMMENDED', 2),
    @($false, $false, $true, $true, 'REVIEW_REQUIRED', 1),
    @($false, $false, $true, $false, 'REVIEW_REQUIRED', 2),
    @($false, $false, $false, $true, 'NOT_MATCHED', 0),
    @($false, $false, $false, $false, 'INDETERMINATE', 2))) {
    $risk = Get-TwcaRisk $case[0] $case[1] $case[2] $case[3]
    Assert-True ($risk.Status -eq $case[4] -and $risk.ExitCode -eq $case[5]) '分類或退出碼錯誤。'
}
'PASS：目標解析、事件分類與退出碼。'

if (-not $IsWindows) {
    function Assert-TwcaRuntime { }
    function Invoke-TwcaCertutil {
        param([string[]]$Arguments, [int]$TimeoutSeconds)
        if ($Arguments[0] -eq '-hashfile' -and $Arguments[2] -eq 'SHA256') {
            $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($Arguments[1])))
            return "SHA256 mock`r`n$hash`r`n成功。"
        }
        if ($Arguments[0] -eq '-dump') { return 'certutil -dump 測試替身' }
        throw '非預期的 certutil 呼叫。'
    }
    '注意：非 Windows 環境，僅 certutil 與平台檢查使用測試替身；TLS 握手與政策驗證使用真實 .NET。'
}

Initialize-TwcaTls
Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
public sealed class TwcaTestServer : IDisposable {
    private TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
    private CancellationTokenSource cancel = new CancellationTokenSource();
    private Task loop;
    private SslStreamCertificateContext context;
    public int Port { get { return ((IPEndPoint)listener.LocalEndpoint).Port; } }
    public TwcaTestServer(X509Certificate2 leaf, X509Certificate2 intermediate) {
        var chain = new X509Certificate2Collection();
        if (intermediate != null) chain.Add(intermediate);
        context = SslStreamCertificateContext.Create(leaf, chain, true);
        listener.Start();
        loop = LoopAsync();
    }
    private async Task LoopAsync() {
        while (!cancel.IsCancellationRequested) {
            try {
                using (var client = await listener.AcceptTcpClientAsync(cancel.Token))
                using (var stream = new SslStream(client.GetStream(), false)) {
                    await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions {
                        ServerCertificateContext = context
                    }, cancel.Token);
                }
            } catch (Exception) { if (cancel.IsCancellationRequested) break; }
        }
    }
    public void Dispose() {
        cancel.Cancel(); listener.Stop(); loop.GetAwaiter().GetResult(); cancel.Dispose();
    }
}
'@

function New-TestRequest {
    param([string]$Name, [bool]$IsCa, [string]$DnsName = '', [string]$Purpose = '1.3.6.1.5.5.7.3.1')
    $key = [Security.Cryptography.RSA]::Create(2048)
    $script:keys.Add($key)
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=$Name", $key, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($IsCa, $false, 0, $true))
    if ($IsCa) {
        $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign, $true))
    } else {
        $san = [Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        $san.AddDnsName($DnsName)
        $request.CertificateExtensions.Add($san.Build())
        $purposes = [Security.Cryptography.OidCollection]::new()
        [void]$purposes.Add([Security.Cryptography.Oid]::new($Purpose))
        $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($purposes, $true))
    }
    [pscustomobject]@{ Request = $request; Key = $key }
}

function New-TestIssued {
    param($Request, $Issuer, [byte]$Serial, [DateTimeOffset]$Before, [DateTimeOffset]$After)
    $publicCertificate = $Request.Request.Create($Issuer, $Before, $After, [byte[]]@($Serial))
    try { return [Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($publicCertificate, $Request.Key) }
    finally { $publicCertificate.Dispose() }
}

$testDirectory = Join-Path ([IO.Path]::GetTempPath()) ('twca-tests.' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($testDirectory)
$keys = [Collections.Generic.List[Security.Cryptography.RSA]]::new()
$ownedCertificates = [Collections.Generic.List[Security.Cryptography.X509Certificates.X509Certificate2]]::new()
$servers = [Collections.Generic.List[TwcaTestServer]]::new()
$existingWorkDirectories = @(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Directory -Filter 'twca-check.*' | Select-Object -ExpandProperty FullName)
try {
    $now = [DateTimeOffset]::UtcNow
    $rootRequest = New-TestRequest 'Test Root' $true
    $root = $rootRequest.Request.CreateSelfSigned($now.AddDays(-5), $now.AddDays(5))
    $ownedCertificates.Add($root)
    $caRequest = New-TestRequest 'TWCA Test Intermediate' $true
    $ca = New-TestIssued $caRequest $root 2 $now.AddDays(-4) $now.AddDays(4)
    $ownedCertificates.Add($ca)
    $rootPath = Join-Path $testDirectory 'root.pem'
    [IO.File]::WriteAllText($rootPath, $root.ExportCertificatePem())
    $caPath = Join-Path $testDirectory 'ca.pem'
    [IO.File]::WriteAllText($caPath, $ca.ExportCertificatePem())
    Assert-Rejected { New-TwcaChainPolicy $caPath }
    $caHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($ca.RawData)).ToLowerInvariant()
    $dataPath = Join-Path $testDirectory 'data.tsv'
    $options = @{ Timeout = 5; DataFile = $dataPath; CaFile = $rootPath; Detailed = $true; ResultExit = 2 }
    $dataLine = "$caHash`tTest CA`tresearch_candidate`thttps://example.com/source`t2026-11-02T00:00:00Z"
    [IO.File]::WriteAllText($dataPath, $dataLine + "`n")
    Assert-True ((Read-TwcaData $dataPath).Count -eq 1) '資料讀取錯誤。'
    foreach ($invalid in @('', ($dataLine + "`n" + $dataLine), $dataLine.Replace($caHash, 'bad'),
        $dataLine.Replace('research_candidate', 'unknown'), $dataLine.Replace('2026-11-02T00:00:00Z', 'unknown'), ($dataLine + "`textra"))) {
        [IO.File]::WriteAllText($dataPath, $invalid)
        Assert-Rejected { Read-TwcaData $dataPath }
    }
    [IO.File]::WriteAllText($dataPath, $dataLine + "`n")
    'PASS：嚴格 TSV 與自訂信任根檢查。'

    foreach ($variant in @('valid', 'hostname', 'purpose', 'expired', 'non-twca')) {
        $dnsName = if ($variant -eq 'hostname') { 'wrong.example' } else { 'localhost' }
        $purpose = if ($variant -eq 'purpose') { '1.3.6.1.5.5.7.3.2' } else { '1.3.6.1.5.5.7.3.1' }
        $leafRequest = New-TestRequest 'localhost' $false $dnsName $purpose
        $issuer = if ($variant -eq 'non-twca') { $root } else { $ca }
        $after = if ($variant -eq 'expired') { $now.AddDays(-1) } else { $now.AddDays(1) }
        $leaf = New-TestIssued $leafRequest $issuer 3 $now.AddDays(-2) $after
        $ownedCertificates.Add($leaf)
        $intermediate = if ($variant -eq 'non-twca') { $null } else { $ca }
        $server = [TwcaTestServer]::new($leaf, $intermediate)
        $servers.Add($server)
        $site = "localhost:$($server.Port)"
        $report = @(Test-TwcaSite $site $options) -join "`n"
        $expectedExit = if ($variant -eq 'valid') { 1 } elseif ($variant -eq 'non-twca') { 0 } else { 2 }
        Assert-True ($options.ResultExit -eq $expectedExit) "本地 TLS $variant 退出碼錯誤：$report"
        $expectedStatus = if ($variant -eq 'non-twca') { 'NOT_MATCHED' } else { 'REPLACE_RECOMMENDED' }
        Assert-True ($report.Contains("事件判定：$expectedStatus")) "本地 TLS $variant 判定錯誤：$report"
        Assert-True ($report.Contains('SHA-256=') -and $report.Contains('撤銷狀態：未檢查')) '詳細輸出不完整。'
        if ($variant -eq 'valid') { $validSite = $site }
    }
    'PASS：真實 TLS、指紋命中、非 TWCA、錯誤主機名、用途與過期憑證。'

    foreach ($category in @('article_observation', 'official_confirmed')) {
        [IO.File]::WriteAllText($dataPath, $dataLine.Replace('research_candidate', $category))
        $report = @(Test-TwcaSite $validSite $options) -join "`n"
        $expected = if ($category -eq 'article_observation') { 'REVIEW_REQUIRED' } else { 'REPLACE_RECOMMENDED' }
        Assert-True ($options.ResultExit -eq 1 -and $report.Contains("事件判定：$expected")) "證據類別錯誤：$report"
    }
    [IO.File]::WriteAllText($dataPath, $dataLine.Replace($caHash, ('0' * 64)))
    $report = @(Test-TwcaSite $validSite $options) -join "`n"
    Assert-True ($options.ResultExit -eq 1 -and $report.Contains('REVIEW_REQUIRED')) '同名不同指紋不應宣告未命中。'
    [IO.File]::WriteAllText($dataPath, $dataLine)
    $options.CaFile = ''
    $report = @(Test-TwcaSite $validSite $options) -join "`n"
    Assert-True ($options.ResultExit -eq 2) '缺少信任根未失敗。'
    $options.CaFile = $rootPath
    $options.Detailed = $false
    $report = @(Test-TwcaSite $validSite $options)
    Assert-True ($report.Count -eq 3) '預設報告應為三行。'

    $listPath = Join-Path $testDirectory 'url.list'
    [IO.File]::WriteAllText($listPath, "# sites`r`n`r`n  $validSite  `r`n$validSite")
    $mainArgs = @('-f', $listPath, '--ca-file', $rootPath, '--data-file', $dataPath)
    $batch = @(Invoke-TwcaMain $mainArgs)
    Assert-True ($batch[-1] -eq 1 -and $batch.Count -eq 8) "批次精簡輸出或退出碼錯誤：$batch"
    [IO.File]::WriteAllText($listPath, "--help`nhttp://localhost/`n$validSite")
    $batch = @(Invoke-TwcaMain $mainArgs)
    Assert-True ($batch[-1] -eq 2 -and ($batch -join "`n").Contains('換證結論：❌ 要。')) '批次未隔離選項或錯誤後未繼續。'
    foreach ($invalidArgs in @(@('--unknown'), @('--timeout'), @('--timeout', '0'), @('--timeout', '301'),
        @('--ca-file'), @('--data-file'), @('--file'), @('-f', $listPath, 'localhost'))) {
        $result = @(Invoke-TwcaMain $invalidArgs)
        Assert-True ($result[-1] -eq 2) 'CLI 無效選項未回傳 2。'
    }
    [IO.File]::WriteAllText($listPath, "# empty`n `t`r`n")
    $result = @(Invoke-TwcaMain $mainArgs)
    Assert-True ($result[-1] -eq 2) '空白清單未失敗。'
    'PASS：證據類別、同名不同指紋、缺根、CLI 選項與批次 CRLF／末行／錯誤後繼續。'

    $blocked = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $blocked.Start()
    try {
        $options.Timeout = 1
        $options.Detailed = $true
        $report = @(Test-TwcaSite "localhost:$($blocked.LocalEndpoint.Port)" $options) -join "`n"
        Assert-True ($options.ResultExit -eq 2 -and $report.Contains('timed out')) "TLS 逾時控制錯誤：$report"
    } finally { $blocked.Stop() }
    $leakedDirectories = @(Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Directory -Filter 'twca-check.*' |
        Where-Object { $_.FullName -notin $existingWorkDirectories })
    Assert-True ($leakedDirectories.Count -eq 0) '暫存憑證目錄未清理。'
    'PASS：TLS 逾時。'
    '全部測試通過。'
} finally {
    foreach ($server in $servers) { $server.Dispose() }
    foreach ($certificate in $ownedCertificates) { $certificate.Dispose() }
    foreach ($key in $keys) { $key.Dispose() }
    [IO.Directory]::Delete($testDirectory, $true)
}