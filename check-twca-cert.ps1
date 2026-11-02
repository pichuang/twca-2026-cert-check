function Show-TwcaUsage {
    '用法：pwsh -File check-twca-cert.ps1 [選項] HTTPS_URL或網域'
    '批次：pwsh -File check-twca-cert.ps1 [選項] --file FILE（或 -f FILE）'
    '選項：--file/-f FILE、--ca-file FILE、--timeout SECONDS、--data-file FILE、--verbose、--help'
    '預設只顯示換證結論；--verbose 顯示完整憑證與診斷。'
    '相依工具：Windows、PowerShell 7.4 以上、Windows certutil.exe；不需要 OpenSSL。'
}

function ConvertTo-TwcaTarget {
    param([string]$Target)
    if ($Target -match '[\s\p{Cc}]') { throw '輸入不可包含空白或控制字元。' }
    $authority = $Target
    if ($Target.StartsWith('https://', [StringComparison]::Ordinal)) {
        $authority = ($Target.Substring(8) -split '[/?#]', 2)[0]
    } elseif ($Target -match '://|[/?#]') {
        throw '僅接受 HTTPS URL 或 DNS 網域（可含連接埠）。'
    }
    if (-not $authority -or $authority -match '[@\[\]]') { throw '不支援空主機、帳密或 IP literal。' }
    $dnsName = $authority
    $port = 443
    if ($authority.Contains(':')) {
        $separator = $authority.LastIndexOf(':')
        $dnsName = $authority.Substring(0, $separator)
        $portText = $authority.Substring($separator + 1)
        if ($portText -cnotmatch '^[0-9]{1,5}$') { throw '連接埠必須是 1 到 65535。' }
        $port = [int]$portText
    }
    if ($port -lt 1 -or $port -gt 65535) { throw '連接埠必須是 1 到 65535。' }
    if ($dnsName.Length -gt 253 -or $dnsName -cnotmatch '^[A-Za-z0-9.-]+$') {
        throw '主機必須是 ASCII DNS 網域；國際化網域請使用 punycode。'
    }
    if ($dnsName -match '^[0-9.]+$') { throw '不支援 IP literal。' }
    foreach ($label in $dnsName.Split('.')) {
        if ($label.Length -lt 1 -or $label.Length -gt 63 -or
            $label -cnotmatch '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$') { throw 'DNS 標籤格式不合法。' }
    }
    [pscustomobject]@{ DnsName = $dnsName; Port = $port }
}

function Read-TwcaData {
    param([string]$Path)
    $records = @{}
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        if ($line.StartsWith('#')) { continue }
        $fields = $line.Split("`t")
        if ($fields.Count -ne 5 -or $fields[0] -cnotmatch '^[0-9a-fA-F]{64}$' -or
            -not $fields[1] -or $fields[1] -match '\p{Cc}' -or
            $fields[2] -cnotmatch '^(research_candidate|article_observation|official_confirmed)$' -or
            $fields[3] -cnotmatch '^https://[^\s]+$' -or
            $fields[4] -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$') {
            throw '中繼資料格式錯誤、指紋重複或清單為空。'
        }
        $fingerprint = $fields[0].ToLowerInvariant()
        if ($records.ContainsKey($fingerprint)) { throw '中繼資料格式錯誤、指紋重複或清單為空。' }
        $records[$fingerprint] = [pscustomobject]@{
            Fingerprint = $fingerprint; Name = $fields[1]; Category = $fields[2]
            Source = $fields[3]; CheckedAt = $fields[4]; Line = $fingerprint + "`t" + ($fields[1..4] -join "`t")
        }
    }
    if (-not $records.Count) { throw '中繼資料格式錯誤、指紋重複或清單為空。' }
    return $records
}

function Initialize-TwcaTls {
    if ('TwcaTlsProbe' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

public sealed class TwcaTlsProbe {
    public List<byte[]> Certificates = new List<byte[]>();
    public List<string> Diagnostics = new List<string>();
    public SslPolicyErrors PolicyErrors = SslPolicyErrors.RemoteCertificateNotAvailable;
    public bool HandshakeCompleted;
    public string PeerAddress = "";
    public string Error = "";

    public static TwcaTlsProbe Check(string hostname, int port, int seconds, X509ChainPolicy policy) {
        return CheckAsync(hostname, port, seconds, policy).GetAwaiter().GetResult();
    }

    private static async Task<TwcaTlsProbe> CheckAsync(string hostname, int port, int seconds, X509ChainPolicy policy) {
        var result = new TwcaTlsProbe();
        using (var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(seconds)))
        using (var client = new TcpClient()) {
            try {
                await client.ConnectAsync(hostname, port, cancel.Token);
                result.PeerAddress = client.Client.RemoteEndPoint.ToString();
                using (var stream = new SslStream(client.GetStream(), false)) {
                    var options = new SslClientAuthenticationOptions {
                        TargetHost = hostname,
                        CertificateChainPolicy = policy,
                        AllowTlsResume = false,
                        RemoteCertificateValidationCallback = (sender, certificate, chain, errors) => {
                            result.PolicyErrors = errors;
                            if (certificate != null) result.Certificates.Add(certificate.GetRawCertData());
                            if (chain != null) {
                                for (int index = 1; index < chain.ChainElements.Count; index++)
                                    result.Certificates.Add(chain.ChainElements[index].Certificate.RawData);
                                foreach (var status in chain.ChainStatus)
                                    result.Diagnostics.Add(status.Status + ": " + status.StatusInformation.Trim());
                            }
                            return true;
                        }
                    };
                    await stream.AuthenticateAsClientAsync(options, cancel.Token);
                    result.HandshakeCompleted = true;
                }
            } catch (OperationCanceledException) {
                result.Error = "TLS connection timed out.";
            } catch (Exception error) {
                result.Error = error.Message;
            }
        }
        return result;
    }
}
'@
}

function New-TwcaChainPolicy {
    param([string]$CaFile)
    $policy = [Security.Cryptography.X509Certificates.X509ChainPolicy]::new()
    $policy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $policy.DisableCertificateDownloads = $true
    $policy.VerificationFlags = [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
    [void]$policy.ApplicationPolicy.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1'))
    if ($CaFile) {
        $certificates = [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $certificates.ImportFromPemFile($CaFile)
        if (-not $certificates.Count) { throw '指定 CA 檔案沒有可解析的 PEM 憑證。' }
        try {
            foreach ($certificate in $certificates) {
                if (($certificate.SubjectName.RawData -join ',') -cne ($certificate.IssuerName.RawData -join ',')) {
                    throw '自訂 CA 檔案只接受自簽信任根，不可只提供中繼憑證。'
                }
            }
            $policy.TrustMode = [Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
            $policy.CustomTrustStore.AddRange($certificates)
        } catch {
            foreach ($certificate in $certificates) { $certificate.Dispose() }
            throw
        }
    }
    return $policy
}

function Invoke-TwcaCertutil {
    param([string[]]$Arguments, [int]$TimeoutSeconds)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $env:SystemRoot 'System32/certutil.exe'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $started = $false
    try {
        [void]$process.Start()
        $started = $true
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw 'certutil 執行逾時。'
        }
        $output = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw "certutil 執行失敗：$output" }
        return $output
    } finally {
        if ($started -and -not $process.HasExited) { $process.Kill($true); $process.WaitForExit() }
        $process.Dispose()
    }
}

function Get-TwcaRisk {
    param([bool]$Recommended, [bool]$Official, [bool]$HasTwca, [bool]$TlsPassed)
    $status = 'INDETERMINATE'
    $label = '無法判定'
    if ($Recommended) {
        $status = 'REPLACE_RECOMMENDED'; $label = '建議更換並確認'
        if ($Official) { $label = '需更換（命中所提供的官方確認資料）' }
    } elseif ($HasTwca) {
        $status = 'REVIEW_REQUIRED'; $label = '需人工確認，不能據此宣告已換新鏈'
    } elseif ($TlsPassed) {
        $status = 'NOT_MATCHED'; $label = '本事件未命中（僅限此次端點與資料版本）'
    }
    $exitCode = 2
    if ($TlsPassed) { $exitCode = 1; if ($status -eq 'NOT_MATCHED') { $exitCode = 0 } }
    [pscustomobject]@{ Status = $status; Label = $label; ExitCode = $exitCode; Official = $Official }
}

function Show-TwcaDecision {
    param($Risk)
    switch ($Risk.Status) {
        'REPLACE_RECOMMENDED' {
            '換證結論：❌ 要。請在 2026-11-06 00:00 前完成換證（保守維運期限，+08:00）。'
            if ($Risk.Official) { '原因：命中所提供的官方確認中繼資料。請更換終端憑證及完整中繼鏈。' }
            else { '原因：命中 TWCA 問題中繼候選清單，建議換證。' }
        }
        'NOT_MATCHED' {
            '換證結論：✅ 不需要因本次 TWCA 事件在 2026-11-06 前換證。'
            '原因：此次端點未見 TWCA 憑證鏈，且 TLS 驗證通過。'
        }
        'REVIEW_REQUIRED' {
            '換證結論：無法確定。請在 2026-11-06 前向 TWCA 確認；未確認前按需換證處理。'
            '原因：使用 TWCA 憑證，但目前證據不足以確認已完成換證。'
        }
        default {
            '換證結論：無法判定。請在 2026-11-06 前完成確認。'
            '原因：TLS 驗證失敗，不能判定為不需換證。'
        }
    }
}

function Show-TwcaFailure {
    param([string]$Message, [bool]$Detailed)
    '換證結論：無法判定。請在 2026-11-06 前完成確認。'
    "錯誤：$Message"
    if ($Detailed) { '事件判定：INDETERMINATE（無法判定）'; 'TLS：未完成或失敗'; '撤銷狀態：未檢查' }
}

function Assert-TwcaRuntime {
    if (-not $IsWindows -or $PSVersionTable.PSVersion -lt [version]'7.4') {
        throw '需要 Windows 與 PowerShell 7.4 以上；Windows PowerShell 5.1 不支援。'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32/certutil.exe') -PathType Leaf)) {
        throw '找不到 Windows certutil.exe。'
    }
}

function Test-TwcaSite {
    param([string]$Target, [hashtable]$Options)
    $workDirectory = ''
    $policy = $null
    try {
        $endpoint = ConvertTo-TwcaTarget $Target
        Assert-TwcaRuntime
        $data = Read-TwcaData $Options.DataFile
        $policy = New-TwcaChainPolicy $Options.CaFile
        Initialize-TwcaTls
        $checkedAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $probe = [TwcaTlsProbe]::Check($endpoint.DnsName, $endpoint.Port, $Options.Timeout, $policy)
        if (-not $probe.Certificates.Count) {
            throw "未取得可解析的憑證；可能是 DNS、TCP 或 TLS 錯誤。$($probe.Error)"
        }
        $workDirectory = Join-Path ([IO.Path]::GetTempPath()) ('twca-check.' + [guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($workDirectory)
        $hasTwca = $false; $recommended = $false; $official = $false
        $matchedRecords = [Collections.Generic.List[string]]::new()
        $summary = [Collections.Generic.List[string]]::new()
        $certIndex = 0
        foreach ($rawCertificate in $probe.Certificates) {
            $certIndex++
            $certPath = Join-Path $workDirectory "cert$certIndex.cer"
            [IO.File]::WriteAllBytes($certPath, $rawCertificate)
            $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate)
            try {
                $hashOutput = Invoke-TwcaCertutil @('-hashfile', $certPath, 'SHA256') $Options.Timeout
                $hashLines = @($hashOutput -split '\r?\n' | Where-Object { ($_ -replace '\s', '') -cmatch '^[0-9a-fA-F]{64}$' })
                if ($hashLines.Count -ne 1) { throw 'certutil 回傳的 SHA-256 格式錯誤。' }
                $fingerprint = ($hashLines[0] -replace '\s', '').ToLowerInvariant()
                if ("$($certificate.Subject)`n$($certificate.Issuer)" -match 'TWCA|TAIWAN-CA') { $hasTwca = $true }
                $isCa = $false
                foreach ($extension in $certificate.Extensions) {
                    if ($extension.Oid.Value -eq '2.5.29.19') {
                        $constraints = [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($extension, $extension.Critical)
                        $isCa = $constraints.CertificateAuthority
                    }
                }
                if ($isCa -and $data.ContainsKey($fingerprint)) {
                    $hasTwca = $true
                    $record = $data[$fingerprint]
                    $matchedRecords.Add($record.Line)
                    if ($record.Category -in @('research_candidate', 'official_confirmed')) { $recommended = $true }
                    if ($record.Category -eq 'official_confirmed') { $official = $true }
                }
                if ($Options.Detailed) {
                    $summary.Add("`n憑證 $certIndex（TLS API 取得的驗證路徑；不等同伺服器送出集合）")
                    $summary.Add("subject=$($certificate.Subject)`nissuer=$($certificate.Issuer)`nserial=$($certificate.SerialNumber)")
                    $summary.Add("notBefore=$($certificate.NotBefore.ToUniversalTime().ToString('o'))`nnotAfter=$($certificate.NotAfter.ToUniversalTime().ToString('o'))")
                    $summary.Add("SHA-256=$fingerprint`nCA:$isCa")
                    $summary.Add((Invoke-TwcaCertutil @('-dump', $certPath) $Options.Timeout))
                }
            } finally { $certificate.Dispose() }
        }
        $tlsPassed = $probe.HandshakeCompleted -and $probe.PolicyErrors -eq [Net.Security.SslPolicyErrors]::None
        $risk = Get-TwcaRisk $recommended $official $hasTwca $tlsPassed
        "目標：$Target" | Write-Output
        Show-TwcaDecision $risk | Write-Output
        if (-not $tlsPassed) { '另有問題：TLS 驗證失敗，請立即處理；不影響上述換證建議。' | Write-Output }
        if ($Options.Detailed) {
            $tlsStatus = if ($tlsPassed) { '通過' } else { '失敗' }
            $caBaseline = if ($Options.CaFile) { $Options.CaFile } else { 'Windows 預設信任庫（非 OpenSSL 或所有瀏覽器信任庫）' }
            "`n目標：$Target`n連線端點／SNI：$($endpoint.DnsName):$($endpoint.Port) / $($endpoint.DnsName)"
            "檢查時間：$checkedAt`n實際連線 IP：$($probe.PeerAddress)`n工具：Windows certutil.exe / PowerShell $($PSVersionTable.PSVersion)"
            "CA 基準：$caBaseline`n中繼資料：$($Options.DataFile)（$($data.Count) 筆）"
            "事件判定：$($risk.Status)（$($risk.Label)）`nTLS：$tlsStatus`n撤銷狀態：未檢查（未執行 OCSP／CRL）"
            '期限：公告為 2026-11-06 00:00，未載時區；維運保守採 +08:00，不代表已確認撤銷時間。'
            if ($matchedRecords.Count) { "`n命中資料（SHA-256、名稱、證據類別、來源、查核時間）："; $matchedRecords.ToArray() }
            "`n資料版本（公開候選清單不等於官方完整撤銷名單）："
            foreach ($record in $data.Values | Sort-Object Fingerprint) { "$($record.Name) | $($record.Category) | $($record.CheckedAt)" }
            $summary.ToArray()
            "`nTLS API 嚴格驗證結果（主機名、用途、有效期間與本機信任路徑）："
            "SslPolicyErrors=$($probe.PolicyErrors)；HandshakeCompleted=$($probe.HandshakeCompleted)"
            $probe.Diagnostics.ToArray()
            if ($probe.Error) { "連線診斷：$($probe.Error)" }
            if ($hasTwca) { "`n下一步：向 TWCA／憑證管理者確認新舊指紋；於實際 TLS 終止層更新重簽的終端憑證及完整中繼鏈，不能只補中繼。" }
            "`n限制：取證握手允許保存不受信任憑證，但是否通過取決於獨立的 TLS 政策結果；不自動下載 AIA。"
            'Windows 可能使用本機快取中繼；API 路徑不等同原版伺服器送出集合，無法完整檢查未選用的替代鏈或據此認定伺服器缺鏈。'
            '未涵蓋重新導向、其他 CDN／LB 節點、App pinning 或瀏覽器撤信政策。'
        }
        $Options.ResultExit = $risk.ExitCode
    } catch {
        Show-TwcaFailure $_.Exception.Message $Options.Detailed | Write-Output
        $Options.ResultExit = 2
    } finally {
        if ($policy) { foreach ($certificate in $policy.CustomTrustStore) { $certificate.Dispose() } }
        if ($workDirectory) { [IO.Directory]::Delete($workDirectory, $true) }
    }
}

function Invoke-TwcaMain {
    param([string[]]$Arguments)
    $options = @{ Timeout = 15; DataFile = (Join-Path $PSScriptRoot 'data/twca-intermediates.tsv'); CaFile = ''; Detailed = $false; ResultExit = 2 }
    $target = ''; $inputFile = ''
    try {
        for ($argIndex = 0; $argIndex -lt $Arguments.Count; $argIndex++) {
            $argument = $Arguments[$argIndex]
            switch -CaseSensitive ($argument) {
                { $_ -in @('--help', '-h') } { Show-TwcaUsage | Write-Output; return 0 }
                '--verbose' { $options.Detailed = $true }
                '--' {
                    if ($target -or $argIndex + 2 -ne $Arguments.Count) { throw '一次只接受一個網站。' }
                    $target = $Arguments[++$argIndex]
                }
                { $_ -in @('--file', '-f', '--ca-file', '--timeout', '--data-file') } {
                    if ($argIndex + 1 -ge $Arguments.Count) { throw "$argument 缺少參數。" }
                    $value = $Arguments[++$argIndex]
                    switch ($argument) {
                        { $_ -in @('--file', '-f') } {
                            if ($inputFile -or -not $value) { throw '請指定一份非空的網站清單路徑。' }
                            $inputFile = $value
                        }
                        '--ca-file' { $options.CaFile = $value }
                        '--data-file' { $options.DataFile = $value }
                        '--timeout' {
                            if ($value -cnotmatch '^[1-9][0-9]{0,2}$' -or [int]$value -gt 300) { throw '逾時秒數必須是 1 到 300。' }
                            $options.Timeout = [int]$value
                        }
                    }
                }
                default {
                    if ($argument.StartsWith('-')) { throw "不認得的選項：$argument" }
                    if ($target) { throw '一次只接受一個網站。' }
                    $target = $argument
                }
            }
        }
        if ($inputFile -and $target) { throw '--file/-f 不可與單站參數同時使用。' }
        if (-not $inputFile -and -not $target) { Show-TwcaUsage | Write-Output; return 2 }
        if ($options.CaFile -and -not (Test-Path -LiteralPath $options.CaFile -PathType Leaf)) { throw '無法讀取指定的 CA 檔案。' }
        if ($inputFile) {
            $entries = @([IO.File]::ReadAllLines($inputFile) | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
            if (-not $entries.Count) { throw '網站清單沒有可檢查的連結。' }
            $batchExit = 0; $siteIndex = 0
            foreach ($entry in $entries) {
                if ($siteIndex++) { '' | Write-Output }
                $report = @(Test-TwcaSite $entry $options)
                if (-not $report.Count -or -not $report[0].StartsWith('目標：')) { "目標：$entry" | Write-Output }
                $report | Write-Output
                $batchExit = [Math]::Max($batchExit, $options.ResultExit)
            }
            return $batchExit
        }
        Test-TwcaSite $target $options | Write-Output
        return $options.ResultExit
    } catch {
        Show-TwcaFailure $_.Exception.Message $options.Detailed | Write-Output
        return 2
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    $result = @(Invoke-TwcaMain -Arguments $args)
    $exitCode = [int]$result[-1]
    if ($result.Count -gt 1) { $result[0..($result.Count - 2)] | Write-Output }
    exit $exitCode
}