# TWCA 網站憑證換證檢查

![網站憑證檢查結果](./imgs/screenshot.png)

檢查網站是否需要因 TWCA 2026 年事件，在 **2026-11-06 前更換憑證**。

這個工具只做檢查，**不會修改網站或自動更換憑證**。

## 1. 準備工具

需要 Bash 3.2 以上、OpenSSL 3 以上，以及網路連線。

Windows 可使用 [check-twca-cert.ps1](check-twca-cert.ps1)，需要 **PowerShell 7.4 以上**與 Windows 內建的 `certutil.exe`，不需要 OpenSSL。不支援 Windows PowerShell 5.1；請使用 `pwsh`，不是 `powershell`。

## 2. 執行檢查

在終端機切換到這個專案資料夾，再執行以下指令。

**檢查一個網站**：把範例網址改成你要檢查的網站。

```bash
bash check-twca-cert.sh https://www.twca.com.tw/
```

也可以只填網域，例如 `www.twca.com.tw`。請勿使用 `http://` 或直接填 IP 位址。

**檢查多個網站**：在 [url.list](url.list) 中每行填一個網址或網域，也可參考 [url.list.example](url.list.example)。

```text
www.twca.com.tw
www.gov.tw
```

接著執行：

```bash
bash check-twca-cert.sh -f url.list
```

`-f` 與 `--file` 相同。空白行與 `#` 開頭的註解會略過；某個網站檢查失敗時，仍會繼續檢查其餘網站。

### Windows PowerShell 版本

```powershell
pwsh -NoProfile -File ./check-twca-cert.ps1 https://www.twca.com.tw/
pwsh -NoProfile -File ./check-twca-cert.ps1 -f ./url.list
pwsh -NoProfile -File ./check-twca-cert.ps1 --verbose -f ./url.list
pwsh -NoProfile -File ./check-twca-cert.ps1 --timeout 30 --file ./url.list
pwsh -NoProfile -File ./check-twca-cert.ps1 --help
```

沿用 Bash 版本的選項、資料檔、換證判定、期限與退出碼。`--data-file FILE` 可指定相同格式的 TSV；`--ca-file FILE` 可指定包含自簽信任根的 PEM 檔案，此時不使用 Windows 預設信任根。自訂 CA 不會匯入系統信任庫；不接受只提供中繼憑證。

`certutil` 本身無法直接取得 HTTPS／SNI 憑證，因此 PowerShell 版本使用 .NET `SslStream` 進行握手與主機名、用途、有效期間、信任路徑驗證；以 `certutil -hashfile ... SHA256` 比對 DER 憑證指紋，詳細模式另以 `certutil -dump` 顯示憑證資訊。不呼叫 `certutil -verify`，以保留原版不執行 OCSP／CRL 的規則，也不使用 `-urlfetch` 或修改信任庫。

**平台差異**：Windows TLS API 回傳的是建構的驗證路徑，不是 OpenSSL `-showcerts` 的伺服器送出集合；Windows 可能使用本機快取中繼，未選用的替代鏈也可能無法取得。因此不能保證兩版在所有端點的結果完全相同，或用 Windows 版本確認伺服器是否送出完整中繼鏈。兩版都停用自動 AIA 下載。

## 3. 看懂結果

| 結果 | 你需要做什麼 |
| --- | --- |
| ✅ 不需換證 | 此次檢查未發現本次 TWCA 事件的換證需求。 |
| ❌ 建議換證 | 請聯絡網站管理者或 TWCA，安排在期限前換證。 |
| 無法確定 | 請在期限前向 TWCA 確認；未確認前按需換證處理。 |
| 無法判定 | 檢查未完成或連線驗證失敗。請查看錯誤、重試，或交由網站管理者確認。 |

即使網站目前能正常開啟，也可能需要換證。**沒有看到 ❌，不一定代表不用換證**，也要留意「無法確定」與「無法判定」。

若你只是網站訪客，請將結果交給網站管理者；憑證更換需要由管理者處理。

## 需要更多資訊時

加上 `--verbose`，取得詳細結果供網站管理者查閱：

```bash
bash check-twca-cert.sh --verbose -f url.list
```

預設每個網站最多等待 15 秒；可用 `--timeout 30` 改為 30 秒。其他選項請查看：

```bash
bash check-twca-cert.sh --help
```

自動化使用時，退出碼 `0` 表示此次未發現換證需求且連線驗證通過，`1` 表示建議換證或需確認，`2` 表示有檢查錯誤或連線驗證失敗。`1` 不代表程式故障；批次檢查回傳所有結果中最高的退出碼。

## 注意事項與來源

- 這是根據公開候選清單提供的換證建議，不是官方撤銷狀態查詢；資料不會自動更新。
- 只檢查本次連線，不能保證網站的所有伺服器或所有瀏覽器結果相同。
- 期限採 **2026-11-06 00:00（+08:00）** 作為保守維運期限；官方公告未載時區，不代表已確認的撤銷時點。
- 管理者換證時需更新網站憑證及完整中繼鏈，再重新檢查並向 TWCA 核對，不能只補一張中繼憑證。
- 已在 macOS 搭配 OpenSSL 3 與 4 測試；Linux 尚未完成實測。
- PowerShell 版本已在 macOS 驗證真實 .NET 本地 TLS 與分類／批次流程，僅 Windows 平台檢查與 `certutil` 使用測試替身；Windows 原生 `certutil` 與 Schannel 尚未實測。

參考：[事件說明文章](https://sheng.page/posts/twca-intermediate-replacement-what-to-check/)、[TWCA 官方公告](https://ssl.twca.com.tw/news_detail/5f3395bf-bef6-4b40-b922-ceac4b06bf53)、[候選清單來源](https://bugzilla.mozilla.org/show_bug.cgi?id=2087236)。使用的比對資料見 [data/twca-intermediates.tsv](data/twca-intermediates.tsv)。

## 開發者測試

```bash
/bin/bash -n check-twca-cert.sh tests/test-check-twca-cert.sh
shellcheck --shell=bash check-twca-cert.sh tests/test-check-twca-cert.sh
/bin/bash tests/test-check-twca-cert.sh
```

PowerShell 測試不需要額外測試套件；Windows 使用原生 `certutil`，非 Windows 使用明示的測試替身，TLS 握手與政策驗證仍使用真實 .NET：

```powershell
pwsh -NoProfile -File ./tests/test-check-twca-cert.ps1
```
