# TWCA 網站憑證換證檢查

使用 Bash 與 OpenSSL 檢查指定 HTTPS 端點實際送出的憑證鏈，提供 TWCA 2026 年中繼更換事件的證據導向建議。工具不安裝憑證、不接觸網站私鑰。

預設只顯示網站、**是否需在 2026-11-06 前換證**及一句原因。命中候選清單時明確建議換證；證據不足時明示需在期限前確認，不會誤報為不用換。

`✅` 表示不需因本次事件換證，`❌` 表示建議換證；無法確定或無法判定時保留文字提醒，不套用這兩種符號。

```bash
bash scripts/check-twca-cert.sh www.rocna.edu.tw
```

需要完整憑證、指紋、資料來源與 TLS 診斷時才加上 `--verbose`：

```bash
bash scripts/check-twca-cert.sh --verbose www.rocna.edu.tw
```

批次檢查 [url.list](url.list) 中的所有網站：

```bash
bash scripts/check-twca-cert.sh --file url.list
bash scripts/check-twca-cert.sh -f url.list
```

每行填一個 HTTPS URL 或網域；忽略空白行、行首 `#` 註解及前後空白，支援 Windows 換行與末行沒有換行。`--file`／`-f` 不可與單站參數混用；其他選項套用至所有網站。逐站顯示結論，單站錯誤不會中止其餘檢查。批次退出碼取所有結果中的最高值：全部為 `0` 才回傳 `0`，任一為 `2` 就回傳 `2`，其餘有 `1` 則回傳 `1`。空清單或無法讀取的檔案回傳 `2`。

## 執行

相依工具為 Bash 3.2 以上、OpenSSL 3 以上與 macOS／Linux 常見工具（awk、grep、sed、tr、mktemp、mkfifo 等）。不需要 jq、Ruby、Python 或 GNU timeout。OpenSSL 4 亦可使用，腳本會檢查必要旗標。

macOS 內建的 LibreSSL 不支援；可以安裝並指定 Homebrew OpenSSL：

```bash
brew install openssl@3
export OPENSSL_BIN="$(brew --prefix openssl@3)/bin/openssl"
/bin/bash scripts/check-twca-cert.sh https://www.mnd.gov.tw/
```

Ubuntu／Debian 可使用提供 OpenSSL 3 以上的版本：

```bash
sudo apt-get install openssl ca-certificates
bash scripts/check-twca-cert.sh www.mnd.gov.tw
```

可指定 CA bundle、逾時秒數與非標準連接埠：

```bash
bash scripts/check-twca-cert.sh --ca-file /path/to/ca-bundle.pem --timeout 20 https://example.com:8443/path
bash scripts/check-twca-cert.sh --help
```

預設逾時為 15 秒，允許 1 到 300 秒。接受 HTTPS URL 或 ASCII DNS 網域（可含連接埠），國際化網域使用 punycode。拒絕 HTTP、帳密、IP literal、空白、控制字元與非法連接埠。URL 路徑、查詢與 fragment 不參與憑證檢查；不送出 HTTP 請求、不追蹤重新導向。

## 如何判定

| 事件狀態 | 意義 |
| --- | --- |
| `REPLACE_RECOMMENDED` | 伺服器送出的 CA 憑證指紋命中公開研究候選清單；建議安排換證並向 TWCA 確認。不是宣稱已查到撤銷狀態。 |
| `REVIEW_REQUIRED` | 憑證 DN 或驗證路徑顯示 TWCA／TAIWAN-CA，但沒有足夠證據辨識是否已更新；需人工確認。 |
| `NOT_MATCHED` | 此次可觀測鏈與本機驗證路徑未見 TWCA，而且 TLS 驗證通過。不是保證所有節點、用戶端或未來連線都不受影響。 |
| `INDETERMINATE` | 連線、逾時、資料或驗證問題導致不能判定。 |

**事件判定與 TLS 結果獨立。** 命中候選中繼，即使尚未到期、TLS 驗證通過，也仍顯示換證建議；命中候選但 TLS 失敗時，仍保留命中證據。

| 退出碼 | 意義 |
| --- | --- |
| `0` | 本事件未命中，而且 TLS 通過。 |
| `1` | 建議更換或需人工確認，而且 TLS 通過。 |
| `2` | 無法判定、TLS 失敗／未完成、連線錯誤、參數或資料錯誤。 |

自動化時應同時保留文字報告及退出碼，不要將 `1` 當成工具故障，也不要將 `2` 當成沒有換證風險：

```bash
result=0
bash scripts/check-twca-cert.sh https://www.mnd.gov.tw/ || result=$?
printf '退出碼：%s\n' "$result"
```

## 取證與驗證

1. 以原 DNS 主機設定 SNI，從一次 `openssl s_client -showcerts` 連線保存伺服器送出的憑證。取證握手允許憑證驗證錯誤，以便在舊鏈已失效時仍取得證據；不把這次握手當成信任成功。
2. 用 `openssl x509` 解析每張憑證，包括 subject、issuer、序號、有效期間、SHA-256 與 Basic Constraints。名稱有 Root 不代表就是信任錨。
3. 對同一份保存的終端與中繼，以 `openssl verify -show_chain -verify_hostname ... -purpose sslserver` 嚴格驗證主機名、用途、有效期間、簽章及本機信任路徑。伺服器送出的其他憑證放在 `-untrusted`，不擅自加入可信任根。
4. 預設使用 OpenSSL 配置的 CA store，不等於 macOS Keychain 或瀏覽器信任庫。提供 `--ca-file` 時只使用該 bundle，停用預設 CApath／CAstore。

缺中繼與本機缺信任根可能產生相同的建鏈錯誤。工具保留 OpenSSL 診斷，不一律判定為伺服器缺鏈，也不自動透過 AIA 下載補鏈。伺服器不必送出根憑證。

每次檢查使用獨立暫存目錄，透過 trap 清理；不寫入或刪除目前目錄的 `cert*.pem`。Bash watchdog 會終止逾時連線，正常完成時會取消 watchdog，不依賴 GNU timeout。

## 指紋資料與來源

[中繼資料](data/twca-intermediates.tsv)包含六張研究候選中繼，以及文章實測的 Global EVSSL 補充項目。所有指紋均在 2026-11-02 由 crt.sh／CCADB 的 PEM 以 OpenSSL 重算，並核對 subject、issuer、序號與有效期間。

- [原文章](https://sheng.page/posts/twca-intermediate-replacement-what-to-check/)：事件背景與維運注意事項。
- [TWCA 官方公告](https://ssl.twca.com.tw/news_detail/5f3395bf-bef6-4b40-b922-ceac4b06bf53)：新中繼重簽終端、沿用金鑰對，並安裝完整鏈。
- [Bugzilla 2087236](https://bugzilla.mozilla.org/show_bug.cgi?id=2087236)：六張候選中繼的研究者清單，不是官方完整撤銷名單。
- [CCADB PEM CSV](https://ccadb.my.salesforce-sites.com/mozilla/PublicAllIntermediateCertsWithPEMCSV)：部分候選 PEM 的交叉查證來源；其餘 crt.sh 下載 ID 記錄於各筆名稱。

Global EVSSL 的指紋 `49695a5f0f7ef6edf698193d99ed48baade20ea457403c11cead492c458665da` 屬 `article_observation`，只產生人工確認提醒，不能推論它就是官方將撤銷的中繼。

官方公告的期限為 **2026-11-06 00:00**，未載時區；維運保守採 **+08:00**，但這不是已確認的撤銷時點。期限前後都使用相同證據規則，不因日期已過就宣稱已撤銷。

資料格式為五欄 TSV：`sha256`、`label`、`category`、`source_url`、`checked_at`。`#` 開頭為註解，其餘每列必須恰好五欄。指紋需為 64 位十六進位，查核時間使用 UTC 格式 `YYYY-MM-DDTHH:MM:SSZ`。拒絕空清單、重複指紋、非法類別與畸形資料；不以 source／eval 執行資料內容。

以 `--data-file FILE` 提供經人工查證的更新資料。`research_candidate` 表示研究候選、`article_observation` 表示補充觀察；只有官方提供精確指紋且完成查證後，才能使用 `official_confirmed`。預設清單沒有任何 `official_confirmed`。來源 URL 與類別是操作者提供的資訊，腳本不會自動驗證官方真偽或更新清單。

更新時必須取得可信來源的實際憑證，用以下方式重算，並核對序號與簽發關係；不能靠名稱或核發日期猜測新舊憑證：

```bash
openssl x509 -in intermediate.pem -noout -subject -issuer -serial -dates -fingerprint -sha256
```

## 換證後要做什麼

於實際終止 TLS 的 LB、CDN、Ingress 或應用程式更新**重簽的終端憑證及完整中繼鏈**，不能只補一張中繼。再次從外部執行檢查，對照新終端及中繼指紋；名稱相同、公鑰沿用或未命中清單，都不能單獨證明完成換證。CT 登錄也不能證明已部署。

## 測試

```bash
/bin/bash -n scripts/check-twca-cert.sh tests/test-check-twca-cert.sh
shellcheck --shell=bash scripts/check-twca-cert.sh tests/test-check-twca-cert.sh
/bin/bash tests/test-check-twca-cert.sh
```

ShellCheck 是開發工具，不是執行相依。測試使用臨時產生的本地 CA、終端憑證與真實 TLS 伺服器；測試指紋不會寫入正式資料。測試不依賴公開網站或網際網路，可設定 `OPENSSL_BIN` 檢查其他 OpenSSL 版本。

目前已在 macOS Bash 3.2，搭配 OpenSSL 3.5.9 與 4.0.3 執行通過，Bash 語法檢查與 ShellCheck 亦通過。Linux 容器引擎目前無法連線，尚未完成 Linux 實測；其他環境的驗證結果應以實際執行為準，不將相容設計等同已測試。

## 限制

- 未執行 OCSP／CRL；TLS 通過不等於撤銷檢查通過，也不代表瀏覽器一定接受。
- 不驗證序號隨機熵、不推論私鑰外洩、不判定 RA 事件影響。
- 只檢查一次連線的 TLS 端點，不掃描所有 DNS IP、其他 CDN／LB 節點、來源站或 HTTP 重新導向目標。
- 不涵蓋 App pinning、Java／Android 自訂信任庫或瀏覽器撤信政策。
- 不提供批次或 JSON 輸出、不自動更新資料、不安裝憑證、不更換金鑰。