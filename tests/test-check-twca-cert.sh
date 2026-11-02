#!/bin/bash
set -eu
export LC_ALL=C
root_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$root_dir/scripts/check-twca-cert.sh"

check_target() {
    target=$1
    parse_target
    [[ $host:$port == "$2" ]] || fail "解析結果錯誤：$1"
}

check_target https://www.mnd.gov.tw/ www.mnd.gov.tw:443
check_target 'https://example.com:8443/path?query#fragment' example.com:8443
check_target example.com:00443 example.com:443
check_target xn--fiqs8s.example xn--fiqs8s.example:443
check_target a.example a.example:443

for rejected_target in 'http://example.com' 'https://user@example.com' \
    'https://' '-evil.example' 'example..com' 'example.com:0' \
    'example.com:65536' 'example.com:443:443' '127.0.0.1' \
    'https://[::1]/' 'https://example.com/a b' 'example.com.' 'example.com/' \
    $'https://example.com/\n'; do
    if (target=$rejected_target; parse_target) >/dev/null 2>&1; then
        fail "不應接受：$rejected_target"
    fi
done
openssl_bin=${OPENSSL_BIN:-openssl}
check_dependencies
printf '%s\n' 'PASS：目標解析與 OpenSSL 能力檢查。'

test_dir=$(mktemp -d "${TMPDIR:-/tmp}/twca-tests.XXXXXXXX")
server_pid=''
trap '[[ -z $server_pid ]] || { kill "$server_pid" 2>/dev/null || :; wait "$server_pid" 2>/dev/null || :; }; rm -rf -- "$test_dir"' EXIT
trap 'exit 2' INT TERM HUP
real_openssl=$openssl_bin
work_dir=$test_dir/work
mkdir "$work_dir"
"$real_openssl" req -x509 -newkey rsa:2048 -nodes -keyout "$test_dir/root.key" -out "$test_dir/root.pem" -days 2 -subj '/CN=Test Root' -addext 'basicConstraints=critical,CA:TRUE' > /dev/null 2>&1
"$real_openssl" req -new -newkey rsa:2048 -nodes -keyout "$test_dir/ca.key" -out "$test_dir/ca.csr" -subj '/CN=TWCA Test Intermediate' > /dev/null 2>&1
printf '%s\n' 'basicConstraints=critical,CA:TRUE,pathlen:0' 'keyUsage=critical,keyCertSign,cRLSign' > "$test_dir/ca.ext"
"$real_openssl" x509 -req -in "$test_dir/ca.csr" -CA "$test_dir/root.pem" -CAkey "$test_dir/root.key" -set_serial 2 -days 2 -extfile "$test_dir/ca.ext" -out "$test_dir/ca.pem" > /dev/null 2>&1
"$real_openssl" req -new -newkey rsa:2048 -nodes -keyout "$test_dir/leaf.key" -out "$test_dir/leaf.csr" -subj '/CN=localhost' > /dev/null 2>&1
printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'subjectAltName=DNS:localhost' 'extendedKeyUsage=serverAuth' > "$test_dir/leaf.ext"
"$real_openssl" x509 -req -in "$test_dir/leaf.csr" -CA "$test_dir/ca.pem" -CAkey "$test_dir/ca.key" -set_serial 3 -days 2 -extfile "$test_dir/leaf.ext" -out "$test_dir/leaf.pem" > /dev/null 2>&1
printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'subjectAltName=DNS:localhost' 'extendedKeyUsage=clientAuth' > "$test_dir/client.ext"
"$real_openssl" x509 -req -in "$test_dir/leaf.csr" -CA "$test_dir/ca.pem" -CAkey "$test_dir/ca.key" -set_serial 5 -days 2 -extfile "$test_dir/client.ext" -out "$test_dir/client.pem" > /dev/null 2>&1
"$real_openssl" x509 -req -in "$test_dir/leaf.csr" -CA "$test_dir/root.pem" -CAkey "$test_dir/root.key" -set_serial 6 -days 2 -extfile "$test_dir/leaf.ext" -out "$test_dir/non-twca.pem" > /dev/null 2>&1
ca_hash=$("$real_openssl" x509 -in "$test_dir/ca.pem" -noout -fingerprint -sha256)
ca_hash=$(printf '%s' "${ca_hash#*=}" | tr -d ':' | tr '[:upper:]' '[:lower:]')
other_hash=$(printf '%064d' 0)

write_data() {
    printf '%s\tTest CA\t%s\thttps://example.com/source\t2026-11-02T00:00:00Z\n' "$1" "$2" > "$test_dir/data.tsv"
    data_file=$test_dir/data.tsv
    load_data
}

set_chain() {
    cat "$1" > "$work_dir/client.out"
    if [[ -n ${2:-} ]]; then cat "$2" >> "$work_dir/client.out"; fi
    : > "$work_dir/client.err"
    extract_certificates
    inspect_certificates
    host=localhost
    ca_file=$test_dir/root.pem
    client_exit=0
}

expect_classification() {
    classify_twca_risk
    [[ $event_status == "$1" && $result_exit == "$2" ]] || fail "分類錯誤：預期 $1/$2，得到 $event_status/$result_exit"
}

expect_decision() {
    local decision
    decision=$(format_decision)
    [[ $decision == *"$1"* ]] || fail "換證結論錯誤：$decision"
}

write_data "$ca_hash" research_candidate
set_chain "$test_dir/leaf.pem" "$test_dir/ca.pem"
verify_tls
expect_classification REPLACE_RECOMMENDED 1
expect_decision '❌ 要。請在 2026-11-06 00:00 前完成換證'
host=wrong.example
verify_tls
expect_classification REPLACE_RECOMMENDED 2
expect_decision '❌ 要。請在 2026-11-06 00:00 前完成換證'

write_data "$ca_hash" article_observation
set_chain "$test_dir/leaf.pem" "$test_dir/ca.pem"
verify_tls
expect_classification REVIEW_REQUIRED 1
expect_decision '無法確定。請在 2026-11-06 前向 TWCA 確認'

write_data "$ca_hash" official_confirmed
set_chain "$test_dir/leaf.pem" "$test_dir/ca.pem"
verify_tls
expect_classification REPLACE_RECOMMENDED 1
(( official == 1 )) || fail '未辨識官方資料類別。'
expect_decision '命中所提供的官方確認中繼資料'

write_data "$other_hash" research_candidate
set_chain "$test_dir/leaf.pem" "$test_dir/ca.pem"
verify_tls
expect_classification REVIEW_REQUIRED 1

set_chain "$test_dir/leaf.pem"
verify_tls
expect_classification REVIEW_REQUIRED 2
grep -q 'unable to get local issuer' "$work_dir/verify.out" || fail '缺中繼測試未失敗。'

set_chain "$test_dir/leaf.pem" "$test_dir/ca.pem"
ca_file=$test_dir/ca.pem
verify_tls
expect_classification REVIEW_REQUIRED 2

future_openssl() {
    if [[ $1 == verify ]]; then
        shift
        "$real_openssl" verify -attime 4102444800 "$@"
    else
        "$real_openssl" "$@"
    fi
}
set_chain "$test_dir/leaf.pem" "$test_dir/ca.pem"
openssl_bin=future_openssl
verify_tls
openssl_bin=$real_openssl
expect_classification REVIEW_REQUIRED 2
grep -q 'expired' "$work_dir/verify.out" || fail '過期憑證未被拒絕。'

set_chain "$test_dir/client.pem" "$test_dir/ca.pem"
verify_tls
expect_classification REVIEW_REQUIRED 2
grep -q 'unsuitable certificate purpose' "$work_dir/verify.out" || fail '用途錯誤未被拒絕。'

set_chain "$test_dir/non-twca.pem"
verify_tls
expect_classification NOT_MATCHED 0
expect_decision '✅ 不需要因本次 TWCA 事件在 2026-11-06 前換證'
host=wrong.example
verify_tls
expect_classification INDETERMINATE 2
expect_decision '無法判定。請在 2026-11-06 前完成確認'
host=localhost
verify_tls
client_exit=1
verify_tls
expect_classification INDETERMINATE 2
printf '%s\n' 'PASS：同名不同指紋、命中風險、缺鏈、缺根、到期、用途與主機名驗證。'

for invalid_data in empty bad-hash duplicate bad-category bad-date extra-field; do
    case "$invalid_data" in
        empty) : > "$test_dir/data.tsv" ;;
        bad-hash) printf 'bad\tCA\tresearch_candidate\thttps://example.com\t2026-11-02T00:00:00Z\n' > "$test_dir/data.tsv" ;;
        duplicate) write_data "$other_hash" research_candidate; cat "$test_dir/data.tsv" "$test_dir/data.tsv" > "$test_dir/duplicate.tsv"; cp "$test_dir/duplicate.tsv" "$test_dir/data.tsv" ;;
        bad-category) printf '%s\tCA\tunknown\thttps://example.com\t2026-11-02T00:00:00Z\n' "$other_hash" > "$test_dir/data.tsv" ;;
        bad-date) printf '%s\tCA\tresearch_candidate\thttps://example.com\tunknown\n' "$other_hash" > "$test_dir/data.tsv" ;;
        extra-field) printf '%s\tCA\tresearch_candidate\thttps://example.com\t2026-11-02T00:00:00Z\textra\n' "$other_hash" > "$test_dir/data.tsv" ;;
    esac
    if (load_data) > /dev/null 2>&1; then fail "未拒絕資料：$invalid_data"; fi
done
for malformed_pem in '' '-----BEGIN CERTIFICATE-----' $'-----BEGIN CERTIFICATE-----\nbad\n-----END CERTIFICATE-----'; do
    printf '%s\n' "$malformed_pem" > "$work_dir/client.out"
    if (extract_certificates; inspect_certificates) > /dev/null 2>&1; then fail '未拒絕無效 PEM。'; fi
done
printf '%s\n' 'PASS：清單嚴格驗證與空白／損壞 PEM。'

timeout_seconds=1
mkfifo "$test_dir/block.fifo"
exec 8<> "$test_dir/block.fifo"
blocked_client() { read -r -t 60 -u 8 _blocked || :; }
run_with_timeout blocked_client
[[ -f $work_dir/timed-out && $client_exit -ne 0 ]] || fail '逾時控制未終止連線。'
[[ -z $client_pid && -z $watchdog_pid ]] || fail '逾時後仍有未清理程序。'
exec 8>&-
rm "$work_dir/timed-out" "$work_dir/watchdog.fifo"
timeout_seconds=5
run_with_timeout "$real_openssl" version
[[ $client_exit == 0 && ! -e $work_dir/timed-out ]] || fail '正常程序被誤判逾時。'
printf '%s\n' 'PASS：Bash watchdog 正常取消與逾時終止。'

write_data "$ca_hash" research_candidate
"$real_openssl" s_server -accept 127.0.0.1:0 -cert "$test_dir/leaf.pem" -key "$test_dir/leaf.key" -cert_chain "$test_dir/ca.pem" -www > "$test_dir/server.log" 2>&1 &
server_pid=$!
server_port=''
for (( attempt=0; attempt<10000; attempt++ )); do
    server_port=$(sed -n 's/^ACCEPT .*:\([0-9][0-9]*\).*$/\1/p' "$test_dir/server.log")
    [[ -z $server_port ]] || break
    kill -0 "$server_pid" 2>/dev/null || fail '本地 TLS 伺服器啟動失敗。'
done
[[ -n $server_port ]] || fail '無法取得本地 TLS 伺服器連接埠。'
printf '%s\n' 'keep' > "$test_dir/cert-existing.pem"
mkdir "$test_dir/tmp"
cli_exit=0
(cd "$test_dir"; TMPDIR=$test_dir/tmp OPENSSL_BIN=$real_openssl /bin/bash "$root_dir/scripts/check-twca-cert.sh" --ca-file "$test_dir/root.pem" --data-file "$test_dir/data.tsv" "https://localhost:$server_port/") > "$test_dir/report" 2>&1 || cli_exit=$?
[[ $cli_exit == 1 ]] || { cat "$test_dir/report"; fail "CLI 退出碼錯誤：$cli_exit"; }
grep -q '換證結論：❌ 要。請在 2026-11-06 00:00 前完成換證' "$test_dir/report" || fail 'CLI 未顯示換證期限。'
[[ $(wc -l < "$test_dir/report") -eq 3 ]] || fail '預設報告不夠精簡。'
if grep -q 'SHA-256\|subject=\|資料版本' "$test_dir/report"; then fail '預設報告包含詳細憑證資訊。'; fi
[[ $(cat "$test_dir/cert-existing.pem") == keep ]] || fail '使用者憑證檔遭變更。'
[[ -z $(find "$test_dir/tmp" -mindepth 1 -print) ]] || fail 'CLI 暫存目錄未清理。'
cli_exit=0
OPENSSL_BIN=$real_openssl /bin/bash "$root_dir/scripts/check-twca-cert.sh" --verbose --ca-file "$test_dir/root.pem" --data-file "$test_dir/data.tsv" "https://localhost:$server_port/" > "$test_dir/report" 2>&1 || cli_exit=$?
[[ $cli_exit == 1 ]] || fail '第二次檢查退出碼不一致。'
grep -q 'REPLACE_RECOMMENDED' "$test_dir/report" || fail '詳細報告未保留事件狀態。'
grep -q 'TLS：通過' "$test_dir/report" || fail '詳細報告未保留 TLS 驗證。'
grep -q 'SHA-256=' "$test_dir/report" || fail '詳細報告未包含憑證指紋。'
printf '%s\n' 'PASS：真實本地 TLS、CLI 退出碼、保存使用者檔案與暫存清理。'

printf '# sites\r\n\r\n  https://localhost:%s/  \r\nlocalhost:%s' "$server_port" "$server_port" > "$test_dir/url.list"
for file_option in --file -f; do
    cli_exit=0
    TMPDIR=$test_dir/tmp OPENSSL_BIN=$real_openssl /bin/bash "$root_dir/scripts/check-twca-cert.sh" "$file_option" "$test_dir/url.list" --ca-file "$test_dir/root.pem" --data-file "$test_dir/data.tsv" > "$test_dir/report" 2>&1 || cli_exit=$?
    [[ $cli_exit == 1 ]] || fail "批次退出碼錯誤：$file_option"
    [[ $(grep -c '^目標：' "$test_dir/report") -eq 2 ]] || fail '批次未讀取全部目標或錯誤處理空白行。'
    [[ $(grep -c '^換證結論：❌ 要。' "$test_dir/report") -eq 2 ]] || fail '批次未沿用 CA 與中繼資料選項。'
    [[ $(wc -l < "$test_dir/report") -eq 7 ]] || fail '批次預設報告不夠精簡。'
done
printf '%s\n' '--help' 'http://localhost/' "localhost:$server_port" > "$test_dir/url.list"
cli_exit=0
OPENSSL_BIN=$real_openssl /bin/bash "$root_dir/scripts/check-twca-cert.sh" -f "$test_dir/url.list" --verbose --ca-file "$test_dir/root.pem" --data-file "$test_dir/data.tsv" > "$test_dir/report" 2>&1 || cli_exit=$?
[[ $cli_exit == 2 ]] || fail '批次未彙總錯誤退出碼。'
grep -q '^目標：--help$' "$test_dir/report" || fail '批次未報告選項形式的無效目標。'
grep -q '^目標：http://localhost/$' "$test_dir/report" || fail '批次遇到無效目標後未繼續。'
grep -q '^換證結論：❌ 要。' "$test_dir/report" || fail '批次遇到錯誤後未檢查有效網站。'
grep -q 'SHA-256=' "$test_dir/report" || fail '批次未沿用 --verbose。'
if grep -q '^用法：' "$test_dir/report"; then fail '清單內容被誤當成 CLI 選項。'; fi
[[ -z $(find "$test_dir/tmp" -mindepth 1 -print) ]] || fail '批次暫存目錄未清理。'
printf '# empty\n \t\r\n' > "$test_dir/empty.list"
for invalid_list in "$test_dir/empty.list" "$test_dir/missing.list" "$test_dir"; do
    cli_exit=0
    /bin/bash "$root_dir/scripts/check-twca-cert.sh" -f "$invalid_list" > /dev/null 2>&1 || cli_exit=$?
    [[ $cli_exit == 2 ]] || fail '未拒絕空白、缺少或目錄清單。'
done
cli_exit=0
/bin/bash "$root_dir/scripts/check-twca-cert.sh" -f "$test_dir/url.list" localhost > /dev/null 2>&1 || cli_exit=$?
[[ $cli_exit == 2 ]] || fail '未拒絕混用清單與單站參數。'
printf '%s\n' 'PASS：批次長短選項、CRLF、末行無換行、錯誤後繼續、選項隔離與退出碼。'

kill "$server_pid"
wait "$server_pid" 2>/dev/null || :
server_pid=''
cli_exit=0
OPENSSL_BIN=$real_openssl /bin/bash "$root_dir/scripts/check-twca-cert.sh" --timeout 1 --data-file "$test_dir/data.tsv" "localhost:$server_port" > "$test_dir/report" 2>&1 || cli_exit=$?
[[ $cli_exit == 2 ]] || fail '連線失敗未回傳 2。'
grep -q '換證結論：無法判定' "$test_dir/report" || fail '連線失敗未標示無法判定。'
[[ $(wc -l < "$test_dir/report") -eq 2 ]] || fail '連線錯誤輸出不夠精簡。'
for invalid_option in --unknown --timeout --ca-file --data-file --file -f; do
    cli_exit=0
    /bin/bash "$root_dir/scripts/check-twca-cert.sh" "$invalid_option" > /dev/null 2>&1 || cli_exit=$?
    [[ $cli_exit == 2 ]] || fail "選項錯誤未回傳 2：$invalid_option"
done
data_file=$root_dir/data/twca-intermediates.tsv
load_data
printf '%s\n' 'PASS：CLI 連線錯誤、缺少參數與正式清單格式。' '全部測試通過。'