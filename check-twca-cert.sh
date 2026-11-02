#!/bin/bash
set -eu
export LC_ALL=C

fail() {
    printf '%s\n' '換證結論：無法判定。請在 2026-11-06 前完成確認。' >&2
    printf '錯誤：%s\n' "$*" >&2
    if [[ ${verbose:-0} == 1 ]]; then
        printf '%s\n' '事件判定：INDETERMINATE（無法判定）' 'TLS：未完成或失敗' '撤銷狀態：未檢查' >&2
    fi
    exit 2
}

usage() {
    printf '%s\n' \
        '用法：bash check-twca-cert.sh [選項] HTTPS_URL或網域' \
        '批次：bash check-twca-cert.sh [選項] --file FILE（或 -f FILE）' \
        '選項：--file/-f FILE、--ca-file FILE、--timeout SECONDS、--data-file FILE、--verbose、--help' \
        '預設只顯示換證結論；--verbose 顯示完整憑證與診斷。' \
        '範例：bash check-twca-cert.sh https://www.twca.com.tw/' \
        '相依工具：Bash 3.2 以上、OpenSSL 3 以上；可設定 OPENSSL_BIN。'
}

parse_target() {
    local authority label
    authority=$target
    case "$target" in
        https://*) authority=${target#https://}; authority=${authority%%[/?#]*} ;;
        *://*|*[/?#]*) fail '僅接受 HTTPS URL 或 DNS 網域（可含連接埠）。' ;;
    esac
    case "$target" in
        *[[:space:][:cntrl:]]*) fail '輸入不可包含空白或控制字元。' ;;
    esac
    case "$authority" in
        ''|*@*|*\[*|*\]*) fail '不支援空主機、帳密或 IP literal。' ;;
    esac
    host=$authority
    port=443
    if [[ $authority == *:* ]]; then
        host=${authority%:*}
        port=${authority##*:}
    fi
    [[ $port =~ ^[0-9]{1,5}$ ]] || fail '連接埠必須是 1 到 65535。'
    port=$((10#$port))
    (( port >= 1 && port <= 65535 )) || fail '連接埠必須是 1 到 65535。'
    [[ $host =~ ^[A-Za-z0-9.-]+$ && ${#host} -le 253 ]] || fail '主機必須是 ASCII DNS 網域；國際化網域請使用 punycode。'
    [[ ! $host =~ ^[0-9.]+$ ]] || fail '第一版不支援 IP literal。'
    local remaining=$host
    while :; do
        label=${remaining%%.*}
        [[ ${#label} -ge 1 && ${#label} -le 63 && $label =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || fail 'DNS 標籤格式不合法。'
        [[ $remaining == *.* ]] || break
        remaining=${remaining#*.}
    done
}

check_dependencies() {
    command -v "$openssl_bin" >/dev/null 2>&1 || fail '找不到 OpenSSL；請安裝 OpenSSL 3 以上或設定 OPENSSL_BIN。'
    openssl_version=$("$openssl_bin" version) || fail '無法取得 OpenSSL 版本。'
    [[ $openssl_version =~ ^OpenSSL\ ([0-9]+)\. ]] || fail '不支援 LibreSSL；請使用 OpenSSL 3 以上。'
    (( BASH_REMATCH[1] >= 3 )) || fail '需要 OpenSSL 3 以上。'
    local client_help verify_help flag
    client_help=$("$openssl_bin" s_client -help 2>&1) || fail '無法查詢 s_client 支援能力。'
    verify_help=$("$openssl_bin" verify -help 2>&1) || fail '無法查詢 verify 支援能力。'
    for flag in -servername -showcerts -verify_hostname -purpose; do
        [[ $client_help == *"$flag"* ]] || fail "s_client 不支援 $flag。"
    done
    for flag in -verify_hostname -purpose -show_chain -no-CApath -no-CAstore; do
        [[ $verify_help == *"$flag"* ]] || fail "verify 不支援 $flag。"
    done
}

cleanup() {
    if [[ -n ${watchdog_pid:-} ]]; then
        kill "$watchdog_pid" 2>/dev/null || :
        wait "$watchdog_pid" 2>/dev/null || :
    fi
    if [[ -n ${client_pid:-} ]]; then
        kill "$client_pid" 2>/dev/null || :
        wait "$client_pid" 2>/dev/null || :
    fi
    [[ -z ${work_dir:-} ]] || rm -rf -- "$work_dir"
}

load_data() {
    [[ -r $data_file ]] || fail '無法讀取中繼資料檔案。'
    if ! awk -F '\t' '
        /^#/ { next }
        NF != 5 { exit 1 }
        length($1) != 64 || $1 ~ /[^0-9a-fA-F]/ { exit 1 }
        $2 == "" || $2 ~ /[[:cntrl:]]/ { exit 1 }
        $3 != "research_candidate" && $3 != "article_observation" && $3 != "official_confirmed" { exit 1 }
        $4 !~ /^https:\/\/[^[:space:]]+$/ { exit 1 }
        $5 !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z$/ { exit 1 }
        { fingerprint = tolower($1); if (seen[fingerprint]++) exit 1;
          print fingerprint "\t" $2 "\t" $3 "\t" $4 "\t" $5; count++ }
        END { if (!count) exit 1 }
    ' "$data_file" > "$work_dir/data.tsv"; then
        fail '中繼資料格式錯誤、指紋重複或清單為空。'
    fi
}

run_with_timeout() {
    mkfifo "$work_dir/watchdog.fifo"
    exec 9<> "$work_dir/watchdog.fifo"
    "$@" < /dev/null > "$work_dir/client.out" 2> "$work_dir/client.err" 9>&- &
    client_pid=$!
    (
        if read -r -t "$timeout_seconds" -u 9 _cancel; then
            :
        else
            printf '%s\n' 'timeout' > "$work_dir/timed-out"
            kill "$client_pid" 2>/dev/null || :
        fi
    ) &
    watchdog_pid=$!
    client_exit=0
    wait "$client_pid" || client_exit=$?
    client_pid=''
    printf '%s\n' 'done' >&9
    wait "$watchdog_pid" || :
    watchdog_pid=''
    exec 9>&-
}

extract_certificates() {
    if ! awk -v directory="$work_dir" '
        /-----BEGIN CERTIFICATE-----/ {
            if (active) exit 1; active = 1; count++;
            file = directory "/cert" count ".pem"
        }
        active { print > file }
        /-----END CERTIFICATE-----/ {
            if (!active) exit 1; close(file); active = 0
        }
        END { if (active || !count) exit 1; print count > (directory "/count") }
    ' "$work_dir/client.out"; then
        fail '未取得完整可解析的 PEM；可能是 DNS、TCP、TLS 或憑證格式錯誤。'
    fi
    cert_count=$(cat "$work_dir/count")
}

inspect_certificates() {
    local cert_index cert_file identity fingerprint constraints match
    has_twca=0
    recommended=0
    official=0
    : > "$work_dir/summary"
    : > "$work_dir/matches"
    : > "$work_dir/untrusted.pem"
    for (( cert_index=1; cert_index<=cert_count; cert_index++ )); do
        cert_file=$work_dir/cert$cert_index.pem
        identity=$("$openssl_bin" x509 -in "$cert_file" -noout -nameopt RFC2253 -subject -issuer -serial -dates) || fail '憑證無法解析。'
        fingerprint=$("$openssl_bin" x509 -in "$cert_file" -noout -sha256 -fingerprint) || fail '無法計算憑證指紋。'
        fingerprint=$(printf '%s' "${fingerprint#*=}" | tr -d ':' | tr '[:upper:]' '[:lower:]')
        [[ $fingerprint =~ ^[0-9a-f]{64}$ ]] || fail 'OpenSSL 回傳的 SHA-256 格式錯誤。'
        constraints=$("$openssl_bin" x509 -in "$cert_file" -noout -ext basicConstraints) || fail '無法取得 CA 屬性。'
        if printf '%s' "$identity" | grep -Eiq 'TWCA|TAIWAN-CA'; then
            has_twca=1
        fi
        printf '\n憑證 %s（伺服器送出）\n%s\nSHA-256=%s\n%s\n' "$cert_index" "$identity" "$fingerprint" "$constraints" >> "$work_dir/summary"
        if [[ $constraints == *'CA:TRUE'* ]]; then
            match=$(awk -F '\t' -v fingerprint="$fingerprint" '$1 == fingerprint { print }' "$work_dir/data.tsv")
            if [[ -n $match ]]; then
                has_twca=1
                printf '%s\n' "$match" >> "$work_dir/matches"
                case "$match" in
                    *$'\tresearch_candidate\t'*) recommended=1 ;;
                    *$'\tofficial_confirmed\t'*) recommended=1; official=1 ;;
                esac
            fi
        fi
        if (( cert_index > 1 )); then
            cat "$cert_file" >> "$work_dir/untrusted.pem"
        fi
    done
}

verify_tls() {
    local verify_args
    verify_args=(verify -show_chain -purpose sslserver -verify_hostname "$host")
    if [[ -n $ca_file ]]; then
        verify_args+=(-CAfile "$ca_file" -no-CApath -no-CAstore)
    fi
    if (( cert_count > 1 )); then
        verify_args+=(-untrusted "$work_dir/untrusted.pem")
    fi
    verify_exit=0
    "$openssl_bin" "${verify_args[@]}" "$work_dir/cert1.pem" > "$work_dir/verify.out" 2>&1 || verify_exit=$?
    if grep -E '^depth=[0-9]+:' "$work_dir/verify.out" | grep -Eiq 'TWCA|TAIWAN-CA'; then
        has_twca=1
    fi
    tls_status='失敗'
    if (( client_exit == 0 && verify_exit == 0 )); then
        tls_status='通過'
    fi
}

classify_twca_risk() {
    event_status=INDETERMINATE
    event_label='無法判定'
    result_exit=2
    if (( recommended )); then
        event_status=REPLACE_RECOMMENDED
        event_label='建議更換並確認'
        if (( official )); then
            event_label='需更換（命中所提供的官方確認資料）'
        fi
    elif (( has_twca )); then
        event_status=REVIEW_REQUIRED
        event_label='需人工確認，不能據此宣告已換新鏈'
    elif [[ $tls_status == '通過' ]]; then
        event_status=NOT_MATCHED
        event_label='本事件未命中（僅限此次端點與資料版本）'
    fi
    if [[ $tls_status == '通過' ]]; then
        if [[ $event_status == NOT_MATCHED ]]; then result_exit=0; else result_exit=1; fi
    fi
}

format_decision() {
    case "$event_status" in
        REPLACE_RECOMMENDED)
            printf '%s\n' '換證結論：❌ 要。請在 2026-11-06 00:00 前完成換證（保守維運期限，+08:00）。'
            if (( official )); then
                printf '%s\n' '原因：命中所提供的官方確認中繼資料。請更換終端憑證及完整中繼鏈。'
            else
                printf '%s\n' '原因：命中 TWCA 問題中繼候選清單，建議換證。'
            fi ;;
        NOT_MATCHED)
            printf '%s\n' '換證結論：✅ 不需要因本次 TWCA 事件在 2026-11-06 前換證。' \
                '原因：此次端點未見 TWCA 憑證鏈，且 TLS 驗證通過。' ;;
        REVIEW_REQUIRED)
            printf '%s\n' '換證結論：無法確定。請在 2026-11-06 前向 TWCA 確認；未確認前按需換證處理。' \
                '原因：使用 TWCA 憑證，但目前證據不足以確認已完成換證。' ;;
        *)
            printf '%s\n' '換證結論：無法判定。請在 2026-11-06 前完成確認。' \
                '原因：TLS 驗證失敗，不能判定為不需換證。' ;;
    esac
}

format_report() {
    printf '目標：%s\n' "$target"
    format_decision
    if [[ $tls_status != '通過' ]]; then
        printf '%s\n' '另有問題：TLS 驗證失敗，請立即處理；不影響上述換證建議。'
    fi
    [[ ${verbose:-0} == 1 ]] || return 0
    printf '\n'
    local peer_address
    peer_address=$(sed -n '/^Connecting to /{s/^Connecting to //;p;q;}' "$work_dir/client.err")
    printf '目標：%s\n連線端點／SNI：%s:%s / %s\n檢查時間：%s\nOpenSSL：%s\n' "$target" "$host" "$port" "$host" "$checked_at" "$openssl_version"
    printf '實際連線 IP：%s\n' "${peer_address:-OpenSSL 未提供}"
    printf 'CA 基準：%s\n中繼資料：%s（%s 筆）\n' "${ca_file:-OpenSSL 預設 CA store（非 macOS Keychain 或瀏覽器信任庫）}" "$data_file" "$(wc -l < "$work_dir/data.tsv" | tr -d ' ')"
    printf '事件判定：%s（%s）\nTLS：%s\n撤銷狀態：未檢查（未執行 OCSP／CRL）\n' "$event_status" "$event_label" "$tls_status"
    printf '%s\n' '期限：公告為 2026-11-06 00:00，未載時區；維運保守採 +08:00，不代表已確認撤銷時間。'
    if [[ -s $work_dir/matches ]]; then
        printf '\n%s\n' '命中資料（SHA-256、名稱、證據類別、來源、查核時間）：'
        cat "$work_dir/matches"
    fi
    printf '\n%s\n' '資料版本（公開候選清單不等於官方完整撤銷名單）：'
    awk -F '\t' '{print $2 " | " $3 " | " $5}' "$work_dir/data.tsv"
    cat "$work_dir/summary"
    printf '\n%s\n' '保存鏈的嚴格驗證結果（主機名、用途、有效期間與本機信任路徑）：'
    cat "$work_dir/verify.out"
    if [[ $tls_status != '通過' ]]; then
        printf '\n%s\n' '連線診斷：'
        tail -n 12 "$work_dir/client.err"
        printf '%s\n' '無法建構信任路徑可能是缺中繼或本機缺信任根；此工具不自動下載 AIA，不能一概認定伺服器缺鏈。'
    fi
    if (( has_twca )); then
        printf '\n%s\n' '下一步：向 TWCA／憑證管理者確認新舊指紋；於實際 TLS 終止層更新重簽的終端憑證及完整中繼鏈，不能只補中繼。'
    fi
    printf '\n%s\n' '限制：取證握手不是信任驗證；伺服器送出的集合不是唯一驗證路徑；未涵蓋重新導向、其他 CDN／LB 節點、App pinning 或瀏覽器撤信政策。'
}

check_file() {
    local entry report site_exit batch_exit=0 count=0
    local site_args=(--timeout "$timeout_seconds" --data-file "$data_file")
    [[ -f $input_file && -r $input_file ]] || fail '無法讀取網站清單檔案。'
    if [[ -n $ca_file ]]; then site_args+=(--ca-file "$ca_file"); fi
    if [[ $verbose == 1 ]]; then site_args+=(--verbose); fi
    while IFS= read -r -u 3 entry || [[ -n $entry ]]; do
        entry=${entry#"${entry%%[![:space:]]*}"}
        entry=${entry%"${entry##*[![:space:]]}"}
        case "$entry" in ''|\#*) continue ;; esac
        if (( count > 0 )); then printf '\n'; fi
        count=$((count + 1))
        site_exit=0
        report=$(/bin/bash "$script_dir/check-twca-cert.sh" "${site_args[@]}" -- "$entry" < /dev/null 3<&- 2>&1) || site_exit=$?
        if [[ $report != '目標：'* ]]; then printf '目標：%s\n' "$entry"; fi
        printf '%s\n' "$report"
        if (( site_exit > 2 )); then site_exit=2; fi
        if (( site_exit > batch_exit )); then batch_exit=$site_exit; fi
    done 3< "$input_file"
    (( count > 0 )) || fail '網站清單沒有可檢查的連結。'
    return "$batch_exit"
}

main() {
    target=''
    input_file=''
    ca_file=''
    verbose=0
    timeout_seconds=15
    script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
    data_file=$script_dir/data/twca-intermediates.tsv
    openssl_bin=${OPENSSL_BIN:-openssl}
    while (( $# > 0 )); do
        case "$1" in
            --help|-h) usage; return 0 ;;
            --verbose) verbose=1; shift ;;
            --)
                shift
                (( $# == 1 )) && [[ -z $target ]] || fail '一次只接受一個網站。'
                target=$1
                shift ;;
                --file|-f|--ca-file|--timeout|--data-file)
                (( $# >= 2 )) || fail "$1 缺少參數。"
                case "$1" in
                    --file|-f) [[ -z $input_file && -n $2 ]] || fail '請指定一份非空的網站清單路徑。'; input_file=$2 ;;
                    --ca-file) ca_file=$2 ;;
                    --timeout) timeout_seconds=$2 ;;
                    --data-file) data_file=$2 ;;
                esac
                shift 2 ;;
            -*) fail "不認得的選項：$1" ;;
            *) [[ -z $target ]] || fail '一次只接受一個網站。'; target=$1; shift ;;
        esac
    done
    [[ -z $input_file || -z $target ]] || fail '--file/-f 不可與單站參數同時使用。'
    [[ -n $target || -n $input_file ]] || { usage >&2; exit 2; }
    [[ $timeout_seconds =~ ^[1-9][0-9]{0,2}$ ]] || fail '逾時秒數必須是 1 到 300。'
    (( timeout_seconds <= 300 )) || fail '逾時秒數必須是 1 到 300。'
    [[ -z $ca_file || -r $ca_file ]] || fail '無法讀取指定的 CA 檔案。'
    if [[ -n $input_file ]]; then
        check_file
        return $?
    fi
    parse_target
    check_dependencies
    work_dir=$(mktemp -d "${TMPDIR:-/tmp}/twca-check.XXXXXXXX") || fail '無法建立暫存目錄。'
    trap cleanup EXIT
    trap 'exit 2' INT TERM HUP
    checked_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    load_data
    run_with_timeout "$openssl_bin" s_client -connect "$host:$port" -servername "$host" -showcerts -verify_hostname "$host" -purpose sslserver
    if [[ -f $work_dir/timed-out ]]; then
        fail "TLS 連線超過 ${timeout_seconds} 秒。"
    fi
    if [[ $verbose == 1 ]] && ! grep -q -- '-----BEGIN CERTIFICATE-----' "$work_dir/client.out"; then
        tail -n 12 "$work_dir/client.err" >&2
    fi
    extract_certificates
    inspect_certificates
    verify_tls
    classify_twca_risk
    format_report
    return "$result_exit"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi