# CS Client 操作

先安全取得 Server CA／TLS 身分並確認 hostname，再向管理者取得 Enrollment OTP。`$CLIENT` 為 `PREFIX/bin/cs-client`，`$CA` 為可信 CA，`$CRED` 為使用者私有憑證目錄；OTP 從標準輸入讀取，不應出現在命令列或日誌。

```sh
"$CLIENT" enroll --port 18443 --ca "$CA" --owner alice --device laptop --credential-dir "$CRED"
```

後續通訊以同一組 `--host HOST --port 18443 --ca "$CA" --owner alice --device laptop --credential-dir "$CRED"` 參數連線。使用 `transfer --help` 上傳、建立 outgoing package 及下載；使用 `resume --help` 上下載續傳、查詢及取消。Package ID 與 Transfer ID 用途不同；保留 Client 私有續傳目錄與原始封裝，不能以相同 key／nonce 對修改後內容重新加密。

使用 `exec ... run --timeout 30 -- COMMAND ARGS...` 執行、`exec ... submit` 非同步提交，再以 `exec ... status REQUEST_ID`、`wait REQUEST_ID` 或 `cancel REQUEST_ID` 查詢與取消。連線中斷導致結果未知時保留 Request ID 並先查詢；不可盲目重送有副作用的命令。取消和結果只允許授權身分操作，逾時或不具安全隔離條件時命令不會以無隔離方式執行。

已終結的命令結果超過管理者設定的保留期限後回報 `expired`，不再提供命令輸出；同一 Request ID 仍不會再次執行。`unknown` 結果須保留並由使用者或管理者處理，不應盲目重送。

完成傳輸或確認不再需要續傳後，可明確執行 `"$CLIENT" cleanup --directory "$RESUME_DIR" --transfer-id "$TRANSFER_ID"` 清除該目錄中可識別的加密暫存；此操作不刪除已發布內容、request 或 manifest。清理會取得排他鎖，遇到進行中的續傳或不安全檔案時拒絕；在清理前確認不再需要該加密封裝。Client 資料及暫存需放在管理者配置的受限檔案系統，並由各使用者負責容量與保留。

上傳／下載必須明確提供私有 `--staging-dir` 和 `--staging-capacity-mib`；續傳上下載必須提供 `--staging-capacity-mib`，其續傳目錄或父目錄必須為同一受限檔案系統上的私有目錄。缺少設定、檔案系統容量超過設定、或可用空間低於 512 MiB 時，Client 會在開始寫入前拒絕。該值驗證的是檔案系統總容量，並非自動建立 quota；下載目的地也必須位於同一受限檔案系統，因解密與原子發布會在目的地建立暫存；發布後的使用者資料保留，仍由使用者及管理者治理。
