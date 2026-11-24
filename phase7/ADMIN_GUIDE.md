# CS 管理與操作

Server 以非 root 執行，管理命令必須以擁有私有管理 socket 的服務身分執行。以下 `$PREFIX` 指安裝位置；System Mode 請由管理者以服務身分執行本機 admin 動作，不得將遠端管理端口暴露成替代方案。

```sh
"$PREFIX/bin/cs-server" admin user_add --owner alice
"$PREFIX/bin/cs-server" admin otp_create --owner alice --ttl 300
"$PREFIX/bin/cs-server" admin device_list --owner alice
"$PREFIX/bin/cs-server" admin device_revoke --owner alice --device laptop
"$PREFIX/bin/cs-server" admin user_disable --owner alice
```

Enrollment OTP 僅供裝置註冊，經可信通道交付並避免記錄；Transfer OTP 由已授權工作階段使用，兩者不能互換。每位需要遠端 exec 的使用者先建立服務身分擁有、0700 的 `data/instance/workspaces/<owner>`；不要將 Server 私鑰、socket 或其他使用者資料放入工作區。

設定 `config/server.json` 與 `config/execution-policy.json` 必須由服務帳號擁有且 0600。執行政策有 RAM、swap、CPU、程序數、工作區與輸出上限；上傳暫存有預留上限；audit 清理按年齡及筆數批次執行。重啟服務以套用調整。已發布資料、package、SQLite/WAL、結果及 systemd journal 目前沒有產品級完整全域硬配額，應以專用檔案系統／受管理 quota、容量告警、備份與依權限審核的保留策略治理；不能以產品內暫存上限取代全域配額。勿直接刪除正在使用的 SQLite、持久結果或活動傳輸。完整一致清理與資料保留政策仍待驗證。

檢查 `cs-server unit status`、系統日誌及 `cs-server health`，並透過認證後的 Client 確認服務功能。日誌由主機 journald 政策治理；不得寫入 OTP、私鑰或明文憑證。發生儲存不足時停止受控寫入、保留證據並依備份及管理政策恢復；不得刪除未知來源的檔案。

必要的 `server.json` 整數 `storage_capacity_mib` 啟用啟動前檢查：管理者須先提供實際容量不超過該值的專用受限檔案系統，且資料庫父目錄、上傳、續傳、package、workspace 與管理 socket 目錄均須位於同一檔案系統、由服務身分私有擁有。設定後若檔案系統容量過大、路徑不安全或跨裝置，Server 直接拒絕啟動。此檢查不建立或修改檔案系統，不設定使用者或目錄配額，不保證管理者後續不改變掛載，也不涵蓋外部 journald 或 Client 檔案；未設定或驗證不通過時 Server 拒絕啟動。傳輸原有的可用空間保留檢查仍會獨立執行。

Server 預設只監聽 `127.0.0.1`。需要直接跨機連線時，管理者可在 `server.json` 明確設定 `"listen":"0.0.0.0"` 或指定 IPv4 位址並重啟服務；這會擴大網路可到達範圍，須由管理者按部署環境設定防火牆。正式 TLS 憑證的 SAN 必須與 Client 驗證的 hostname 一致，預設的 localhost 自簽憑證不能直接用作遠端主機身分。若監聽位址不含 localhost，`cs-server health` 的 localhost 自檢可能無法使用；請以對應位址及可信 hostname 測試。

命令結果預設在終結後保留 90 天；可設定 `exec_result_retention_days`（1–3650）。背景清理以有限批次移除過期輸出、命令本文及 worker 身分，保留 Request ID／雜湊／裝置的最小紀錄並回報 `expired`，以防同一 ID 再次執行。狀態 `unknown` 不會被自動清除。SQLite 已刪除內容可能仍存在未回收的頁面及備份／WAL；此機制不是安全抹除或資料庫檔案大小上限。應另行規劃授權備份、檔案系統 quota 與受控維護。

Server 在新傳輸、封裝及命令等寫入前重新檢查邊界與至少 512 MiB 可用空間；不足時拒絕新操作，取消及查詢不因該預留檢查主動封鎖。內核硬配額仍是強制邊界，作業中若耗盡空間，使用者應保留 Request ID／Transfer ID 並先查詢狀態；不得盲目重試。SQLite 使用 secure_delete，但 WAL、備份及儲存裝置的殘留不保證被抹除。
