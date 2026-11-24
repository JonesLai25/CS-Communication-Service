# Phase 2 設計與範圍

本階段以 Linux-only 修正為準，保留 Phase 1 TLS 1.3、受限 session 及 SQLite 交易。Enrollment OTP 是供人類安全轉交、256-bit 隨機單次註冊授權；Transfer OTP 是 Phase 3 的傳輸密鑰，兩者互不共用、不同生命週期。OTP 以 SHA-256 雜湊保存，綁定 owner、期限（30–3600 秒），每次最多註冊一個 device，過期／撤銷／停用後拒絕；核銷與雙公鑰寫入在同一 SQLite `BEGIN IMMEDIATE` 交易中完成，並行只有一筆成功。

Client 先驗證 TLS 身分，再送 owner/device、Ed25519 和 X25519 公鑰。Server 回傳一次性 nonce 與臨時 X25519 公鑰，綁定此 TLS exporter；Client 對版本、用途、Server 憑證摘要、TLS context、nonce、owner、device、兩個 Client 公鑰、Server 臨時公鑰和 OTP 摘要的長度前綴 transcript 做 Ed25519 簽章，並以 X25519 shared secret、HKDF-SHA256 衍生金鑰對 transcript 產生 HMAC-SHA256，證明兩把私鑰持有。Server 驗證後才原子註冊；每條連線只能完成一次該流程，跨 session 重放失效。Server 不保存 Client 私鑰，也不將 OTP 明文、密鑰或 transcript 寫入稽核。這是受保護 TLS 內的公鑰註冊，非 Transfer OTP 與檔案加密實作。

本機管理面使用受保護的 Unix socket，父目錄須由服務 UID 擁有且 0700、socket 0600，核對 Linux `SO_PEERCRED` 對端 UID，並以 flock 保護 socket 建立及 stale socket 恢復。此版本授權服務帳號的同 UID 本機管理員；同 UID 的本機惡意程序不在 User Mode 隔離保證內。支援使用者新增／列出／停用、OTP 發行／撤銷、裝置列出／撤銷。系統級安裝、跨 UID 管理員與授權群組仍屬 Phase 6，不能視作已完成。

Client CLI 在聯網之前以 0600 建立 Ed25519 和 X25519 私鑰、fsync 並保留於 0700 目錄；OTP 透過隱藏輸入而非命令列傳入。註冊回應遺失為 unknown，保留金鑰，`--resume` 先使用該金鑰重新認證，無法證實已註冊才允許重新輸入授權碼，不自動重放註冊。現有 Phase 1 資料庫啟動時透過交易新增使用者、OTP 和 X25519 欄位；現有 device 不會自動取得 X25519 金鑰，檔案傳輸不得對其假設已具備加密金鑰。

執行與驗收僅使用本機隔離、臨時測試資料；Phase 2 的局部測試與完整產品驗收分別標記，見 PHASE_2_STAGE_REPORT.md 和 ACCEPTANCE_MATRIX.md。

每次實際測試操作及結果查詢，除了 session 入口檢查，也在同一 SQLite 交易中重查使用者和裝置啟用狀態；撤銷與操作依資料庫交易順序決定，避免先檢查、後執行期間跨過撤銷。管理介面的裝置列表顯示簽章及加密公鑰 SHA-256 指紋，不顯示私鑰或 OTP 雜湊。階段性 CLI 以 `python3 phase1/admin_cli.py --socket <socket> <operation>` 操作；註冊使用 `python3 phase1/enroll_cli.py --port <port> --ca <trusted-cert> --owner <user> --device <id> --credential-dir <private-dir>`，OTP 由隱藏提示輸入。所有例子僅用於本機測試，系統安裝與對外部署未完成。
