# 安全模型草案

信任界線：遠端未註冊者、已註冊裝置、CS 使用者、CS 管理員、執行沙箱與 OS 管理員均不同。OS root 或同 UID 本機對手不在 User Mode 隔離保證之內；Server 必須能存取解密金鑰，故不是零知識服務。

TLS 1.3 必須驗證 CA/主機名稱或事先透過可信管道配置的 pin，無自動信任或關閉驗證。Enrollment OTP 以安全亂數產生、限時限次且只保存 verifier，註冊與核銷同一交易；Client 對簽章與加密金鑰皆證明持有。後續簽章應綁定一次性 challenge、session、協定版本及請求摘要，防重放；撤銷後新的敏感操作及續傳必須重新檢查授權。

Transfer OTP 是每個 transfer 的 256-bit 隨機金鑰材料，使用標準 HPKE 加密給註冊 X25519 金鑰，與 enrollment OTP 分離。Server master key 應獨立於資料庫、以專屬服務帳號和限制權限保存；持久化金鑰採 AEAD 包裝並綁定 transfer/owner/版本。此措施防止資料庫單獨洩漏，不防止服務帳號或主機被入侵；備份、輪換與金鑰損失恢復策略須先驗證。日誌不得含密鑰、OTP 或私鑰。

候選 bwrap + namespaces、最小唯讀 runtime、僅授權 workspace、隔離網路、受限 proc/dev、資源上限與 no-new-privileges；需額外確認 seccomp、cgroup、行程樹終止、Unix socket 及 /proc 逃逸。只要任一必需能力不足，禁用 exec；不能使用直接 subprocess 作退路。服務自檢不能取代攻擊性測試。可用性與隔離各平台均未證實。

Phase 2 User Mode 本機管理 socket 驗證同 UID 的 Linux `SO_PEERCRED` 與受保護目錄；已對不同 rootless UID 執行實際拒絕測試。同 UID 惡意本機程序及不同 UID 的 system service 管理員授權不在目前隔離保證內，後者歸 Phase 6。Enrollment OTP 是 256-bit 隨機註冊授權，僅以雜湊儲存並限時一次核銷，不得與 Transfer OTP 或檔案加密金鑰混用。詳見 PHASE_2_DESIGN.md。

Phase 5 本機實作以受限 systemd user scope 加 Bubblewrap／libseccomp；所有 `connect`（含 Unix 與 IP）由 seccomp 拒絕，以免可見 runtime 或工作區內的宿主 Socket 成為跨命名空間通道。此限制也排除 sandbox 內的主動 Socket 連線；如環境無法證明必要隔離，exec 拒絕啟用。實作與本機證據見 PHASE_5_DESIGN.md 和 CODE_REVIEW_005.md；此結果不代替獨立安全審查或 Phase 7 驗收。
