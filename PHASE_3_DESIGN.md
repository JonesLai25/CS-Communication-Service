# Phase 3 設計與操作邊界（進行中）

本階段實作預設仍只監聽 loopback、拒絕 root；不是正式部署。`--transfer-master` 指向服務 UID 所有且權限 0600 的 32-byte 隨機檔，`--transfer-root` 為該 UID 所有、0700 的私人接收根目錄，`--package-root` 為另一個同樣受保護的套件根目錄；缺少相依參數時伺服器拒絕啟動相應功能。主金鑰及 TLS 憑證身分必須保持穩定，現階段未提供輪換。

註冊使用者及裝置先經 Phase 1／2 TLS exporter 與 Ed25519 認證。Server 對已啟用的 X25519 裝置核發單次傳輸專用 256-bit Transfer OTP，使用 RFC 9180 HPKE X25519/HKDF-SHA256/AES-256-GCM 封裝。HPKE 的認證資料包含 Server 憑證身分、owner、device、Transfer ID、方向；下載另外綁定 Package ID。Enrollment OTP 的資料表、生命週期與用途獨立。沒有 X25519 公鑰的舊裝置必須拒絕核發；不得降級到明文或其他使用者的金鑰。

Client 建立受限 tar 檔案樹，使用獨立的 Zstandard 分塊，再以 Transfer OTP 衍生的 AES-256-GCM 串流加密。每次封裝使用隨機 salt 衍生獨立金鑰，逐塊認證序號、型別及內容，尾端認證總長、塊數及摘要。伺服器在 0700 staging 完整驗證、解壓、拒絕路徑穿越、連結及特殊檔，再以 `renameat2(RENAME_NOREPLACE)` 發布；資料庫交易在發布前重新檢查使用者、裝置與傳輸權限。`tarfile` 解析器的擴充標頭在處理前拒絕，避免過大配置。上下載分別以 160 MiB 密文、128 MiB 封裝、單一處理工作、一般連線 6 秒期限、已認證且取得處理槽的操作最多一次延長至 60 秒、3 秒 TLS I/O 閒置期限及 512 MiB 可用空間檢查限制資源；已對 110 MiB 可壓縮及 98 MiB 不可壓縮檔案實測完整 TLS 上下載，峰值見階段證據；取樣磁碟峰值並非硬配額。

已上傳且經授權的來源可建立 Package ID；其索引記錄 owner、來源、大小與摘要，任何目錄路徑皆不可由遠端直接指定。下載獲得獨立 Transfer ID 及 OTP，與 Package ID 不同；同一下載重取相同已驗證密文。有效下載引用阻止人工刪除。套件預設 24 小時到期，維護工作每 60 秒清理到期傳輸密鑰、密文及套件；維護失敗須重新嘗試。這些局部流程尚未證明掉電一致性、全部故障恢復或正式系統的 quota 管理。

CLI 見 `phase1/transfer_cli.py --help`。Client 透過 `upload` 自動核發及解封 key、封裝並上傳；`package-create` 將已授權上傳的 Transfer ID 轉為獨立 Package ID；`download` 自動核發及解封 key，下載到私人 staging 驗證後發布於目的根目錄下的下載 Transfer ID。命令輸出不含 key；不明結果保留已輸出的 Request ID／Transfer ID，應以查詢命令確認，不自動盲目重送。

目前沒有斷點續傳、掉電恢復或跨進程 reconciliation；中斷不代表已提交。Phase 4 須完成不可變來源 Manifest、持久區塊進度、重啟協調、原子持久發布、取消／過期邊界與失敗注入驗收。此文件及本地原型、局部功能測試均不代表產品安全驗收通過。現行測試狀態與限制見 PHASE_3_WORK_IN_PROGRESS.md。
