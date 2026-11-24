# 測試計畫

每項需求在 ACCEPTANCE_MATRIX 有可證偽結果及狀態。證據保留執行版本、平台、測試命令、時間、非機密輸出及失敗診斷；PASS 必須有實測證據。先測單元及資料交易，再用獨立進程啟動真實 TLS server/client 做整合與協定互通；mock 不代替端到端。

安全反向測試包括不可信憑證、錯誤/重用/過期 OTP、偽造簽章、撤銷後操作、跨使用者存取、沙箱讀取私鑰/socket/他人 workspace、symlink 與壓縮炸彈、錯誤 key、修改/重排/重放 chunk。注入斷網、SIGKILL、斷電等價持久化邊界、磁碟滿、損壞及權限變更；確認沒有部分提交、重複副作用或誤報成功。真實 Ubuntu 20.04/22.04 執行平台測試；Windows 為 OUT_OF_SCOPE，安裝/升級/回滾/移除使用隔離 VM；自動化測試不得更改正式服務。每個失敗需保存證據，修復後重跑有關測試。

## 永久測試環境安全限制

禁止關閉、重啟或暫停實體主機，禁止 reboot、shutdown、poweroff 等主機電源命令；不得停止或重啟既有 Job Manager、SSH、網路或其他非本專案服務。SIGKILL 僅可作用於本次測試自行建立且已確認身分的程序；網路中斷只針對測試連線，不得關閉主機網路介面。磁碟滿、部分寫入、資料損毀與掉電優先以故障注入、隔離目錄或 VM 模擬；真正的 OS 重啟／斷電僅限專用隔離 VM，且不得影響宿主。無法安全建立環境時標記 UNVERIFIED 或 BLOCKED，不擴大範圍。模擬與實體掉電驗收須分別記錄。所有測試子程序必須有啟動和執行期限，超時時僅清理自行建立的程序。

## 驗收工具的負向控制

重要安全及恢復測試必須在隔離、可清理的測試資料上注入已知違規，確認檢查能失敗；至少涵蓋暴露假私密資料、修改封裝、竄改區塊、不可信憑證和錯誤 hostname、以及非預期例外。測試控制不得修改正式程式或部署環境。具體已測案例與不足見 CODE_REVIEW_001.md。

CR-017–022 回歸包含 135 次受限連線的 session 回收、冒用同裝置 challenge 的公平性、全域上限、惡意 HTTP 標頭、回應 framing、SQLite 讀寫故障分類與禁止明文隱式重連；負向控制只改暫存副本。所有失敗測試輸出及修復後的重跑結果分別保存，見 CODE_REVIEW_003.md。

## P22 Local First

測試優先使用本機可重建隔離環境，按 ENGINEERING_CHARTER.md 的 P22 執行。記錄 CPU、記憶體、Swap、磁碟與網路使用界線；模擬、容器、虛擬機及實體平台證據分別記錄。缺少某平台環境只阻擋該平台測試，不得阻止可在本機完成的驗證。

Phase 2 增加真實 TLS 註冊、Enrollment OTP 錯誤／過期／撤銷／重用／並行核銷、兩種私鑰持有證明、使用者／裝置停用、同 UID 管理 socket 與真實跨 UID 拒絕、回應遺失後重新認證、Phase 1 資料庫遷移、CLI 私鑰權限和受控驗證突變。既有測試必須在不擴大宿主權限的隔離環境回歸；Ubuntu 20.04 使用者空間與宿主 22.04 庫環境分別記錄，不代表原生核心或完整產品驗收。

Phase 3 本機驗證：`tools/local_container.sh phase1`、`tools/local_container.sh phase3`、`tools/local_container.sh phase3-mutations`、`tools/ubuntu20_phase3_test.sh`、`tools/netns_phase3.sh`、`tools/run_phase3_large.sh` 及 `tools/run_phase3_large.sh incompressible`。測試僅操作新建之隔離資料與可辨識測試程序，遵守本文件既有永久限制；不得修改宿主網路、停止其他服務、使用 sudo 或重啟宿主。測試命令與實際輸出見 PHASE_3_STAGE_REPORT.md 和 evidence。大檔暫存空間為測試期間取樣，非全系統硬配額；測試模擬不等於實體掉電驗收。

## Phase 4 續傳及崩潰驗證

以真實 TLS 和受認證裝置測上傳／下載，包含中斷後人工續傳、受控暫時失敗後查詢再自動續傳、Server 重啟、取消／逾期、不可變 Manifest 與金鑰／context 不匹配、區塊遺失、交換、損毀、部分寫入、磁碟滿與 fsync 失敗。負向控制在隔離副本中變更 Manifest、區塊及金鑰，測試必須偵測；測試使用 unittest，在 Python `-O` 下仍有效。VM 測試只終止測試自行啟動的專屬 QEMU，禁止操作宿主機電源或其他程序。虛擬磁碟斷電模型、程序 SIGKILL 與實體裝置掉電結果分開記錄；VM 模擬不得宣稱實體掉電驗收通過。

## P06：交付驗收

正式交付須符合工作目的：產生、測試或報告成功均不自動等於需求與驗收成功；故障修復後須恢復原工作。Review Package 以 `tools/deliver_review.py` 在專案旁的持久化位置交付，檢查乾淨 Git 基準、非 tmpfs/ramfs、檔案清單與 SHA-256、排除秘密和暫存，並同步檔案與目錄。暫存檔不是正式交付；保留錯誤、修復與重驗證紀錄。

## Phase 5 Sandbox 與命令執行

以真實非 root Bubblewrap、seccomp 和每工作 cgroup，直接嘗試讀取本次建立的假 Server 私密檔、連線管理 Socket、寫入另一使用者工作區、連線宿主 loopback、讀取 host proc、繼承環境變數與 FD；在隔離測試中故意暴露假資料或移除 affinity seccomp 規則，驗證控制能偵測。另測 CPU affinity、記憶體、程序數、輸出和工作區容量，僅操作測試建立的程序；驗證程序樹清理、逾時、取消、原子發布兩側的 SIGKILL、Server 中斷、重新連線查詢、並行相同 Request ID 及 sandbox 自檢失敗拒絕。實體掉電與虛擬電源中斷另列 Phase 7，不由程序 SIGKILL 或模擬替代。

Phase 5 含 systemd 同層工作 scope；單獨檢查外層不足以限制總量。測試控制 scope 上限 80 MiB RAM／96 MiB swap／32 tasks，單一工作 scope 上限 112 MiB／32 MiB swap／32 tasks；合計不得超過既有 192 MiB／128 MiB swap／64 tasks，均限同一 CPU。工具與工作本身均驗證實際 cgroup，單一工作由 SQLite 原子 admission 限制。先前配置總上限超額的診斷與修復保留在 `evidence/phase5-combined-budget-incident.txt`。

上述 Phase 5 控制與工作 scope 均位於一次性、測試專屬 user slice，其自身的 memory.max、memory.swap.max、pids.max 硬限制總量；測試和工作程序均驗證實際 slice 成員資格及上限。即使工作數 admission 出錯，仍不能使總量突破 slice 限制；結束只移除本次建立的 slice。

交付工具先在持久目的地的私有暫存目錄完成匯出、完整驗證及 fsync，再以不可覆寫硬連結原子發布正式檔名並同步目的目錄；中途失敗不得留下看似完成的正式檔。匯出器與交付驗證器須以真實輸出格式做整合測試，程序包裝亦須保留失敗退出碼。
