# Phase 6 本機階段報告

基準為 Phase 5 `955a986`。本階段建立版本化、離線且鎖定 hash 的 Linux Server／Client 安裝、升級與保留資料的解除安裝；提供非 root User Mode、管理者安裝而服務帳號執行的 System Mode、systemd 單元與明確服務管理。安裝不自行啟動或部署服務，schema 不相容拒絕升級，執行鎖保護解除安裝；執行中升級固定舊版本，重啟後載入新版本。身分、密鑰、資料庫、工作區及已完成結果受到保留。

## 證據與限制

- `evidence/phase6-install-fault-final.txt`：離線安裝、重複安裝、依賴故障、指標切換後故障回復、程式竄改拒絕、在用拒絕解除安裝及資料保留。
- `evidence/phase6-e2e-lock-final.txt`：真實安裝後非 root systemd User Mode，完成 OTP enrollment、認證、加密上下載、Sandbox 遠端命令、升級期間執行版本固定、服務重啟及持久結果查詢；受限 aggregate slice 為 192 MiB，磁碟取樣小於 512 MiB。每使用者工作區由管理者預建 0700。
- `evidence/phase6-system-container-shared-client.txt`：獨立 Ubuntu 20.04 使用者空間的 rootless 容器內，測試管理者安裝、非 root 服務身分及實際啟動、其他非 root 使用者啟動 Client、unit 所有權與禁止以 root 執行。System Mode 管理器狀態及解除註冊測試使用受控 mock；不宣稱原生 systemd system service 已驗收。
- `evidence/phase6-unit-final.txt` 與 `evidence/phase6-policy-controller-initial.txt`：政策解析、權限、預設及調整限制、unit 語法、管理邊界、audit 清理和實際較嚴格命令資源配置。上傳低磁碟及故障情境見 Phase 4 回歸。
- `evidence/phase6-regression-ubuntu20-phase4.txt`：20 項續傳測試通過；`evidence/phase6-regression-ubuntu20-phase3.txt` 為 25 項加密傳輸回歸通過；`evidence/phase6-regression-ubuntu20-phase1-retry.txt` 為獨立認證回歸。`evidence/phase6-regression-ubuntu20-phase1.txt` 的前 31 項認證測試通過，但同容器接續執行續傳時遭限制終止、退出碼 137，整體未通過；分開執行後重新驗證，不提高上限。
- 保留 `evidence/phase6-e2e-initial.txt`（升級時偵測到應用產生 pycache，已修正）、`phase6-system-container-initial.txt`（mock 回傳碼與暫存清理缺陷）、`phase6-system-container-start.txt`（測試程序清理缺陷）及後續重驗。`phase6-system-client-review.txt` 記錄跨使用者執行鎖修正。`phase6-inventory-resource-deviation.txt` 保留一次短暫容器盤點漏設單 CPU affinity 的偏差；後續測試工具強制驗證 affinity。

產品政策與測試預算分離；產品執行資源、上傳預留、audit 保留可設定。已發布資料／package／資料庫與持久結果仍缺完整全域儲存 quota 和自動清理；audit 批次清理及主機 journald 的行為均非硬性總儲存上限。需由管理者監控並於後續階段完成。User Mode systemd 及容器不能取代 Ubuntu 20.04／22.04 原生 System Mode、完整持久儲存配額、虛擬／實體掉電與獨立安全審查；這些保持 UNVERIFIED，移交 Phase 7。Windows OUT_OF_SCOPE。

測試及部署資源界線維持不變；未使用 sudo、未部署宿主正式服務、未更動 Job Manager、其他服務或 ZFS。交付檔須使用 `tools/deliver_review.py 6` 在專案父目錄持久發布，核驗 Git 版本、乾淨工作區、manifest、禁入項目與 SHA-256。

交接停止條件：P21-A，Phase 6 本機階段驗收成果提交使用者。剩餘的產品級驗收與完整全域儲存管理見上文及風險清單，依使用者指示移交 Phase 7；本階段未以其為工程阻塞。平台沙箱原先拒絕存取使用者 bus，改以授權的非 root 測試 scope 執行，見 `evidence/phase6-install-system-refactor.txt` 及重試證據，並非產品測試通過。
