# Phase 5 本機階段報告

## 實際完成

以使用者接受的 `60a0c99` 為 Phase 4 基準，實作經 TLS 和裝置認證的命令 submit／query／cancel、同步與非同步 Client CLI、SQLite 原子 Request ID 與持久結果。環境未配置或 sandbox 自檢失敗時拒絕執行；相同 Request ID 不重複啟動，異常中斷標為 unknown，不宣稱任意命令 exactly-once。舊的檔案傳輸與 OTP 邊界維持原狀。

命令以非 root Bubblewrap、隔離 namespaces、無主動 socket 連線、libseccomp、FD／環境白名單與 no-new-privileges 執行；每工作 systemd user scope 限 112 MiB RAM、32 MiB swap、32 tasks 和一 CPU。檔案先複製至該 cgroup 的 tmpfs，限制工作區 16 MiB／512 項／深度 16；檢查後以持久 marker、fsync 和原子交換發布。逾時、取消、輸出超限及程序異常不發布部分工作區。工作程序 PID／啟動時間／boot ID 用於重啟核對，未知結果不自動重跑；SQLite 持續忙碌時先拒絕新工作，再重新核對及自檢後恢復。

## 驗證證據

- `evidence/phase5-security-final.txt`：實際假 Server 私密檔、其他工作區、管理 socket、宿主 loopback、host proc、環境及 FD 隔離；暴露假資料、移除 affinity 和 Unix socket connect 規則的受控突變均被測出。
- `evidence/phase5-worker-verified.txt`（11 項）、`phase5-controller-verified.txt`（8 項）、`phase5-tls-final-security.txt`（2 項）：記憶體、程序數、CPU、輸出與工作區上限；程序樹、timeout、取消、狀態持久化、實際 TLS 重新連線與相同 Request ID 並行測試。測試與工作 scope 同屬唯一測試 slice，實際合計硬上限 192 MiB RAM／128 MiB swap／64 tasks，結束後移除 slice 與暫時設定。
- `evidence/phase5-workspace-sigkill.txt` 及 `phase5-unit-final.txt`：僅對自行建立的測試程序 SIGKILL，驗證原子交換前後的 reconciliation；同時驗證交付位置、Git、SHA-256、資源守門與負向控制。
- `evidence/phase5-regression-phase1.txt`、`phase5-regression-phase3.txt`、`phase5-regression-phase3-mutations.txt`、`phase5-regression-phase4.txt`、`phase5-regression-phase4-mutations.txt`：既有功能與突變控制回歸。首次回歸隔離副本缺新模組的失敗及修復重跑分別保留。
- `evidence/phase5-ubuntu20-final.txt`：獨立 Ubuntu 20.04 使用者空間中的日誌、工作區恢復和 Client Schema 單元測試；不冒稱在 Ubuntu 20.04 原生核心完成 sandbox 驗收。本機完整 Sandbox／TLS 驗證使用 Ubuntu 22.04.3 LTS。

## 誠實保留的限制

本機階段驗證不代表正式產品安全驗收。Phase 4 的超額測試配置、虛擬電源中斷、實體儲存設備掉電，以及 Phase 5 的虛擬／實體掉電、原生安裝與獨立安全審查維持 UNVERIFIED，依使用者指示移交 Phase 7。Phase 5 自我審查另發現初期測試 controller 與 job 是同層 scope，配置上限不能只看單一 scope；聚合硬限制及測試 slice 的暫時設定清理皆已修復，失敗與重驗證記錄保留。

工作區不接受 symlink、硬連結、特殊檔，主動 Socket 連線均被禁止；命令輸出合計限 2048 bytes。命令日誌有數量上限但尚無完整自動保留及清理政策；全產品持久磁碟硬配額、安裝與獨立安全審查移交後續。若安全能力或資料狀態無法驗證，執行維持拒絕。

## 交付驗收

Phase 4 審查包最初放在暫存位置是交付缺陷，已移至專案旁並核對雜湊；事件、修復與負向測試已保存。Phase 5 審查包應由 `tools/deliver_review.py 5` 在乾淨 commit 後直接輸出至專案父目錄；工具檢查持久檔案系統、Git 基準、ZIP 全量 SHA-256、排除項目以及 fsync，完成後才回報。

P21-A：上述 Phase 5 本機功能、故障注入、負向控制與必要回歸已完成，提交本機階段成果；沒有將未完成的 Phase 7 產品級驗收標記通過。

Phase 5 第一次正式交付嘗試在 `3bab709` 後被自動檢查拒絕：匯出 metadata 的 Git SHA 多了一個換行，導致交付驗證器與匯出器格式不一致；沒有保留未驗證的包。已修正並加入以實際匯出器輸出餵入交付驗證器的整合測試；失敗與重驗證證據見 `evidence/phase5-delivery-initial-failure.txt` 和 `evidence/phase5-delivery-recovery-tests.txt`。

交付修復亦改為先在同一持久目的地下的私有目錄完整匯出、核對並同步，再以不可覆寫方式原子發布正式檔名；測試包含目的檔已存在時不得覆寫，以及 tmpfs／暫存路徑拒絕。
