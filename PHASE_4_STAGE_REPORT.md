# Phase 4 本機階段報告

## 範圍與實作

以 Phase 3 核准基準 `1d688fb` 為起點，新增受認證 TLS 上下載續傳：固定 Transfer ID／Package ID、原始壓縮快照與密文 Manifest、分塊進度日誌、有限自動重試與人工續傳。續傳重用原密文；金鑰不寫入本機續傳目錄，以原 Request ID 重新取得原授權。Enrollment OTP 保持獨立，無 X25519 裝置維持拒絕。完成取消、過期、不可恢復失敗清理、磁碟空間檢查、384 MiB 未完成上傳預留總額、原子發布與啟動 reconciliation；規格及使用限制見 PHASE_4_DESIGN.md。

## 驗證與證據

- Phase 4 自動測試、負向控制及既有 Phase 1／2／3 回歸見 `evidence/phase4-regression-*`；所有安全測試均使用 unittest／明確例外並在 Python `-O` 執行。
- `evidence/phase4-netns-initial.txt`：兩個獨立 rootless network namespace、兩個 TCP proxy、真實 TLS 及模擬成功但回應遺失後續傳，範圍與資源受限。
- `evidence/phase4-store-cleanup.txt`：低磁碟空間拒絕、預留總額、部分寫入／ENOSPC、fsync 故障、區塊損毀遺失重排、取消與逾期；`phase4-crash-initial.txt` 為僅針對自建程序的 SIGKILL，`phase4-vm-crash-initial.txt` 為獨立 VM 檔案系統模型。
- `evidence/phase4-vm-application-retry3.txt` 記錄專屬無網路 QEMU VM 執行實際 CS 核心、發布前後終止及重啟 reconciliation；此一次重試使用 256 MiB scope，**超過既有 192 MiB 限制**，不作為資源合規驗收。已恢復 192 MiB 上限並另行重驗；失敗及修復日誌均保留。測試只終止自行建立的 VM，沒有操作宿主電源、ZFS、其他程序或服務。

## 限制及移交

本階段本機驗證不代表產品安全或正式部署驗收。實體儲存設備真正掉電、斷電快取及韌體行為尚未驗證；VM 僅模擬虛擬磁碟電源中斷。全產品磁碟硬 quota、離線 Client 暫存過期自動清理、密鑰輪換、原生 Linux 安裝與獨立安全審查移交後續。遠端撤銷與下載 Client 本地發布沒有跨主機原子交易；發布前重驗授權但不聲稱全域即時撤銷。Windows OUT_OF_SCOPE，遠端 exec 持續停用。
- `evidence/phase4-vm-application-192m-retry3.txt` 和 `phase4-vm-application-192m-final.txt`：192 MiB scope 下 QEMU 被該 scope OOM 終止；`phase4-vm-application-192m-tcg.txt` 的 64 MiB guest 未能啟動核心，`phase4-vm-application-192m-final2.txt` 的 80 MiB guest 在期限內未達應用標記。上述為失敗證據，受限 VM 的**實際 CS 應用程式虛擬斷電恢復標記 UNVERIFIED**；不影響已在 144 MiB 執行的 VM 檔案系統模型與自建程序 SIGKILL 證據。不得以 256 MiB 診斷結果取代此限制下的驗收。

本機通過項目為功能、受控故障注入與程序層崩潰恢復的階段驗證；上述 VM 應用層測試及所有產品級驗收維持 UNVERIFIED。未更動既有工程憲章或 ZFS 設定；所有測試資源只屬本次測試，正式遠端 exec 保持停用。

最終驗證：`phase4-verified-phase4.txt` 19 項、`phase4-verified-phase4-mutations.txt` 3 項、`phase4-verified-phase3.txt` 25 項均通過；`phase4-regression-phase1.txt` 31 項及 `phase4-regression-phase3-mutations.txt` 7 項通過。`phase4-ubuntu20-verified.txt` 在獨立 Ubuntu 20.04／glibc 2.31 安裝固定雜湊依賴並通過最終 19 項 Phase 4 測試；`phase4-ubuntu20-final.txt` 另有 31 項 Phase 1／2 回歸。`phase4-netns-final.txt` 是最終雙節點代理鏈驗證。
