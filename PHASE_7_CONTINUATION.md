# Phase 7 儲存治理後續

本文件更新 `PHASE_7_FINAL_REPORT.md` 中將 `storage_capacity_mib` 描述為可選的舊狀態；產品驗收仍未結案。

正式 Server 啟動必須提供 `storage_capacity_mib`，依 kernel 的檔案系統總容量確認資料庫及其 WAL、接收資料、套件、續傳、工作區與管理 socket 均位於同一私有且受限的檔案系統；不符合條件直接拒絕啟動。服務運行時重新檢查路徑及容量，新傳輸、封裝及命令必須保留至少 512 MiB 可用空間。邊界改變時維護、管理及資料操作 fail closed；低空間時健康檢查不報正常，新寫入拒絕，已驗證邊界的查詢及取消不主動因保留空間而封鎖。所有直接 Server 入口也必須指定上限，沒有正式繞過參數。管理者需先建立真正有界的檔案系統；CS 不建立或修改宿主 quota。單一檔案系統容量是共享總量硬上限，不是每使用者配額，也不能保證其他資料不搶占空間。

Client 上下載及續傳 CLI 也必須指定私有暫存位置與 `--staging-capacity-mib`，並驗證底層檔案系統容量與 512 MiB 保留；下載目的地必須與 Client 暫存位於同一有界檔案系統，因解密發布會在目的地建立暫存；已發布使用者資料保留，不自動刪除。`cs-client cleanup` 需明確指定目錄與 Transfer ID，取得排他鎖並先驗證所有候選檔案，才刪除可識別的加密暫存；不刪除目的地、其他檔案、Request ID 或 manifest。上傳準備與續傳均持鎖，新版會寫入 transfer marker 讓準備中斷後可識別清理；舊的尚無 manifest／marker 暫存不會被猜測刪除。

SQLite 連線啟用 secure_delete；已完成結果依期限清除內容但保留 Request ID／摘要／裝置墓碑，不刪除 unknown 或重放防護紀錄。SQLite、WAL、結果及墓碑受上述 OS 檔案系統容量控制，但資料庫自由頁、WAL 和備份不能視為已安全抹除，也不自動執行需要額外空間的 VACUUM。過期 Transfer OTP、續傳與 outgoing package 採有上限批次清理；已發布的使用者資料保留，不因磁碟不足自動刪除。journald 為宿主管理者負責的獨立政策，並非此檔案系統配額的一部分。

可重現依賴：發行包包含 Python 3.12 x86-64 manylinux2014 鎖定 wheel；另提供持久化、原始 hash 已核驗的 CPython 3.12.16 離線 runtime，詳見 `evidence/phase7-runtime-offline.txt`。runtime 使用者應維護來源、授權及安全更新。Windows OUT_OF_SCOPE。

證據和影響：儲存守衛、低空間 HTTP 安全拒絕、加密暫存鎖和識別、分批密鑰到期及 Request ID 防重送見 `evidence/phase7-budget-storage-controls-verified.txt`；Ubuntu 20.04 續傳回歸見本次最終測試輸出。Phase 5 Sandbox 核心、HPKE、TLS 密碼協定及虛擬硬體沒有修改，其既有負向控制仍適用；因 CLI、Server 入口及資料庫維護有修改，需重新驗證實際新版發行檔與相應端對端流程。此前的原生 System Mode、實體掉電與獨立安全審查不能因這些測試而改為通過。

VM 最小需求：現有 384 MiB 客體資料碟無法滿足產品要求的「512 MiB 可用空間＋預留＋封裝」，所需邏輯容量必須大於該和並再容納檔案系統 metadata 和測試資料；640 MiB 僅為待驗證估算，非已驗證需求。既有 512 MiB 測試磁碟上限並未提高，沒有再重複失敗方案；見 `evidence/phase7-vm-minimum-resource.txt`。

## 本次可交付基準及測試

產品發行檔以 Git `8d41e158ad2dc786336029b0de2bd918a21ab14e` 建置：`CS-linux-x86_64-8d41e15.zip`，SHA-256 `694df543d8abf3cd9b0ab2104e371144147798143d49495d80034fe18a9c775d`；來源及 wheel 清單見 `evidence/phase7-budget-release-current-integrity.txt`。實際新版安裝與完整端對端見 `evidence/phase7-budget-release-e2e-final.txt`；Ubuntu 20.04 使用者空間實際安裝、容量不足拒絕及隔離 tmpfs 真正 ENOSPC／SQLite WAL 事務回滾與完整性檢查見 `evidence/phase7-budget-release-sqlite-full.txt`。後者是隔離容器，不代表實體裝置掉電驗證。原始錯誤測試假物件之失敗及修正後結果分別保留於 `evidence/phase7-budget-storage-resume-final.txt`、`evidence/phase7-budget-storage-resume-retry.txt`。

本次變更涉及服務儲存前置、Client 續傳與本機清理、Registry 的 SQLite secure_delete 和有限批次到期清理；因此重新驗證受影響的儲存／續傳、安全拒絕與實際發行檔。未修改 TLS 握手實作、HPKE 算法或 Sandbox 邊界；其前期錯誤憑證、標準向量及突變負向控制保留有效，但不取代新版端對端驗證或獨立安全審查。最新發行檔的隔離副本竄改必須被拒絕，見 `evidence/phase7-budget-release-mutation-current.txt`。

目前 Server 和 Client 的強制檢查依賴 kernel `statvfs` 回報的**整個檔案系統**總容量；若只是對大檔案系統套用 per-user／project quota、但總容量仍超過設定，本版會保守拒絕，不聲稱已驗證這類 quota。設定值大於或等於檔案系統容量只是邊界檢查，不證明該檔案系統是專供 CS，管理者仍須確保隔離及額外容量策略。宿主 journald 與 Client 已發布目的地／備份由管理者負責；CS 不清理宿主共用日誌。

外部驗收仍為 UNVERIFIED：Ubuntu 20.04／22.04 原生 System Mode、實體裝置掉電、跨實體主機與真正獨立安全審查。受限 VM 衝突及最小需求見 `evidence/phase7-vm-minimum-resource.txt`；需管理者提供符合限制的專用隔離環境，或明確授權調整專用 VM 的磁碟上限，方可在不繞過 512 MiB 安全保留的情況下繼續。這些屬 P21-B／D／E 的外部資源及安全邊界，不能以本機容器或自我測試冒充通過。

依賴供應核對補充：獨立 runtime 檔與原始上游摘要一致；首次將本機既有 runtime 全部 regular files 與 archive 比對時，三個自動產生的 `.pyc` 不同，該命令又因後續 `cat` 掩蓋 Python 退出碼，不能算通過。已保留原輸出，重新以非快取 regular files 比對 3519 筆、零差異，見 `evidence/phase7-runtime-payload-integrity.txt` 及 `evidence/phase7-runtime-payload-retry.txt`。
