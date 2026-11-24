# Phase 3 工作紀錄（歷史過程）

本文件依時間保留開發過程及當時限制；目前本機階段狀態與仍未完成的產品驗收項目以 PHASE_3_STAGE_REPORT.md 為準。

Phase 2 驗收基準 `8bdd06a`。目前已建立 HPKE RFC 9180 封裝核心與向量測試；傳輸身分、方向、Server 身分及 Transfer ID 均為認證資料。裝置沒有 X25519 公鑰、已撤銷、使用者已停用或 owner 不匹配時拒絕。Transfer OTP 與 Enrollment OTP 的資料表、金鑰及用途分離。

TLS 認證連線具備上傳 Transfer OTP 的核發、按 Request ID 查詢、取消；可選 `--transfer-master` 接受服務 UID 擁有且 0600 的 32-byte 檔案。OTP 使用 AES-GCM 存入 SQLite，重啟須使用相同主金鑰與 TLS 伺服器身分。相同 Request ID 核發具交易冪等語義，衝突、逾期及取消拒絕，取消／逾期清理只保留 tombstone；目前無自動背景清理。下載核發已增加套件 ACL 及 Package ID 綁定；完整失敗恢復與產品級驗收仍未完成。

已建立固定 256 KiB 讀取、增量 SHA-256、AES-256-GCM 逐塊認證的壓縮資料串流封裝；每次封裝以隨機 salt 衍生獨立 key，AAD 綁定完整 context、分塊順序與類型，最終認證記錄涵蓋數量、長度與摘要。解密只能寫入私有 staging，完整驗證後另行處理。128 MiB 測試資料在 Zstandard 加密往返管線的峰值 RSS 25,620 KiB；不代表包含檔案樹、網路併發及解壓的整體記憶體驗收。其他測試證據位於 `evidence/phase3-*.txt`。負向突變第一版只移除 AAD context，未觸發測試因 HKDF 仍綁定 context；第二版同時移除兩者後測試正確失敗，相關原始輸出與重驗均保留。

Linux-only 相容性風險：現有 Ubuntu 20.04 獨立容器 Python 3.8、cryptography 44.0.3；目前宿主鎖定 pyhpke 0.6.4 要求 Python >=3.10，pyhpke 0.5.4 允許 Python 3.8 但要求 cryptography <44。已實際核對 wheel metadata，保留既有 lock，並以發行者 SHA-256 驗證獨立 Python 3.12.16；在不借用宿主函式庫的 Ubuntu 20.04/glibc 2.31 容器，以 pyhpke 0.6.4、cryptography 44.0.3 與雜湊鎖定依賴通過既有 31 項及本階段 18 項測試。`tools/ubuntu20_phase3_setup.sh` 和 `tools/ubuntu20_phase3_test.sh` 可重建與重跑，見 evidence/phase3-ubuntu20-py312*.txt；這不等於原生安裝或產品級平台驗收。

新增分塊 Zstandard 壓縮及受限解壓核心；每塊核對內容大小、視窗、總輸出與摘要，並測試加密封裝往返與毀損拒絕。另加入受限 tar 檔案樹封裝及私有 staging 解壓核心，拒絕路徑穿越、符號連結、硬連結、特殊檔、非空 staging、數量和容量超限。新增本機接收 helper：使用私人 staging，依序驗證加密及壓縮、解封檔案樹，並使用 Linux renameat2 NOREPLACE 發布；測試錯誤金鑰、惡意路徑與重複發布。當時這些尚未接入傳輸資料通道；目前已接入，fsync 與崩潰 reconciliation 等產品級驗收仍屬 Phase 4。

當時尚待完成：檔案樹的完整安全與故障驗證、受認證上傳及下載資料通道、outgoing package 建立／索引／ACL 與清理、路徑及 archive 安全、資源限制整體量測、跨程序與平台相容驗證、安全與故障注入、更新 Review Package、完整回歸和階段驗收。Phase 4 仍須持久化續傳、可靠發布與掉電恢復；不能將本階段局部證據標記為產品驗收 PASS。

測試工具診斷：一次 Phase 1 回歸在受測程序仍運行時更新了 shell runner；測試本身 31 項通過，但 shell 讀取已變更腳本導致 wrapper 語法錯誤並回傳非零，見 `evidence/phase3-phase1-wrapper-failure.txt`。固定 runner 後已重新完整執行，結果與清理見 `evidence/phase3-phase1-final-regression.txt`；後續不得在 runner 執行時修改它。

目前可選的本機 TLS 小檔垂直切片以 `--transfer-master` 和 `--transfer-root` 啟用：Client 使用 HPKE 收到的 key，壓縮加密後一次提交最多 2,048 bytes 密文；Server 最多並行 2 個接收，解壓 archive 上限 8 MiB，驗證及交易內再授權後才無覆寫發布。Client 可在重新認證後按 Transfer ID 查詢本機發布結果；回應遺失測試見 `evidence/phase3-tls.txt`。此限制不滿足大檔上下載需求，亦不保證 crash/power-loss 持久性；禁止以此測試標記完整檔案服務 PASS。下載已接入後續實作，見下文。

安全自審在 2026-11-24 發現 tarfile 會在外層迭代檢查之前處理 GNU／PAX 延伸標頭，可能先讀取超大內容；現以 `_StrictTarInfo` 在處理前拒絕非一般檔及目錄型別。超大延伸標頭測試限制實際讀取量，並以隔離突變確認移除此防護會被偵測。這依賴 Python tarfile 的私有 hook，需維持相容性回歸；見 `evidence/phase3-archive-review.txt`。

已加入單次 TLS 串流上傳：輸入密文上限 160 MiB、解壓 tar 上限 128 MiB、單一並行接收，接收根目錄須至少有 512 MiB 可用空間；完整性驗證及授權核對後才發布。2 MiB 實際 TLS 上傳及修改密文拒絕已驗證，程式端以固定大小讀取。一般請求 6 秒期限保留，已認證且取得單一槽的串流操作可延長一次至 60 秒；尚無分段續傳；超時或斷線時不得宣稱完成，應重新認證查詢 Transfer ID。outgoing package 已接入網路，可從已授權上傳成果建立不可變索引、查詢、驗證摘要及清理，並拒絕跨使用者存取；有效下載引用會阻止人工清理。崩潰 reconciliation 尚未完成，該時點尚未完成 Phase 3 本機驗證。

串流容器測試初次失敗因 64 MiB tmpfs 不滿足 512 MiB 空間保護，見 `evidence/phase3-container-stream-initial.txt`；改用測試專用、受限工作範圍且執行後清理的暫存目錄重驗。磁碟型暫存又暴露 SQLite challenge 核銷的忙碌競爭；已改有限重試，重驗及先前失敗分別見 `evidence/phase3-phase1-final-regression.txt` 與 `evidence/phase3-ubuntu20-reclaim-failure.txt`。

Outgoing 元件的首次負向測試暴露初始化前未建立 Transfer Store 資料表；已改為在 package 初始化時明確檢查依賴，修正測試初始化並重驗，見 `evidence/phase3-outgoing-initial.txt` 和 `evidence/phase3-outgoing.txt`。其後已接入 TLS 下載；此局部測試仍不能取代完整下載驗收。

資源保護：一次 Ubuntu 容器回歸期間宿主 MemAvailable 約 196,784 KiB，因此僅向確認為本次測試的 timeout 程序送出 TERM；測試容器結束後可用記憶體回升至約 351,244 KiB，未完成輸出記於 `evidence/phase3-ubuntu20-resource-stop.txt`。殘留於該次專用測試目錄的假憑證及資料庫已清除。後續 runner 的 scope／container 上限降至 144 MiB、啟動前要求宿主至少 300,000 KiB 可用，且在容器清理後遞迴清除該次唯一測試目錄；需重驗，不把中止結果視為通過。

降低上限至 144 MiB 的完整 Ubuntu 回歸仍使宿主 MemAvailable 降至約 193,468 KiB；僅終止本次測試並自動清除該次目錄，見 `evidence/phase3-ubuntu20-resource-stop-144.txt`。改用單獨 Phase 3 測試後，獨立 Ubuntu 20.04 在 144 MiB 限額下通過 20 項，見 `evidence/phase3-ubuntu20-targeted.txt`；本機 Phase 1／2 回歸 31 項通過。`evidence/phase3-ubuntu20-py312.txt` 是本輪較早的完整測試快照，並不冒稱為最新版本的完整回歸。完整 Ubuntu 回歸仍需資源合適時分段執行。

真實 TLS Client API 與 CLI 已可自動申請及 HPKE 解封 Transfer OTP、封裝壓縮、加密上傳，以及建立套件後下載、解密及安全還原。CLI 執行方式為 `python3 phase1/transfer_cli.py --port PORT --ca CA --owner USER --device DEVICE --credential-dir PRIVATE_DIR upload SOURCE_DIR`；使用 `package-create UPLOAD_TRANSFER_ID` 建立 Package ID，再以 `download PACKAGE_ID PRIVATE_DESTINATION_ROOT` 下載。每次操作印出非秘密的 Request ID／Transfer ID，發生不明結果可用 `transfer-result`、`upload-result` 或 `package-result` 查詢，不自動重送。

下載 ciphertext 與已索引 package 具有各自摘要；相同 Transfer ID 重取同一 ciphertext，Package ID 和 Transfer ID 各自獨立。套件預設 24 小時到期；維護執行緒每 60 秒清理過期金鑰、停止對應下載並清理密文與套件。套件與傳輸建立使用交易與 Request ID 去重；進程或磁碟在發佈中斷時仍需要 Phase 4 reconciliation。有限連線期限仍可能使慢速傳輸中斷，尚無區塊進度或續傳，不得視為完整產品驗收。

當時尚待工作項目：驗證最新的雙向 TLS 串流、套件期限與清理、Client CLI、跨使用者與負向控制；重新執行資源受控的 Ubuntu 20.04 和既有功能回歸；檢驗大於記憶體上限的完整端對端流程與磁碟佔用。`evidence/phase3-resource-guard.txt` 記錄主機 MemAvailable 約 220 MiB 時拒絕啟動容器；此前完整 Ubuntu 證據屬較早版本，不代表最新變更已通過。有限連線期限與未實作續傳仍須在 Phase 4 檢驗；完整產品驗收矩陣保持 UNVERIFIED。

已準備 `tools/netns_phase3.sh` 以兩個 rootless network namespace、兩個代理及不同測試 UID 執行加密上下傳並比對摘要；當時尚未執行成功。當次因 MemAvailable 低於 300,000 KiB 在建立 namespace 前即由保護機制拒絕，見 `evidence/phase3-netns-guard.txt`。其後已重新執行通過，見 `evidence/phase3-netns-final.txt`。

## 當時的可恢復狀態與限制

當時基準之後的上下載與 Client 變更尚未完成隔離容器回歸；請以本工作區 Git 狀態及最新 commit 為恢復點。持續檢查主機資源，確認無其他本專案測試程序及資源恢復後，先執行 `./tools/local_container.sh phase3`、`./tools/ubuntu20_phase3_test.sh phase3`、`./tools/netns_phase3.sh`，再分段完成 Phase 1／2 全部回歸、較大檔案完整上下載與受控負向測試；保留每次結果和資源量測。絕不可因跳過測試而標記 Phase 3 完成。

當時已連續兩次於獨立 Ubuntu 完整回歸期間，因宿主可用記憶體降至約 193–197 MiB，終止本次可辨識測試並清除專屬暫存；之後連續觀察約 170–181 MiB，低於 300,000 KiB 測試保護門檻。未發現可安全終止以回收資源的本專案測試殘留。資源門檻、失敗輸出和具體後續步驟見 `evidence/phase3-host-memory-block.txt`；這是本機即時資源條件，不是宣稱產品設計或工具永遠不可行。

管理者已排除記憶體壓力：根因為 ZFS ARC 約 1732 MiB，管理者動態設定 `zfs_arc_max` 為 512 MiB，回報可用 RAM 由 162 MiB 增至 1.4 GiB，未重啟宿主機或終止其他服務。恢復時唯讀核對 MemAvailable 1,409,668 KiB、SwapFree 2,363,908 KiB、上限 536,870,912 bytes，當下 ARC 549,797,688 bytes；數值會隨時間變動。紀錄見 `evidence/phase3-resource-recovery.txt`。繼續維持既定資源保護，不由本專案修改 ZFS 設定。

已認證且取得單一傳輸槽的上傳、套件建立及下載可將連線期限延長一次至 60 秒；一般請求仍為 6 秒、TLS I/O 閒置逾時 3 秒，Client 上下載亦有有限期限。期限無法重複延長，並以隔離突變驗證。先前 98 MiB 不可壓縮檔案在 6 秒期限中斷的證據保留於 `evidence/phase3-large-incompressible-initial.txt`；修正後在 144 MiB scope、單核心下完成實際上下載與摘要比對，Client／Server 峰值 RSS 約 35–36 MiB、取樣暫存邏輯峰值 411,178,742 bytes，見 `evidence/phase3-large-incompressible.txt`。此測試為實際程序中斷及磁碟暫存測試，不代表掉電或 Phase 4 續傳驗收。
