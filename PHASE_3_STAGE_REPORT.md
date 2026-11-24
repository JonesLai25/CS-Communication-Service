# Phase 3 本機階段報告

Phase 2 已由使用者以 `8bdd06a` 接受。本階段完成本機範圍的 Transfer OTP、加密檔案上下載、outgoing package 和 Client 自動化切片；這是提出人工階段驗收的結果，不是完整產品或安全驗收通過。原有 Phase 1／2 與 Linux-only 範圍保留。

## 功能與安全邊界

- Server 對已認證、啟用且具 X25519 公鑰的裝置產生 256-bit Transfer OTP；使用 RFC 9180 HPKE 封裝並綁定 Server 身分、使用者、裝置、Transfer ID、方向及下載 Package ID。Enrollment OTP 獨立；舊裝置無 X25519 公鑰時拒絕。
- 使用受限 tar 檔案樹、Zstandard 分塊、增量雜湊及 AES-256-GCM 分塊封裝；Client 自動核發／解封 key、上下載與驗證後還原。私人 staging 拒絕路徑穿越、符號／硬連結、特殊檔、危險擴充標頭及覆寫；失敗不發布。
- Package ID 與 Transfer ID 不同。套件具 owner 索引、Request ID 去重、摘要、授權下載、24 小時期限與清理；有效下載引用阻止人工清理。相同下載 Transfer ID 重取相同 ciphertext。單次傳輸密文上限 160 MiB、解壓 tar 上限 128 MiB，受認證且取得唯一處理槽後連線期限可延長一次至 60 秒；TLS I/O 閒置期限仍為 3 秒。
- 回應遺失時保留 Request ID／Transfer ID 並重新認證查詢，不盲目重送。傳輸、套件與接收結果在過期／取消後的完整跨重啟語義仍須 Phase 4 驗收。

## 實測與受控負向測試

- `evidence/phase3-phase1-resumed.txt`：144 MiB 單核心隔離環境，既有 31 項 Phase 1／2 回歸通過。
- `evidence/phase3-container-final.txt`：最終 Phase 3 本機容器 25 項通過；`evidence/phase3-ubuntu20-final.txt` 中獨立 Ubuntu 20.04、glibc 2.31、Python 3.12 鎖定依賴通過既有 31 項及 Phase 3 25 項；`evidence/phase3-ubuntu20-targeted-final.txt` 另重驗最終 tag 竄改案例。Ubuntu 20.04 容器不代表原生核心／安裝驗收。
- `evidence/phase3-netns-final.txt`：兩個 rootless 私人 network namespace、不同測試 UID、兩層代理完成真實 TLS 加密上下載與摘要比對，不等於跨實體主機。
- `evidence/phase3-large-compressible.txt`：110 MiB 可壓縮檔案完整上下載。`evidence/phase3-large-final.txt`：98 MiB 不可壓縮資料，壓縮包 102,771,639 bytes，完整 TLS 上下載摘要一致；Client／Server 峰值 RSS 36,384／36,608 KiB，均低於 98,304 KiB；scope 144 MiB、單核心，取樣暫存邏輯空間峰值 513,983,181 bytes，小於 536,870,912 bytes。測試僅刪除自行建立的測試來源以維持預算；取樣不是磁碟硬配額。
- `evidence/phase3-mutation-scoped.txt`：隔離副本內七項突變均由測試偵測，包含 AEAD tag 驗證、下載 owner 授權、context 綁定、覆寫、路徑穿越、tar 延伸標頭與期限重複延長。錯誤憑證／hostname、舊 TLS、錯 key、重放、跨使用者、過期與取消、回應遺失和中斷不發布均有對應測試。RFC 9180 向量及非預期 HPKE 例外分類另見 `evidence/phase3-hpke.txt`、`evidence/phase3-hpke-error-classification.txt`。

## 故障與修復

管理者指出宿主 ZFS ARC 佔用約 1732 MiB，並動態將 `zfs_arc_max` 設為 512 MiB；可用 RAM 回升至約 1.4 GiB。只讀核對及處置來源見 `evidence/phase3-resource-recovery.txt`；本專案未修改 ZFS。先前兩次資源保護中止及清理記錄保留。

不可壓縮大檔首次下載遇到 6 秒連線期限，失敗見 `evidence/phase3-large-incompressible-initial.txt`；已改為僅認證並取得唯一槽後允許一次 60 秒延長，保留閒置逾時，重驗見 `evidence/phase3-large-final.txt`。其他失敗與修復，包括 SQLite challenge 清理忙碌、tar 延伸標頭、容器暫存空間門檻及 TLS 下載關閉時序，均保留於 `PHASE_3_WORK_IN_PROGRESS.md` 與對應 evidence。

## 移交與停止條件

- Phase 4：不可變來源 Manifest 與 key／Transfer ID 配對、區塊進度和續傳、自動／手動重試邊界、取消／過期／不可恢復失敗、暫存寫入與 fsync、原子持久發布、崩潰 reconciliation、SIGKILL／部分寫入／損毀／磁碟滿及專用隔離 VM 掉電驗收。**單次傳輸成功不代表續傳或實體掉電驗收通過。**
- Phase 6／7：正式安裝／升級／卸載、原生 Ubuntu 20.04／22.04 與跨實體環境驗收、完整磁碟配額、金鑰輪換、獨立安全審查。Windows 維持 OUT_OF_SCOPE；不整合 Job Manager，不啟用遠端 exec。
- 現階段大小上限及單一處理槽是受限本機實作；磁碟空間為事前檢查與測試取樣，並非全使用者硬配額。憑證或主金鑰變更可使既有 Transfer OTP 無法恢復，輪換未實作。伺服器的 loopback 測試模式不代表正式部署。

P21-A：Phase 3 本機必要功能、回歸、安全與資源受控驗證已執行並整理，提交人工階段驗收。上述產品級及後續 Phase 項目明確保留，未以局部測試標記 PASS；無須以未來階段功能阻擋本階段的本機驗收。
