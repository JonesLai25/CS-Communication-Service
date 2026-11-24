# Phase 7 產品整合與驗收報告

> 此為先前階段記錄；最新儲存治理、測試與發行基準見 [Phase 7 後續](PHASE_7_CONTINUATION.md)。

**狀態：本機整合與發行檔驗證完成；完整產品驗收尚未通過。** 本報告不將容器、程序故障注入或自行審查當成原生 System Mode、實體掉電或獨立安全審查。產品程式基準 `283a4ecf5e419f4440fe8d59ecddeb9522844d39`；最終 Review Package 的 Git commit 可能包含其後僅供驗收與交付的文件和測試，與發行檔內的程式基準分開標示。

## 已實作及本機驗證

- 使用離線發行檔，實際完成安裝、非 root systemd User Mode 啟動、使用者與 Enrollment OTP、裝置公鑰註冊、TLS 認證、加密上下載、上傳斷線及 Server 重啟後續傳、傳輸取消、遠端命令與取消、結果查詢、升級和解除安裝；保留身分、資料庫、工作區與結果。測試並驗證結果內容過期後保留 Request ID 墓碑，重送不再執行。`evidence/phase7-release-e2e-retention-initial.txt`。其中 User Mode 真實運行在 Ubuntu 22.04 宿主，測試服務僅在自建 user slice；不代表系統服務原生驗收。
- 獨立 Ubuntu 20.04 rootless 容器以實際發行檔安裝並啟動非 root Server；核驗 TLS、指定 IPv4 監聽及 kernel tmpfs 容量界限的啟動和拒絕；卸載後保留資料。`evidence/phase7-release-ubuntu20-retention.txt`。另在該容器獨立 16 MiB tmpfs 實際填滿並取得 ENOSPC，見 `evidence/phase7-release-ubuntu20-enospc.txt`；這只證明測試檔案系統的硬上限，並非全域 quota。容器共用宿主核心。
- Server 增加管理者明確配置的 IPv4 監聽位址，預設 loopback。兩個本機私有 network namespace 直接透過 TLS 完成授權與加密上下載、比對摘要，未更動宿主網路；`evidence/phase7-netns-direct-final.txt`。
- 結果終結後預設 90 天分批刪除輸出和命令本文並保留 ID／摘要／裝置墓碑，`unknown` 不自動清除。管理者可配置期限。`evidence/phase7-security-retention.txt`。現有過期 transfer 與 outgoing package 清理保留既有保護規則；已發布使用者資料不因推測而自動刪除。
- 可選 `storage_capacity_mib` 驗證 Server 資料所在檔案系統的內核回報總容量與單一裝置，拒絕不符合設定的啟動；管理者必須事先配置有界檔案系統。這不建立 quota、不涵蓋 journald／Client 暫存、不保證掛載之後不被修改，也不實作所有持久資料的自動清理。測試及範圍見 `evidence/phase7-storage-scope.txt`。
- TLS 錯誤憑證、hostname、舊版本及重要突變控制、密文與續傳負向控制通過 `evidence/phase7-security-retention.txt`；真實 Sandbox 邊界與負向控制見 `evidence/phase7-sandbox-negative-controls.txt`。這是自我驗證，不是獨立安全審查。

## 發行與操作文件

持久化離線發行檔 `CS-linux-x86_64-283a4ec.zip` 位於專案父目錄，供 x86-64 Linux、Python 3.12 使用；包含 Server／Client 原始碼、安裝器、鎖定 wheel、安裝／管理／使用手冊及 SHA-256 manifest，不包含私鑰或虛擬環境。實際發行檔 SHA-256：`eff071283fadc97a6fddc2c89b6ddc9540dfb89d1e3ef666e65f591815ef804c`。已對照 Git 基準逐檔驗證並實際安裝，見 `evidence/phase7-release-integrity-final.txt`；實際發行檔的隔離副本遭故意修改後確實被拒絕，見 `evidence/phase7-release-actual-mutation.txt`。hash 與 manifest 不能驗證發布者身分；摘要須由可信通道取得。

## 未完成的必要產品級工作

1. **完整全域儲存 quota 與安全清理：未完成。** 已發布資料、SQLite 主檔／WAL／自由頁、結果墓碑、外部 journald 與 Client 暫存尚未被單一強制配額及完整自動清理政策覆蓋。上述可選檔案系統容量檢查及有限期結果清理是局部改善。不得在未明確配置與驗證的環境宣稱完整治理；不得為清理而擅自刪除使用者資料。
2. Ubuntu 20.04／22.04 **原生 System Mode**、實際開機與完整服務管理仍 UNVERIFIED；現有的 Ubuntu 20.04 是容器、Ubuntu 22.04 為非 root User Mode 測試。不能因容器有非 root 程序就聲稱原生 systemd system service 通過。
3. 實際 CS 核心在原有 192 MiB／384 MiB VM 資源界線內的虛擬斷電恢復仍 UNVERIFIED。客體私有 swap 使程式成功啟動，但 384 MiB 資料磁碟不足以滿足程式原有 512 MiB 可用空間保留；測試未越界、未繞過檢查。見 `evidence/phase7-vm-diagnosis.txt`。既有純檔案系統 VM 測試與程序級 SIGKILL 不可取代此項；實體設備掉電亦 UNVERIFIED。
4. 真正獨立安全審查與跨實體主機驗證 UNVERIFIED。Windows 原生支援及測試 OUT_OF_SCOPE。舊 Client 不認得新 `expired` 狀態，需與 Server 配套升級；預設自簽憑證僅適用 localhost，遠端部署須配置可信且 SAN 正確的憑證。

## P21 工作狀態

完整產品階段驗收的 P21-A 條件**尚未成立**：全域儲存治理與上述驗收項目仍未完成。要完成原生 System Mode、journal／檔案系統配額部署驗證與 VM 受控電源中斷，需要在不影響宿主及既有服務的專用環境中，獲得可用管理權限和足以同時滿足 512 MiB 保留與測試資源政策的專用儲存；目前使用者明確禁止擅自擴大宿主權限或提高測試上限。獨立安全審查與實體掉電需要不可由自測替代的外部資源。可在本地安全完成的發行檔、本機整合、網路隔離、重要負向控制與局部資源治理已執行；此紀錄不把局部成果宣稱為產品全項 PASS。平台沙箱與 systemd bus 的存取限制已透過受控非 root scope 處理，不混同上述產品驗收限制。
