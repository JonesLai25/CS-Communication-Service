# Code Review 002

基準 `91eb593`，Phase 0 已結案，正式產品驗收仍未通過。階段內自主執行及安全停止條件見 ENGINEERING_CHARTER.md。測試僅使用臨時資料庫、loopback、測試程序及假憑證；回歸證據見 evidence/code-review-002.txt。

| 項目 | 措施與仍需驗證 |
|---|---|
| CR-009 | SQLite 同一 `BEGIN IMMEDIATE` 交易內做唯一請求登記、取得執行權、無危險資料庫副作用與結果。真實 TLS 兩個 Client 同 ID 測試一個 new、一個 existing 且 effect count 為 1；不同內容 409。僅測試操作，不宣稱命令 exactly-once。 |
| CR-010 | PROTOCOL_DESIGN.md 固定此切片的 Ed25519 帶長度前綴簽章欄位，包含版本、用途、Server 身分、TLS context、challenge、使用者及裝置。測跨 TLS 連線、錯誤 Server context、跨身分、錯簽章與重放。已改用 RFC 9266 TLS 1.3 exporter 並測試兩端一致及跨連線拒絕；hostname 驗證另採 service-identity，錯誤 hostname 實測拒絕；跨平台互通與安全審核仍待完成。 |
| CR-011 | 每次 SQLite 交易新連線、WAL、250ms 忙碌上限、`BEGIN IMMEDIATE`，禁止跨 thread 共用連線。測同 challenge 並行只成功一次、並行同 ID、資料庫鎖定及恢復。首次測試發現 Python 3.10 缺 SQLite 常數，已使用相容 fallback 修復並重測。 |
| CR-012 | Challenge 60 秒，建立時清理過期資料，單裝置最多八個有效 challenge、每分鐘十次，停用立即拒絕；audit 記錄簽發與成功，不含 challenge、token 或私鑰。測過期、清理、限額、頻率及停用；稽核保存期限、失敗事件及跨使用者濫用防護未完成。 |
| CR-013 | Phase 3 必須串流壓縮、逐塊加密、增量 hash、限制併發與固定記憶體，並以大檔量測 RSS；現有原型不是正式實作。 |
| CR-014 | 對可能有副作用的 test 呼叫通訊失敗回報 UnknownOutcome，保留 Request ID，不自動重送；重認證後查詢。測送出後斷線及重新連線查詢；不同類型未知結果仍待更多故障注入。 |
| CR-015 | unittest 測試以明確判斷，舊含 assert 原型若在 `python -O` 執行直接失敗；負向控制驗證優化模式不會假成功。需持續檢查新增測試及 CI 環境。 |
| CR-016 | 匯出工具明確檔案清單、必需檔缺失拒絕、逐層拒絕 symlink、解析後 root 檢查、SHA-256 manifest、不覆寫輸出；測試缺檔、連結、hash 和排除清單。 |

目前 TLS 認證 slice 只監聽 loopback，公鑰只能透過本機臨時 provision；未實作 Enrollment OTP、正式管理、重啟 session 恢復、跨平台部署與完整外部安全審計。正式 remote exec 維持停用。Phase 1 完整階段驗收不可將局部通過或 Phase 0 結案當作 PASS。

註：本文件記錄 Review 002 當時狀態。CR-012 原先的裝置共用 challenge 額度已因 CR-020 於後續修訂移除；最新行為以 CODE_REVIEW_003.md 為準。
