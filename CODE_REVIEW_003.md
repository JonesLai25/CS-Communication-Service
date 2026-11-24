# Code Review 003：Phase 1 持續修復

審查基準 `8257dd4`。修復與測試均在現有授權及測試環境限制下進行；這些測試不自動變成產品驗收 PASS。

| 項目 | 措施與證據 |
|---|---|
| CR-017 | Handler 結束時撤銷該連線 session，再清理該連線 challenge；SQLite 清理失敗保留 60 秒過期兜底。測 135 次順序登入／關閉，未耗盡 128 session 上限，連線後 challenge 最終清空。 |
| CR-018 | 對實際 TLS 請求拒絕重複 Host、Authorization、Content-Length、Transfer-Encoding、GET body、Expect；限制 request header 的讀取總量 16 KiB、body 4096 bytes、正規 HTTP/1.1 framing。測試惡意標頭及超大 header，拒絕後關閉連線。這不是對所有代理／HTTP 實作的互通或 request-smuggling 安全審計。 |
| CR-019 | Client 驗證唯一 Content-Length、Content-Type、無 Transfer-Encoding、完整長度、大小、JSON 唯一 key、status/error schema。未知或畸形寫入結果為 UnknownOutcome；畸形 404 不當作資料不存在。 |
| CR-020 | 不再讓未認證 challenge 消耗跨連線的裝置配額。每條連線最多簽發一次、錯誤簽章達四次即關閉，結束即回收；活動連線、單次期限及全域 challenge 有界。12 條偽造同裝置 challenge 同時存在時合法裝置仍可登入。無法消除全域連線資源飽和造成的 DoS。 |
| CR-021 | SQLite 連線、讀取及交易錯誤統一分類 Busy／StorageError，HTTP 回應不暴露資料庫內容。測鎖定與刪除測試資料表；GET 和 POST 均回 503 且無不受控 traceback。 |
| CR-022 | 早期 `auth_store` 及測試移至 `prototypes/legacy_auth_store.py`、`prototypes/test_legacy_auth_store.py`，只作歷史實驗。正式 Phase 1 切片以 `phase1/registry.py` 為單一實作，無資料遷移或安全支援承諾。 |

測試由 `phase1/test_review003.py`、既有 TLS／認證測試及 `phase1/test_mutations003.py` 執行；負向控制在暫存副本移除 session 回收或重複標頭檢查，必須偵測失敗。所有子程序有期限，只終止本次測試自行建立的程序。

殘留工作：跨平台實測、獨立安全審查、代理鏈中的 HTTP 差異、資源飽和的進一步故障測試、Enrollment OTP 與正式管理均未驗收。詳見 PHASE_1_STATUS.md。測試不使用實體主機重啟、主機網路變更、sudo 或其他既有服務。

延伸自我審查另發現：Python `HTTPConnection` 在 socket 關閉時可能隱式建立明文連線，繞過自訂 TLS 包裝。已以 `TLSOnlyHTTPConnection` 禁止此隱式連線；關閉時清除 session token，操作結果未知時要求以新的 TLS Client 重新認證並查詢。負向測試攔截 socket 建立，確認不嘗試明文重連。

完整回歸第一次執行時，斷線模擬替身缺少新清理路徑所需的 `close()`，導致測試本身拋出 AttributeError；原始輸出保存在 evidence/code-review-003-initial-failure.txt。已補上替身介面，重新執行受影響測試與完整回歸；此修復不把程式例外視為通過。

第二輪完整回歸因認證成功後未重設先前拒絕次數，後續重放測試提早遇到連線關閉；保留 evidence/code-review-003-second-failure.txt。現已在成功認證時重設次數，並以獨立真實 TLS 測試重驗。完整回歸最終結果以 evidence/code-review-003.txt 的結尾和退出碼為準。

另外以測試自己建立的子程序，在 SQLite 交易提交前及提交後各做一次 SIGKILL：提交前的 request／effect 均不存在，提交後結果可查且相同 Request ID 不重複建立 effect。這是程序崩潰模擬，不能證明實體掉電或任意外部命令的 exactly-once。

對「禁止明文重連」的突變測試首次失敗：原測試在建立 HTTPConnection 後才 patch 全域 socket 函式，沒有攔截該物件已保存的連線函式，因此錯誤實作也會誤報通過。原始失敗見 evidence/code-review-003-mutation-failure.txt；現改為 patch 該連線物件的 `_create_connection`，並證明正常實作通過、移除保護的暫存突變被測試拒絕。
