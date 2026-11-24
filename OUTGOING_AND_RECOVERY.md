# Outgoing Package 與恢復策略（設計草案）

Package ID 是 Server 上已建立索引的不可變壓縮包識別碼；Transfer ID 是一次授權下載或上傳的識別碼。每次下載建立新的 Transfer ID 與獨立 Transfer OTP；多個傳輸可引用同一 Package ID，從不共享傳輸金鑰。Package ID 不可由路徑直接推導，也不授予存取權。

具備建立權限的本機管理流程或經授權的服務提出來源與 owner；Server 在隔離 staging 安全建立 Zstandard 包、檢查資源及路徑、計算 SHA-256，fsync 後以交易發布索引與 immutable blob；只有索引狀態 ready 且授權 owner/ACL 通過才可列出或下載。下載建立時及讀取/續傳/提交時檢查 ACL、使用者與裝置狀態；引用 package 的 transfer 固定 digest。建立失敗不發布；源內容變更建立新 package，不修改既有 blob。

生命週期：creating → ready → retiring → deleted，失敗為 failed。管理者可撤銷、標記過期；retiring 即停止新下載，依政策取消或拒絕現有 transfer 並清理 key/暫存。刪除先持久化 tombstone 再回收 blob；崩潰後依索引與引用計數重試清理。清理不能刪除仍獲授權且未終止的引用；磁碟滿及中斷需測試。使用者不得提供任意 Server 讀取路徑，建立來源亦須是授權 workspace 內安全解析的路徑。

自動續傳只適用短暫斷線或 Server 暫時不可用，且身份、權限、TTL、原封裝摘要和 key 均仍有效，Client 可取得並驗證對端進度；有指數退避、次數/時間上限，終止後標記 interrupted。重新啟動時可自動查詢；查無證據不得猜測完成。手動 resume 必須重新認證並套用同樣檢查；無法恢復的傳輸回報明確原因，不重新使用原 ID/key 建立新封裝。取消為持久化請求，停止排程、拒絕後續 chunk、清除可清理暫存/key；與提交競爭時以已提交的持久結果為準。過期則拒絕續傳、標記 expired 並清理。撤銷授權、缺失 key、封裝變更、已驗證資料毀損且無可信來源、認證失敗或不相容版本均不自動重試；提供診斷，必要時建立全新 transfer。這些語義尚未實作或驗收。
