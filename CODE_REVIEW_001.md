# Code Review 001

審查基準 `40ec76d`；修復仍屬工作區變更。原始審查方向接受，正式驗收仍為 UNVERIFIED。可重現命令及本輪輸出見 [code-review-001.txt](evidence/code-review-001.txt) 與本文件；所有測試均使用臨時資源，SIGKILL 僅發給測試自行建立的子程序。

| 編號 | 修復、證據與未完成事項 |
|---|---|
| CR-001 | TLS 握手移入有界工作者，最多 16 條，I/O 3 秒、總期限 6 秒；`python3 phase1/test_tls.py` 測未完成握手、未完成 header 不阻塞其他 Client、飽和拒絕與超時恢復。有限數量 worker/timer，非完整 DoS 驗收，HTTP parser 使用 Python 既定限制。 |
| CR-002 | `prototypes/chunk_check.py` 先建 manifest 與一次性 ciphertext，續傳不重新加密；驗證來源摘要、ID、區塊數、key 指紋與每塊摘要。測來源改變、ID/key 錯誤、遺失、重排、竄改。原型 manifest 未經認證、key 指紋儲存不適合產品；唯一 key、保護及協定 binding 尚待正式設計與實作。 |
| CR-003 | 原型寫入暫存、fsync、rename、目錄 fsync，重啟依區塊重新驗證而不信任進度。對本測試子程序 SIGKILL，模擬部分寫入、毀損及錯誤進度，驗證 reconciliation。**沒有模擬真實電力中斷或證明磁碟持久性**；不同崩潰時點、磁碟滿、交易與真實掉電仍未驗收。 |
| CR-004 | `python3 prototypes/sandbox_check.py` 用真實臨時路徑嘗試讀寫及 socket 連接，檢查環境白名單、FD、proc、network、PID 與 RLIMIT_NOFILE；將私密假資料故意掛入後確實觸發失敗。程序樹清理、更多資源限制、escape、seccomp 與 Ubuntu 20.04 未驗證；正式 exec 持續禁用。 |
| CR-005 | 只接受 PyHPKE `OpenError` 且底層是 `InvalidTag`；測試錯 key/AAD/Transfer ID、重放與非預期 RuntimeError。重放檢查只示範記憶體 ledger，跨重啟的實際 replay 防護未完成。 |
| CR-006 | Client 限制 4096 bytes，驗證狀態碼、content type、JSON schema 與 request ID，區分 TLS、網路、授權、協定及遠端錯誤；未確定結果類型僅預留，health 無副作用。測無效憑證、hostname 與 TLS 1.2 拒絕；尚無授權端點的真實端到端測試。 |
| CR-007 | 目前 subprocess 測試使用 timeout；Server 啟動有期限，清理僅限自行建立的子程序，終止後逾時再 kill；沙箱 subprocess 設期限。不能因此保證未來所有新測試都自動遵守，須持續審查。 |
| CR-008 | `python3 tools/export_review.py /tmp/cs-review.zip` 以固定 allowlist 打包來源、規格、測試、lock、證據與 HEAD／工作區狀態，拒絕專案內輸出與 symlink；不加入 venv、快取、私鑰及其他檔案。可包含未提交的工作區內容，HEAD 不是對內容完整性背書；應先檢查輸出。 |

## 負向控制

沙箱掛入假秘密必須觸發斷言；修改來源或加密區塊必須觸發 `Corrupt`；錯誤憑證及 hostname 必須引發 `TLSError`；非預期例外不能被 HPKE 測試當作認證拒絕。這些測試只在暫存目錄和本次程序內執行。實驗未窮舉所有可能測試失效模式。

## Phase 1 接續

`auth_store.py` 在獨立 SQLite 示範已登記 Ed25519 key 的一次性 challenge、錯簽章與重放拒絕，以及按 owner／Request ID 持久保存摘要、不同內容衝突；重開資料庫有測試。它未接入 TLS，也沒有 session、channel binding、正式管理或 enrollment OTP，不能支撐正式認證／exactly-once 主張。下一步需完成正式受保護管理介面、OTP 核銷與使用者停用、TLS session 身分綁定、challenge 過期清理／限制、原子狀態及 crash unknown 語義，再進行真實跨程序負向測試。不得對外提供任何缺少授權的業務端點。
