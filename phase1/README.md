# Phase 1 TLS 認證垂直切片

測試版本只監聽 127.0.0.1、拒絕 root，使用 TLS 1.3、有限連線數／期限。`provision.py` 可將 Ed25519 原始 32-byte 公鑰登記於擁有者私密的本機 SQLite，供測試啟動；這不是 enrollment。Server 使用 `--cert`, `--key`, `--db` 啟動；Client Python API 的 `AuthenticatedClient` 對同一 TLS 連線完成 challenge、session、測試請求與查詢。詳細簽章格式、安全限制及非 exactly-once 範圍見 PROTOCOL_DESIGN.md。

`.venv/bin/python phase1/test_vertical.py` 測試獨立 TLS 程序、SQLite 競爭、認證與重放；`.venv/bin/python phase1/test_tls.py` 測通訊上限與證書。測試使用專用臨時資料；不得當作正式部署。RFC 9266 TLS exporter 跨平台相容、OTP 管理、稽核策略和完整階段驗收尚待完成；正式命令執行仍停用。

安裝依賴需先有可信 pip：`python -m pip install --require-hashes -r phase1/requirements.lock`。此 lock 僅包含本機 Linux x86_64/Python 3.10 實測 wheel 雜湊；其他平台須另外鎖定驗證。

CR-017–022 的 session、challenge 與 HTTP/SQLite 邊界見 CODE_REVIEW_003.md；早期認證程式移至 prototypes，並非正式路徑。執行 `/tmp/cs-phase1-final/bin/python -O phase1/test_review003.py`（或以其他符合 lock 的虛擬環境 Python）及 `phase1/test_mutations003.py` 驗證回歸與負向控制。

本機受限容器環境、固定映像、資源與清理限制，以及雙容器隔離測試的重現方法見 [LOCAL_TEST_ENVIRONMENT](../LOCAL_TEST_ENVIRONMENT.md)。

Phase 2 更新：以上關於 OTP 尚未實作的敘述保留 Phase 1 歷史脈絡；目前已有受保護本機管理 socket、Enrollment OTP 與公鑰註冊。執行方式與限制見 [Phase 2 設計](../PHASE_2_DESIGN.md)。Transfer OTP 與正式部署仍屬後續階段。

Phase 3／4 現有 Transfer OTP 與雙向續傳；Server 必須明確配置私有 `--transfer-master`、`--transfer-root`、`--package-root`、`--resume-root` 才啟用相關路徑。Client 可執行 `phase1/resume_cli.py --help` 查看 upload、resume、download、resume-download、status 及 cancel。請保留私有續傳目錄和 Request ID；續傳只重送原密文。詳見 [Phase 4 設計](../PHASE_4_DESIGN.md)。

Phase 5 僅在明確設定 `--exec-root` 且安全自檢通過時啟用 exec；詳見 [Phase 5 設計](../PHASE_5_DESIGN.md)。CLI 為 `exec_cli.py`，工作區須由本機管理者建立私有使用者目錄。隔離能力不足時 exec 會停用，不退回直接執行。
