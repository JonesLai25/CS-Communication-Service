# Phase 6：Linux 安裝與服務管理

User Mode 使用使用者擁有、0700 的明確 prefix；System Mode 由管理者直接執行安裝程式建立專用非 root 帳號，程式及 unit 由 root 擁有且不可被該帳號修改，資料與設定由服務帳號擁有並採 0700／0600。安裝程式不呼叫 sudo，也不自動啟用或啟動正式服務。System Mode 的遠端命令仍需要服務帳號可用的 systemd user manager、cgroup 與 sandbox，條件不符時拒絕執行，不能降級。實際原生系統與 system manager 驗證屬 Phase 7。

`phase6/installer.py install --prefix ABS --python PYTHON --wheelhouse DIR --lock FILE` 為 User Mode 安裝；`phase6/system_installer.py install` 另有 `--service-user`，必須由管理者執行。所有依賴由指定離線 wheelhouse 依鎖檔 hash 安裝。`bin/cs-server initialize` 建立獨立身分與設定，不覆寫既有身分；`bin/cs-server unit install|start|stop|restart|status|enable|disable|remove` 由擁有管理權的使用者明確操作。System Mode 操作需 `--mode system --service-user NAME`。產生的自簽憑證為初始本機身分，正式信任、發佈及憑證輪替仍須部署管理。

版本目錄不可變，current 原子切換；執行中的程序固定既有版本，重啟後進入新版本。安裝失敗回復原指標；不相容 schema 拒絕升級。解除安裝前須停止程序並移除管理 unit；保留 config、金鑰、資料庫、工作區及結果。舊版本需管理者依保留政策處理，本階段不自動清除。

`config/execution-policy.json` 為 0600、服務帳號擁有的嚴格設定。預設每次工作 RAM 112 MiB、swap 32 MiB、32 程序、1 CPU、工作區 16 MiB／512 entries／16 層、輸出 2048 bytes、逾時 300 秒，並可在程式驗證的安全範圍調整。這是產品政策，與測試工具強制的宿主預算相互獨立。`server.json` 可設定待完成上傳預留額（預設 384 MiB）、audit 保留 90 天及 100000 筆，背景每次有限量清理；磁碟可用空間不足時上傳 fail closed。已發布檔案、package、資料庫及結果尚無完整全域儲存 quota；結果數量有上限但未實作自動清除；journald 空間與保留由現有主機政策管理。本階段不得聲稱完整容量管理已驗收。

System Mode 若建立帳號後安裝或初始化失敗，專用帳號及已建立的資料刻意保留，避免自動刪除可能已被使用的身分或資料；管理者應檢查原因後重試，或在確認無使用後自行處理。User Mode／System Mode 升級不自動轉換 schema、不自動啟動新版本；相容性不明時保留原版本並拒絕升級。初次 remote exec 前，管理者必須為既有 CS 使用者建立由服務帳號擁有的同名 0700 工作區。
