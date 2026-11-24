# Phase 5 自我程式碼審查

- 預設拒絕：`--exec-root` 未配置、與 Server 敏感路徑重疊、cgroup／user bus／tmpfs／Bubblewrap／seccomp 不可用或 sandbox 自檢失敗時，不啟動 exec。結果查詢仍受原使用者與裝置授權保護。不存在直接 subprocess 降級路徑。
- 端點與授權：唯一 Request ID 和內容摘要在 SQLite 原子登記；每次只能一筆工作，同一請求重複提交僅回傳既有狀態。完成結果持久化；逾時、取消、未知與失敗分開記錄，不保證任意命令 exactly-once。
- 執行權限：非 root、user/PID/network/IPC/UTS/mount namespace、精簡 `/proc`／`/dev`、唯讀 runtime、FD 白名單、環境白名單、no-new-privileges 和 libseccomp。受控測試實際存取假私密檔、其他工作區、管理 Socket、宿主 TCP listener、host PID 和環境／FD；故意暴露假資料、刪除 affinity 過濾規則時測試應拒絕。
- 資源與資料：每工作 cgroup 強制 RAM／swap／pids 上限，worker 單 CPU affinity，seccomp 防止擴張；暫存使用該 cgroup 中的 tmpfs，資料總量、檔案數、深度、輸出和每檔大小有限。真實測試涵蓋 OOM、程序數上限、輸出及工作區超額；不進行宿主磁碟填滿或主機資源設定變更。
- 取消及崩潰：只對本工作建立且握有 Popen 身分的程序操作；sandbox PID namespace、父程序死亡信號與 worker 等待清理防止後代持續修改。持久紀錄 PID、啟動時間與 boot ID，重啟先等待同一 worker 離開，才重整 tmpfs 與工作區；交換前後使用 marker、fsync 和原子交換，遇不一致維持 unknown 並拒絕新工作。程序 SIGKILL 和故障注入證據不能取代 Phase 7 虛擬／實體掉電。
- 交付：Phase 4 先放 `/tmp` 為交付缺陷，即便 ZIP 與雜湊正確仍不算持久交付；已保留事件、補上固定持久路徑、自動檢查掛載、乾淨 Git 與 SHA-256，並在交付流程完成後才回報。

本審查及本機測試不等同獨立安全審查。受信任的同一 OS UID、本機部署與 host kernel 仍屬信任邊界；正式安裝、原生 Ubuntu 版本環境、獨立安全審查、完整儲存保留政策及硬體斷電仍未驗收。
