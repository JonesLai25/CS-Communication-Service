# Phase 5：受隔離命令執行

以 Linux-only 為前提，Server 僅在明確配置私有 `--exec-root`、確認與 Server 私密路徑分離，且工作 scope、Bubblewrap、seccomp 與非 root 自檢成功後開啟認證後的 exec；未配置或自檢失敗時拒絕 exec，其他通訊繼續。每個使用者的工作區為 root 下同名、由服務使用者擁有的 0700 目錄；工作區需由本機管理者先建立，不接受 Client 提供宿主路徑。Server 不以 shell 解讀 argv。

每個工作使用 systemd user transient scope（112 MiB RAM、32 MiB swap、32 tasks），worker 檢查實際 cgroup 限制，將 affinity 設為一 CPU；seccomp 禁止被隔離程序擴張 affinity、建立新 namespace、mount、ptrace、BPF、keyring、io_uring 等，Bubblewrap 建立 user/PID/network/IPC/UTS/mount 隔離、唯讀 runtime、乾淨環境、精簡 `/proc`、`/dev` 及 tmpfs；FD 白名單與 no-new-privileges。缺少必需工具、權限、cgroup 或自檢失敗即拒絕，不退回直接 subprocess。

工作區先複製到該工作 cgroup 的 tmpfs 暫存，拒絕 symlink、硬連結、特殊檔、跨檔案系統與非擁有者資源；限制總檔案與目錄 512 項、深度 16、總檔案 16 MiB。程式可讀寫隔離快照，但不能藉不受限數量的磁碟檔案耗盡宿主。工作完成後核對原工作區未被外部更改；若工作正常結束（含非零 exit code）且快照符合限制，使用持久 marker、fsync 及 renameat2 原子交換寫回；逾時、取消、輸出超限或工作程序消失不發布暫存。工作區若含 symlink、硬連結或特殊檔會拒絕，不保證此階段適用所有既有目錄。若工作區在執行中由外部變更，保留外部版本並回報 unknown。

Request ID 與內容摘要在 SQLite 中原子登記，並與其他請求共享唯一性；重複同一請求不重複啟動。每次最多一個工作，timeout 為 1–300 秒，stdout/stderr 合計最多 2048 bytes；超限作為失敗並停止工作。結果、退出碼及狀態可在裝置仍獲授權時經重新連線查詢；取消工作僅作用於該工作建立的程序。執行開始後若 Server 或 worker 異常消失，結果為 unknown，不盲目重送，也不聲稱任意命令 exactly-once。

持久化工作程序 PID、啟動時間與 boot ID；Server 重啟先確認同一程序已離開，再刪除其專屬 tmpfs 暫存並 reconciliation 工作區交換前後的 marker。無法判明、程序仍存活或資料不一致時保留資料、拒絕啟用 exec；不終止其他服務。此流程為程序級故障恢復，實體掉電與專屬 VM 虛擬電源中斷驗收仍屬 Phase 7。

Client 以 `phase1/exec_cli.py --help` 查詢 submit/run/status/wait/cancel；命令必須放在 `--` 之後。同步等待只查詢原 Request ID，TLS session 到期前重新建立認證連線，不重送執行請求。操作人員須保存 Request ID；結果以受限 SQLite 記錄保存，無清除策略的長期配額及正式部署運維仍需後續工作。

工作結果資料庫限制為每個使用者 4096 筆、全域 16384 筆；達到上限時拒絕新請求，既有結果仍可查詢。此上限不是完整磁碟硬配額或自動刪除政策。即使目前 sandbox 自檢失敗而停止接受新工作，既有結果仍可在原裝置授權有效時唯讀查詢。

為防止路徑型 Unix Socket 跨越網路 namespace，seccomp 一併拒絕所有 `connect`；命令無法主動連線至 sandbox 內或外的 Socket。這是目前的安全限制，而非一般網路服務環境。

若工作生命週期所需的 SQLite 交易持續忙碌或儲存故障，控制器先停止接受新工作；背景有限頻率重試，確認沒有活動工作、將未確認項目記為 unknown、完成清理與 sandbox 自檢後才恢復接收。原請求不會被自動重送；若資料或隔離狀態無法確認，持續拒絕執行並保留證據。

為支援內容衝突檢查，執行 argv 會保存在服務的私有 SQLite 日誌中；Client 不應將密碼或私鑰放在命令列參數。
