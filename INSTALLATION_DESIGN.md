# 安裝設計草案

User Mode 放在 XDG 目錄，以前景或 systemd --user 執行；自動開機取決於登入與 linger。System Mode 需要管理員授權，安裝程序建立專屬非 root 帳號、限定權限的設定/資料目錄及 systemd 服務；常態 Server、OTP 管理與 exec 不提權。Client 僅交付 Linux，Ubuntu 20.04 與 22.04 的憑證信任、私鑰保護及安裝須驗證；Windows 安裝為 OUT_OF_SCOPE。

候選部署先安裝新版本至獨立目錄，檢查版本、依賴、目錄和 migration 相容性後切換；失敗恢復舊程式，資料 schema 若不可逆須先備份並測試還原。解除安裝預設保留使用者資料；移除資料為明確操作。退出碼區分成功、參數、權限、相依性與回滾失敗。以上均未實作，不修改既有服務。

Phase 5 本機使用時，執行端需以非 root 服務使用者運作，準備與憑證、資料庫、管理 Socket 及傳輸目錄分離的 0700 工作區根目錄，並在其中預先建立同名的 0700 使用者目錄。只有顯式傳入 `--exec-root` 才會嘗試啟用命令執行；系統需具備可用的 systemd user bus、受限 cgroup、Bubblewrap、libseccomp、tmpfs 與 atomic exchange，啟動自檢不通過時 exec 停用。這是本機驗證設定，正式原生安裝及權限配置仍待後續驗收；不需也不得由測試擅自修改其他服務或宿主資源設定。

## Phase 6 實作

User／System 安裝、權限、離線依賴、升級回復、明確服務管理及未完成的容量政策見 `PHASE_6_DESIGN.md`。System Mode 安裝與執行使用不同身分，須明確管理 systemd 及非 root user manager；不得自動以 root 執行 CS Server。
