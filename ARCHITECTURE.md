# 架構設計草案

CS 是獨立模組化單體：Linux Server 與 Linux Client 共用版本化協定；不依賴 Job Manager。詳見 [Linux-only 規格修正](SPEC_LINUX_AMENDMENT.md)。Server 責任分為身分與授權、請求紀錄、傳輸、受限命令、管理與持久化。網路服務和本機管理接口各自授權；任何遠端工作都不能取得管理接口或私密資料。命令執行與檔案傳輸是不同服務，均預設拒絕。

候選：Python 3 + SQLite（交易、唯一約束與 WAL）、標準 TLS 與成熟第三方密碼套件；優點是開發與測試直接；代價是打包與套件維護，HPKE 與 Linux 各支援版本仍須依階段實測。Rust 可提供單一執行檔，但本機未發現工具鏈；是否改用它取決於供應鏈、跨平台打包與隔離原型的證據。不得以當前環境已有套件宣稱依賴可交付。

管理平面使用本機 Unix socket、受控目錄權限及 peer credentials；單獨授權管理帳號或群組，不能僅靠 CLI 名稱。System Mode 專屬非 root 身分；User Mode 同一 OS 帳號可管理自身服務，無法防禦同 UID 的本機惡意程序。以權限與服務帳號保護 Server 資料；命令用隔離執行環境，不能依賴同 UID 的目錄權限。後台無可驗證隔離時禁用 exec。

啟動盤點（2026-11-24，本工作區）：Ubuntu 22.04.3、x86_64、Python 3.10.12、Git 2.34.1、OpenSSL 3.0.2、cryptography 3.4.8、zstd、bwrap、unshare、systemctl 可見；pip、pytest、Python zstandard、FastAPI、httpx 未見；未見 rustc/cargo/go/gcc。bwrap 基本 user namespace 測試 exit 0，**非安全驗證**。當時 Ubuntu 20.04、systemd 啟用與 HPKE 尚未測；後續證據見階段報告，Windows 已 OUT_OF_SCOPE。安裝系統服務需要系統管理權限，本階段沒有使用。可由 `id`, `python3 --version`, `bwrap --unshare-user --ro-bind / / --proc /proc --dev /dev /bin/true` 重現基本盤點。
