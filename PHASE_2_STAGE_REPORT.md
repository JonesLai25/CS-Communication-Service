# Phase 2 本機階段報告

Phase 1 本機階段以 `1ae7ddd` 驗收；現行產品範圍為 Linux-only，Ubuntu 20.04／22.04 仍須驗收，Windows 原生／安裝器／Wine／VM 為 OUT_OF_SCOPE。原始文件與既有基準保留。

Phase 2 已建立 Linux 使用者、Enrollment OTP、Ed25519／X25519 雙持鑰證明、TLS exporter 綁定公鑰註冊、本機受保護管理 socket、裝置撤銷與使用者停用。OTP 為單次高強度註冊授權，僅保存雜湊；核銷與寫入兩把公鑰同一 SQLite 交易。Transfer OTP 屬 Phase 3，不共用。Client 以 0600 保存私鑰並透過隱藏輸入取得 OTP；回應遺失時保留金鑰並先重新認證，不盲目重送。權限撤銷會在後續操作交易內重新檢查。

本機測試、反向控制、Ubuntu 20.04 使用者空間及跨 UID 管理拒絕結果以 `evidence/phase2-local.txt`、`evidence/phase2-ubuntu20.txt`、`evidence/phase2-admin-uid.txt` 的實際輸出與退出碼為準。`phase2-local-initial.txt`、`phase2-ubuntu20-initial.txt` 為較早的測試快照，不取代最終結果。完整設計與執行方式見 PHASE_2_DESIGN.md。

限制：本階段為本機驗證，User Mode 管理 socket 授權服務 UID；同 UID 惡意程序、跨 UID system service 管理員、正式安裝／systemd 部署、原生 Ubuntu 20.04 核心、獨立密碼學安全審查與後續 Phase 3–7 仍未完成。Phase 1 舊 device 在遷移後可能沒有 X25519 公鑰，Phase 3 必須拒絕假設其支援傳輸密鑰。這些產品級項目不因局部測試通過而變成 PASS；完整產品驗收矩陣仍為 UNVERIFIED。

## 本機階段驗證與自我審查

- `./tools/local_container.sh phase1`：31 項通過，Python `-O`；包含 Phase 1 回歸、Phase 2 註冊及取消授權、並行單次核銷、兩種私鑰持有證明、跨 TLS 連線重放拒絕、結果遺失恢復與持鑰證明負向突變。
- `./tools/ubuntu20_test.sh`：獨立 Ubuntu 20.04 user space、glibc 2.31、Python 3.8，使用鎖定雜湊離線安裝依賴，同一套 31 項通過；不借用宿主函式庫，不等同原生核心驗收。
- `tools/test_admin_cross_uid.py`：實際不同 UID 連線拒絕；`tools/test_phase2_admin_recovery.py`：鎖競爭、stale socket 復原及非 socket 路徑拒絕通過。
- `./tools/container_pair.sh`、`./tools/netns_chain.sh`：既有 Phase 1 雙容器及代理鏈回歸，實際輸出分別見 `evidence/phase2-pair.txt`、`evidence/phase2-netns.txt`。
- 自我審查修正撤銷與請求交易競爭；修正認證與註冊不得在同一 TLS 連線混用；修正管理 Socket 初始化失敗時重複關閉鎖描述符，初次失敗及重驗見 `evidence/phase2-admin-recovery-initial.txt`、`evidence/phase2-admin-recovery.txt`。原始基準和初次測試紀錄保留。

本次停止條件 P21-A：Phase 2 本機階段預定功能與可在授權環境完成的驗證已執行，等待人工階段驗收。剩餘項目包括正式安裝／跨 UID system mode、原生 Ubuntu 20.04 與 22.04 產品驗收、獨立安全審查、後續傳輸與執行功能；這些是產品或後續階段工作，不宣稱本機測試已覆蓋。無須為繼續本機 Phase 2 核心實作取得額外權限；依階段驗收關卡等待下一階段指令。
