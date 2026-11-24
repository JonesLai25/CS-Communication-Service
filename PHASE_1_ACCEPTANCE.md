# Phase 1 本機階段驗收資料

## 範圍與狀態

本次提交的是 Ubuntu 22.04、本機 loopback 上的 TLS 1.3 認證通訊切片，供 Phase 1 階段驗收；不代表跨主機、跨平台或 CS v0.1 產品安全驗收通過。Server 僅提供 health、challenge/auth、受認證無危險資料庫測試操作與結果查詢；不提供正式 exec、檔案傳輸或 Enrollment OTP。裝置以本機手動 provision，沒有遠端管理介面。

| 本機階段條件 | 證據 |
|---|---|
| 真實獨立 Server／Client 程序；TLS 1.3、CA 與 DNS/IP SAN 驗證、RFC 9266 exporter | `phase1/test_tls.py`、`phase1/test_exporter.py`、`phase1/test_vertical.py` |
| Ed25519 challenge 簽章、綁定 TLS、短期 Session、拒絕重放、錯身分及跨連線 token | `phase1/test_vertical.py` |
| 同 ID 同內容原子取得一次測試執行權，衝突拒絕、斷線重連查詢；不宣稱任意命令 exactly-once | `phase1/test_vertical.py`、`phase1/test_crash_registry.py` |
| 連線與 header 期限及上限、回應驗證、儲存錯誤分類、挑戰公平性和資源回收 | `phase1/test_tls.py`、`phase1/test_review003.py` |
| 測試防線有效、非最佳化模式依賴；沒有底層明文隱式重連 | `phase1/test_mutations003.py`、以 Python `-O` 執行完整套件 |

完整實際輸出與兩次測試修復、一次突變控制失敗的原始證據見 `evidence/code-review-003*.txt`；產品驗收矩陣保持 UNVERIFIED。Linux x86_64/Python 3.10 wheel 鎖定在 `phase1/requirements.lock`；乾淨 venv 安裝過程記錄於 Review 002 證據。

## 外部及後續範圍

Windows 原生為 OUT_OF_SCOPE；跨實體主機與獨立安全審查未驗證。QEMU 6.2.0 TCG 已實際啟動隔離 Linux 訪客；宿主 /dev/kvm 可用並成功建立空 VM，命令沙箱內不可見。Ubuntu 20.04 的獨立使用者空間與本機跨 network namespace 代理鏈證據見後續補充；不能視為原生核心或跨實體主機驗收。正式網路部署、安全審計、跨平台、安裝、檔案、命令、持久續傳與實體掉電均未驗收，應在對應階段繼續處理。Phase 2 需完成受保護管理、Enrollment OTP、裝置撤銷及其安全測試。

依 P21，本機 Phase 1 範圍的實作與列出的必要本機回歸已準備階段驗收；可驗證的仍未完成項目及平台限制如上。若將跨主機、跨平台或獨立審查列為本階段必要條件，則整個 Phase 1 不能標記完成；不得以此報告宣稱該等驗收已通過。

## P22 本機容器補充

另已完成 rootless Podman 無外網容器的完整 Phase 1 回歸，以及同一私有網路 namespace 內兩個獨立容器的受認證 Server／Client、拒絕、冪等與重連查詢。詳細環境、資源限制與證據見 LOCAL_TEST_ENVIRONMENT.md；此結果不替代跨實體主機或不同原生 OS 的驗收。

## CR-023–025 本機階段報告補充

- Ubuntu 20.04.6 的獨立容器使用者空間（glibc 2.31、Python 3.8）以其相容 wheel hash lock 離線安裝，24 項測試通過；未借用宿主系統函式庫或 venv。
- QEMU 6.2.0 使用 TCG 以 64 MiB 訪客記憶體、單 CPU、無磁碟與無網路實際啟動最小 Linux；KVM API 與空 VM 可建立，未以 KVM 啟動客體。
- 兩個不同 network namespace 透過 veth 與兩層 TCP 代理完成端對端 TLS、錯誤金鑰／hostname 拒絕及斷線重連；宿主網路未修改。
- 詳細輸出、初次依賴失敗及修復見 CODE_REVIEW_004.md、LOCAL_TEST_ENVIRONMENT.md 與相應 evidence。Ubuntu 容器共用宿主核心，兩個網路節點也共用核心；這些不代替原生 OS 或實體主機驗收。
