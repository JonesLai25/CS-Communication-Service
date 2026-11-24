# CS Communication Service Phase 1 本機階段報告

## 階段範圍

Phase 1 已建立真實 TLS 1.3 Server／Client 認證切片：預先登記 Ed25519 裝置、RFC 9266 exporter 綁定、一次性 challenge、連線綁定 session、SQLite request registry、無危險測試效果、原子執行權與斷線後重新認證查詢。同一 Request ID 的保證僅限該 SQLite 交易內的測試效果，**不是任意命令 exactly-once**。不提供正式遠端 exec、Enrollment OTP、檔案傳輸或正式部署。

## 本機驗收與證據

| 驗證 | 實測結果及範圍 |
|---|---|
| 宿主 22.04 函式庫的隔離容器 | `evidence/local-phase1-after-ubuntu20.txt`：完整 Phase 1 測試；容器共用宿主核心與唯讀宿主函式庫。 |
| 獨立 Ubuntu 20.04 使用者空間 | `evidence/ubuntu20-final-test.txt`：Ubuntu 20.04.6、glibc 2.31、Python 3.8.10，從 hash lock 離線安裝相容 wheel，24 項測試通過。無宿主 `/usr`、`/lib` 或 venv 掛載；共用宿主 Linux 核心。 |
| 跨本機網路節點／代理 | `evidence/netns-proxy.txt`：兩個獨立 network namespace、私有 veth、兩層 TCP 代理；TLS 端對端認證、錯誤 hostname／金鑰拒絕、請求與重連查詢。宿主不建立測試介面。 |
| TCG VM | `evidence/qemu-tcg.txt`：QEMU 6.2.0、TCG 單 vCPU、64 MiB guest、無網路／磁碟，實際 Linux guest boot marker。這只證明最小 VM 啟動，不是 CS 產品在 VM 內驗收。 |
| KVM 與工具盤點 | `evidence/qemu-inventory.txt`：宿主 KVM API 12 可查並可建立／關閉空 VM，qemu-img 可建立／檢查臨時 qcow2；未啟動 KVM guest。命令沙箱中 `/dev/kvm` 不可見不代表宿主不可用。 |
| 失敗與負向控制 | Review 003 與 004 所列錯誤、突變、舊依賴不相容及修復後測試均保留於 evidence。 |

完整重現命令、依賴版本、資源界線和限制見 `LOCAL_TEST_ENVIRONMENT.md`；CR-023–025 詳見 `CODE_REVIEW_004.md`。測試 scope 上限為單 CPU、192 MiB RAM、128 MiB swap、64 tasks；TCG 使用獨立 144 MiB RAM／32 MiB swap scope 並在宿主可用記憶體低於 200 MiB 時拒絕啟動。測試不更動宿主網路介面或既有服務，僅清理本次建立的測試資源。

## 仍未驗證及後續

Ubuntu 20.04 原生核心、跨實體主機、KVM 客體啟動、獨立安全審查、完整安裝／升級及產品級安全驗收仍未證明。Windows 原生為 OUT_OF_SCOPE。Ubuntu 容器 apt 系統套件使用簽章驗證的發行版倉庫但未採 snapshot；Python wheel 使用固定 hash。QEMU 測試 kernel 經 HTTPS 與固定 SHA-256 檢查，尚未完成發行者獨立簽章核對。獨立安全審查列為後續驗收，不無限阻塞核心開發。Phase 2 需接續 Enrollment OTP、受保護管理與裝置生命週期；Phase 3–7 才涵蓋檔案、恢復、受限 exec、安裝和產品驗收。`ACCEPTANCE_MATRIX.md` 的產品級 UNVERIFIED 不因本報告自動變更。
