# Phase 1 狀態與下一步

本機垂直切片已建立：TLS 1.3 / RFC 9266 exporter、預先登記 Ed25519 裝置、綁定連線的短期 session、SQLite 請求登記與無危險測試效果、斷線後重新認證查詢。CR-017–022 的 session 資源回收、HTTP 邊界、回應驗證、challenge 公平性、SQLite 錯誤與原型邊界由 CODE_REVIEW_003.md 追蹤。測試輸出見 evidence/code-review-003.txt。僅限 loopback，正式 exec 持續禁用。

Phase 1 本機階段的受限 HTTP、TLS adapter、認證、競爭與故障恢復驗證已整理於 PHASE_1_STAGE_REPORT.md。Windows 原生為 OUT_OF_SCOPE；獨立安全審查為後續驗收，不無限阻塞核心開發。先前未發現 QEMU／KVM 的描述已更正：QEMU 6.2.0 與 TCG 已安裝並實際啟動訪客；宿主 /dev/kvm 可用並通過空 VM 建立，命令沙箱內不可見。詳見 evidence/qemu-inventory.txt。Phase 2 OTP、管理平面與裝置撤銷流程尚未實作，不能將本機手動 provision 當作 enrollment。

階段報告與後續驗收必須區分本機切片、外部依賴及正式產品；模擬故障、模擬掉電與真實掉電驗收分開。RFC exporter 和 service-identity 的本機成功不代表其他平台已通過。

## P22 Local 隔離環境補充

已建立獨立 rootless Podman／fuse-overlayfs 測試環境：受限容器內完整 Phase 1 測試與兩容器的 TLS 拒絕、冪等及重連查詢結果見 LOCAL_TEST_ENVIRONMENT.md 與相應 evidence。兩容器共用宿主核心及唯讀宿主系統函式庫，不能等同不同原生作業系統或實體主機。Podman 曾接受但未實施的資源上限已由獨立 systemd scope 驗證修正，先前未受限證據予以保留而不視作預算驗收。

## CR-023–025 本機延伸驗證

QEMU 6.2.0 與 qemu-img 已確認；TCG 實際啟動小型 Linux guest，宿主 KVM API 與空 VM 建立可用。獨立 Ubuntu 20.04.6 使用者空間以自有 glibc 2.31、Python 3.8 和 hash 鎖定 wheel 通過 Phase 1 24 項測試。兩個不同 network namespace 使用 veth 和兩層代理成功完成 TLS 認證及重連查詢。詳見 CODE_REVIEW_004.md 與對應 evidence。

Ubuntu 容器、同核心 network namespace 與極小 Linux guest 均不代表 Ubuntu 20.04 原生核心、跨實體主機或 KVM 訪客啟動驗收；Windows 為 OUT_OF_SCOPE，獨立安全審查保留後續。
