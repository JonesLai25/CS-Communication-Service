# 風險與規格一致性

| 項目 | 處置及證據缺口 |
|---|---|
| 非 root 多租戶隔離 | bwrap 基本啟動不等於安全；需要兩個 Ubuntu 版本的攻擊與資源限制測試，失敗禁用 exec。 |
| HPKE 依賴 | 本機 cryptography 3.4.8 不證明支援標準 HPKE；選成熟套件並以標準測試向量驗證。 |
| 冪等與副作用 | 崩潰不能保證任意外部副作用 exactly-once；不明時回報 unknown，先查詢。 |
| key 恢復 | 可恢復意味必須持久化 key；服務帳號遭入侵仍可讀取，明確界定威脅模型及備份輪換。 |
| nonce 與續傳 | 不可對不同明文使用相同 key/nonce；保留原封裝及 ciphertext，測試崩潰與來源更動。 |
| 原子提交 | 非空目錄替換與跨檔案系統不保證原子；草案採同檔案系統新目標、同名拒絕，需故障注入。 |
| 裝置撤銷 | 持續傳輸和查詢均重新授權，完成前撤銷的具體行為需測試；授權與提交並發需交易化。 |
| Windows | OUT_OF_SCOPE：Linux-only 範圍不包含 Windows 原生、安裝器、Wine 或 Windows VM。Ubuntu 20.04／22.04 仍須各自驗收。 |
| 版本與協定 | 原規格留有封裝及金鑰策略細節；目前為候選設計，需標準向量與互通測試後固定。 |
| 本機管理 | User Mode 同 UID 不構成安全隔離；System Mode 以受控 socket 和 peer credentials 驗證，不憑帳號名稱。 |

原規格要求受限命令、傳輸及非 root，可同時成立但需實測；尚未發現必然互斥的需求。規格例子使用 OTP 命令列參數可能被程序列表或 shell history 暴露，實作應支援隱藏輸入或安全輸入通道，不記錄秘密。若沙箱在目標平台不可行，該平台 exec 必須保持停用並如實標記，不能宣稱完整 v0.1 驗收。

2026-11-24 更新：候選 PyHPKE 0.6.4 的一組 RFC 9180 測試向量、加密區塊概念及 bwrap 基本隔離已實測；範圍和未覆蓋項目見 [evidence](evidence/README.md)。這些風險均未關閉。pip bootstrap 缺少釘選與驗證、lock 僅涵蓋當前 Linux wheel；正式供應鏈及其他平台重現性仍待驗證。Phase 1 health 目前無 client 身分認證，只允許 loopback 且無敏感功能。

Code Review 001 修復和剩餘風險見 [CODE_REVIEW_001](CODE_REVIEW_001.md)：TLS 有界但尚未完成 DoS 驗收；sandbox 尚無程序樹清理及完整逃逸測試；加密 manifest 原型未認證且不能使用於產品；SIGKILL／故障注入不代表實體掉電。上述是 Review 001 時點的紀錄；Review 002 已將認證、session 與請求登記接入本機 TLS 測試端點，Enrollment OTP 與正式產品驗收仍未完成。

CR-010: 初期使用的 `tls-unique` 不適用 TLS 1.3，已改用 pyOpenSSL 25.3.0 的 [RFC 9266 exporter](https://www.rfc-editor.org/rfc/rfc9266.html)，並驗證同一連線兩端一致、跨連線拒絕與憑證反向測試；Python 標準庫不提供該 exporter。此主機實測不等於跨平台與獨立安全審計。Hostname 驗證已改採固定版本 service-identity，成功及錯誤 hostname 均已於本機測試；IP SAN 成功路徑亦已於本機測試；跨平台互通待驗證。TLS adapter、認證協定和錯誤邊界仍需持續審核。

CR-017–022 修復後，session 在連線結束即撤銷；資料庫清理可能因忙碌而延後到 challenge 到期，亦設有全域上限。未認證者不消耗裝置共用配額，但仍可能耗盡所有可用連線；跨代理 request-smuggling 與分散式 DoS 仍未驗收。細節和測試見 CODE_REVIEW_003.md。

自訂 TLS transport 仍須持續檢查庫版本變更、錯誤路徑及中介代理相容性；已禁止底層 HTTPConnection 在斷線時隱式建立明文 socket，並測試該負向條件。

P22 本機容器：此主機 Podman 原生資源限制曾被靜默忽略，改用驗證過的使用者 systemd scope、單 CPU 與事前磁碟檢查；圖像 graph 沒有 ZFS 硬配額，容器 tmpfs 有大小限制。Podman/FUSE 曾遺留 helper，現僅對自行建立之 scope／專案 graph 驗證並清理，失敗須回報。跨 OS、不同核心與實體機驗收仍待對應階段。

CR-023–025：宿主 QEMU TCG 實際小型 Linux guest 啟動成功、KVM API 和空 VM 可建立，但尚無 KVM guest 開機證據。Ubuntu 20.04 使用者空間使用 Python 3.8 專用鎖定依賴（pyOpenSSL 25.1.0／cryptography 44.0.3），與 Ubuntu 22.04 的 lock 不同；重建的 apt 系統套件尚未以 repository snapshot 固定，獨立安全審查仍需覆蓋兩組依賴。代理鏈及雙 network namespace 共用宿主核心，不等同跨實體主機。

Phase 2 本機管理以私有 Unix socket、SO_PEERCRED 及服務帳號同 UID 管理者授權；同 UID 惡意程式不受隔離，跨 UID 的系統管理員群組、systemd 安裝與正式部署屬後續階段。Phase 1 舊 device 經資料庫遷移仍可能沒有 X25519 加密公鑰，Phase 3 不得假設其具備傳輸密鑰接收能力。Enrollment 與 Transfer OTP 必須保持獨立。獨立密碼學協定安全審查與 Linux 原生部署驗收仍未完成。

Phase 3 進行中：Transfer OTP 核發及分塊封裝僅為局部實作；Zstandard 安全解封、上下載資料通道及 outgoing package ACL 已有本機實作與局部測試；整體資源限制、故障恢復及安全審查尚未驗收。Ubuntu 20.04 預設 Python 3.8 不符合既有 pyhpke 0.6.4 的版本要求；pyhpke 0.5.4 又與現有 cryptography 44 鎖定不相容。已在獨立 Ubuntu 20.04 容器使用 Python 3.12 及雜湊鎖定依賴通過局部相容測試；原生安裝、維護與產品級驗收仍未完成，詳見 PHASE_3_WORK_IN_PROGRESS.md。主金鑰與 TLS 憑證身分改變後，現有受保護 Transfer OTP 不可讀取，受控金鑰輪換尚未實作。

Phase 3 本機驗證完成後，仍需於後續階段處理：單次傳輸上限（160 MiB ciphertext／128 MiB tar）、伺服器單一傳輸槽與 60 秒受認證請求期限；不可中斷的本地磁碟作業可能在連線期限後仍執行至返回，結果應查詢、不得盲重試。收發及套件容量按單次和使用者數目部分限制，尚無全使用者磁碟硬配額；大檔 512 MiB 結果是取樣而非硬限制。主金鑰或 TLS 證書變更後的金鑰輪換、真正掉電持久性與原生平台安裝維持未驗證。詳見 PHASE_3_STAGE_REPORT.md；Windows OUT_OF_SCOPE。

Phase 4 風險：上傳未完成密文有 384 MiB 總預留上限，但已發布資料及 outgoing package 尚無產品級全域磁碟 quota；Client 離線時無法即時清理過期本機暫存。下載本地發布與遠端撤銷無跨主機原子交易，僅在發布前重驗授權，不能聲稱即時全域撤銷。受控 VM 虛擬電源中斷、程序 SIGKILL 與故障注入不代表實體儲存設備掉電通過；真實硬體、原生安裝及獨立安全審查仍未驗證。

專屬 VM 執行實際 CS 核心在既有 192 MiB scope 尚未通過：較大客體在 scope 發生 OOM 或未在期限內達標，64 MiB 客體核心未啟動。單次 256 MiB 診斷超出既有測試上限，已記錄並修正，不能作為合規驗收證據。隔離 VM 純檔案系統模型及本機程序故障注入另有通過證據；實際 CS 核心在合規 VM 的虛擬斷電測試為 UNVERIFIED。

Phase 5 本機 sandbox 採 Bubblewrap、libseccomp 與每工作 systemd user scope；其他 Linux 安裝或缺少 user bus、user namespace、cgroup controller、tmpfs 或 atomic exchange 的環境會拒絕 exec，原生 Ubuntu 20.04／22.04 安裝及獨立安全審查仍 UNVERIFIED。單一工作、16 MiB 工作區、512 項路徑與 2048 bytes 輸出為保守限制；不支援 workspace symlink／硬連結／特殊檔。SQLite 命令日誌長期清理及全產品持久儲存 quota 尚未實作，持續移交後續。Server／worker SIGKILL、模擬故障及原子交換測試不得取代 Phase 7 的 VM 虛擬電源中斷與實體儲存設備掉電驗收。

Phase 5 已對持久命令紀錄設每使用者 4096 筆、全域 16384 筆上限；滿額時拒絕新請求，但仍缺完整資料保留、清理及全產品磁碟配額政策。唯讀查詢已保存結果不需要重新啟用 sandbox。

Phase 6：使用者空間與隔離容器測試不等於 Ubuntu 20.04／22.04 原生 System Mode 部署驗收。System Mode exec 依賴服務帳號的 systemd user manager，缺少條件時拒絕執行；需在原生目標環境驗證。已發布資料、package、資料庫與持久結果尚缺完整全域儲存 quota／清理；audit 有有限量清理，不能保證高流量下立即符合上限，journald 保留由宿主管理。初始自簽 TLS 憑證需要正式信任與輪替流程。VM／實體掉電與獨立安全審查仍 UNVERIFIED，移交 Phase 7。

Phase 7：產品新增可由管理者指定的 IPv4 監聽位址，預設僅 loopback；直接遠端部署需具備正確 hostname／IP SAN、可信 TLS 憑證及管理者設定的網路防護。可選容量檢查只在管理者事先提供有界檔案系統時驗證多個 Server 資料目錄在同一裝置且總容量受限，不建立 quota、不涵蓋外部 journald、Client 暫存，也沒有完成已發布資料與結果的全域自動清理。不得將此檢查視為完整產品儲存治理。受限 VM 的實際 CS 測試已透過客體 swap 啟動至應用，但 384 MiB 虛擬資料磁碟不足以滿足程式既有 512 MiB 空間保留，故未進入斷電測試，見 `evidence/phase7-vm-diagnosis.txt`。原生 System Mode、實體掉電與真正獨立安全審查維持 UNVERIFIED。

Phase 7 結果保留更新：已終結命令結果按設定期限清除輸出及命令內容，保留 Request ID／摘要／裝置墓碑，未知狀態保留。墓碑與 SQLite 自由頁面仍會佔空間，批次清除不等於資料庫實體縮容或安全抹除；最終全域 quota 與日誌保留仍未完成。

Phase 7 相容性：命令結果保留到期後協定回覆新增 `expired`；舊版 Client 可能將其視為不符合 schema，應與 Server 一併升級，舊版不會因此自動重執行。預設自簽憑證僅含 localhost，遠端直連必須自行部署具有正確 SAN 的可信憑證。發行檔 manifest 與 SHA-256 提供完整性，不構成發布者數位簽章，摘要必須由可信通道取得。

Phase 7 後續：`storage_capacity_mib` 現為 Server 必要項，Client 傳輸／續傳暫存也需配置容量並驗證；不得直接套用前述「可選」舊狀態。檔案系統總容量不等於每使用者配額、可被其他同檔案系統程序消耗；宿主 journald、Client 目的地及備份仍由管理者治理。重放墓碑永久保留並受 OS 邊界限制，容量耗盡時拒絕新工作；不自動刪除已發布資料。原生 System Mode、真實掉電、跨實體機及獨立安全審查仍 UNVERIFIED。
