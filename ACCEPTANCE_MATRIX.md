# 驗收矩陣

以下原始矩陣保留建立時的 **UNVERIFIED** 歷史狀態；Phase 7 的實際本機證據與仍未完成的產品級驗收見文末更新。規格與設計本身不是測試證據。

原型證據另見 [Phase 0 證據](evidence/README.md)：A04 有本機 TLS 切片部分測試，A09 有基礎隔離原型，A11/A12 有密碼及磁碟原型；這些不等於各項完整產品驗收，以下狀態維持 UNVERIFIED。

[Code Review 001](CODE_REVIEW_001.md) 新增的驗證與負向控制均為有限範圍的原型或局部切片，產品項目繼續維持 UNVERIFIED；故障注入與實體掉電亦分開記錄。

| ID | 需求與驗收方法（不符合即失敗） | 狀態 |
|---|---|---|
| A01 | 查 Server 實際 UID 非 0；system mode 重開機後可用 | UNVERIFIED |
| A02 | user/system 安裝、版本升級、失敗回滾、卸載與資料保留在隔離環境驗證 | UNVERIFIED |
| A03 | Ubuntu 20.04／22.04 Linux Client 安裝並連線真實 Linux Server | UNVERIFIED |
| A03-W | Windows 原生 Client、安裝器、Wine 或 Windows VM | OUT_OF_SCOPE |
| A04 | 可信 TLS 成功；錯 hostname、未知憑證、降級均拒絕 | UNVERIFIED |
| A05 | 建立/停用使用者、管理多裝置、撤銷金鑰後即拒絕 | UNVERIFIED |
| A06 | 正確 OTP 註冊；錯誤、重用、過期及並行核銷拒絕 | UNVERIFIED |
| A07 | 驗簽、持鑰證明及重放拒絕；未授權裝置不得執行或傳輸 | UNVERIFIED |
| A08 | exec 返回正確 stdout/stderr/exit、非同步結果、取消及 timeout | UNVERIFIED |
| A09 | 實測 sandbox 無法讀取 Server 私鑰、管理 socket、他人 workspace；無能力時 exec 拒絕 | UNVERIFIED |
| A10 | Server 核發 Transfer OTP；Client 自動解封，上下載完成並比對檔案 hash | UNVERIFIED |
| A11 | 明文、錯 key、遭竄改/重排區塊拒絕且不提交 | UNVERIFIED |
| A12 | 上下載斷線續傳不重傳已驗證區塊；Server 重啟後同 key 恢復，最終 hash 一致 | UNVERIFIED |
| A13 | 變更來源、過期、撤銷及跨 owner 續傳被拒絕；清理過期資料 | UNVERIFIED |
| A14 | 路徑穿越、連結、特殊檔及資源超限拒絕，正式工作區無部分內容 | UNVERIFIED |
| A15 | 同 ID 同內容不重複副作用，不同內容衝突；重啟未知狀態不盲重試 | UNVERIFIED |
| A16 | 網路斷線、SIGKILL、磁碟滿、資料損毀及提交中斷後恢復或明確報錯 | UNVERIFIED |
| A17 | session 中斷後授權使用者可查原結果；跨使用者拒絕 | UNVERIFIED |
| A18 | 日誌含 ID、階段、時間、錯誤與結果，不含秘密；管理界面拒絕無權限本機使用者 | UNVERIFIED |
| A19 | outgoing 僅索引且有權限之包可下載；任意伺服器路徑拒絕 | UNVERIFIED |

Code Review 002：Phase 1 在本機測試了簽章、session、重放及持久化測試請求；已改用 RFC 9266 TLS 1.3 exporter 並進行本機測試，正式安全與跨平台驗收仍為 UNVERIFIED。其他產品驗收狀態不變。

Code Review 003 在本機增加 session 回收、challenge 公平性、HTTP framing、Client 回應和 SQLite 讀寫錯誤分類測試；見 CODE_REVIEW_003.md。這些測試不改變表內產品驗收狀態。

P22 本機隔離容器及雙容器通訊證據見 LOCAL_TEST_ENVIRONMENT.md；同核心容器不代表跨平台、跨主機或產品級驗收，表內狀態維持 UNVERIFIED。

CR-024 已實測獨立 Ubuntu 20.04 容器使用者空間及其鎖定 Python 3.8 依賴；CR-023 的 TCG guest 和本機雙 network namespace／代理鏈另有證據。上述是 Phase 1 本機範圍的實測，不代表完整產品、原生 Ubuntu 20.04 核心、Windows 或跨實體主機驗收；表內產品項目不變。

Phase 2 局部驗證範圍與結果見 PHASE_2_STAGE_REPORT.md；A05／A06 的完整產品驗收維持 UNVERIFIED，直到所需部署、目標原生平台及後續整合均有證據。Windows 相關項目為 OUT_OF_SCOPE。

## Phase 3 本機階段證據（不變更 A01–A19 的產品驗收狀態）

| 項目 | 本機結果 | 證據與限制 |
|---|---|---|
| Transfer OTP、RFC 9180、舊裝置拒絕與用途分離 | PASS（本機） | `evidence/phase3-container-final.txt`、`evidence/phase3-ubuntu20-targeted-final.txt`；產品安全審查未完成 |
| TLS 上下載、套件索引與授權、過期及清理 | PASS（本機） | `evidence/phase3-container-final.txt`；完整安裝與跨實體主機未驗收 |
| 資料竄改、路徑、覆寫及授權負向控制 | PASS（本機） | `evidence/phase3-mutation-scoped.txt`，突變僅在隔離副本 |
| 隔離網路代理鏈 | PASS（本機） | `evidence/phase3-netns-final.txt`，共用宿主核心 |
| 大檔及資源 | PASS（受控測試） | `evidence/phase3-large-final.txt`、`evidence/phase3-large-compressible.txt`；磁碟為取樣，並非硬配額 |
| 原生產品安裝、系統化資源配額、獨立安全審查 | UNVERIFIED | Phase 6／7；不以容器或局部結果替代 |
| 區塊續傳、崩潰及實際掉電恢復 | UNVERIFIED | Phase 4；模擬與實體掉電分開驗收 |
| Windows 原生、Wine、Windows VM | OUT_OF_SCOPE | Linux-only |

## Phase 4 本機階段（不改變產品驗收）

| 項目 | 本機結果 | 產品驗收 |
|---|---|---|
| 雙向續傳、不可變密文與 Manifest、授權及負向控制 | 見 Phase 4 階段報告與測試證據 | UNVERIFIED，須完整產品整合及獨立安全審查 |
| fsync、原子發布、重啟 reconciliation | 程序 SIGKILL、故障注入與專屬 VM 虛擬電源中斷分別驗證 | 實體裝置掉電 UNVERIFIED |
| 暫存上限、取消與過期 | 本機受控測試 | 全產品儲存 quota 及原生部署 UNVERIFIED |
| 實際 CS 核心於 192 MiB 限額 VM 的虛擬電源中斷恢復 | UNVERIFIED：OOM／逾時，見 `evidence/phase4-vm-application-192m-*` | UNVERIFIED；不以超額診斷或純檔案系統模型替代 |

## Phase 5 本機驗證（不變更產品級狀態）

| 項目 | 本機驗證 | 產品驗收 |
|---|---|---|
| 非 root、實際假資源隔離、seccomp／負向控制 | 見 Phase 5 測試證據 | 獨立安全審查及原生平台驗收 UNVERIFIED |
| 隔離工作區、資源上限、程序清理、取消與逾時 | 見 Phase 5 測試證據 | 正式部署與長期容量策略 UNVERIFIED |
| 請求冪等、持久結果、重新連線、程序崩潰恢復 | 見 Phase 5 測試證據 | 真實掉電及 VM 虛擬電源中斷 UNVERIFIED，移交 Phase 7 |

## Phase 6 本機結果與產品級邊界

| 項目 | 本機驗證 | 產品驗收 |
|---|---|---|
| User Mode 離線安裝、升級、失敗回復及資料保留 | 自動化安裝測試；systemd User Mode 服務完成認證、檔案傳輸、exec、升級與重連查詢 | 原生 Ubuntu 20.04／22.04 UNVERIFIED |
| System Mode 專用非 root 身分、安裝、服務單元及非 root 程序啟動 | rootless Ubuntu 20.04 容器，共用宿主核心；systemd manager 操作以模擬測試 | 原生 systemd System Mode 和端對端 UNVERIFIED |
| 資源配置、待完成上傳預留、audit 清理 | 局部受控驗證 | 全域持久儲存 quota、長期清理及 journald 保留 UNVERIFIED |
| 電源中斷、實體儲存掉電、獨立安全審查 | 不以程序或容器測試替代 | UNVERIFIED，移交 Phase 7 |


## Phase 7 更新：本機證據與未完成驗收

| 範圍 | 已驗證 | 仍未完成／產品驗收 |
|---|---|---|
| A01–A03 Linux 安裝與身分 | 實際發行檔於 Ubuntu 22.04 宿主 User Mode 安裝、systemd 啟動、升級和卸載；獨立 Ubuntu 20.04 容器安裝與 TLS 啟動 | Ubuntu 20.04／22.04 原生 System Mode、系統開機後服務及完整端對端 UNVERIFIED |
| A04–A07 TLS、使用者、Enrollment 和認證 | 實際發行檔端對端；TLS 錯憑證、hostname、舊版本及 mutation 測試；兩隔離網路節點直接連線 | 獨立安全審查與跨實體機驗證 UNVERIFIED |
| A08–A09 命令與 Sandbox | 實際發行檔完成命令、取消、結果查詢；實際隔離資源及突變控制 | 原生 System Mode、獨立安全審查 UNVERIFIED |
| A10–A15 傳輸、續傳及冪等 | 發行檔加密傳輸、實際斷線／重啟後續傳、取消、內容比對；Phase 3／4 自動化及負向控制 | 完整全域儲存 quota、清理及跨實體機 UNVERIFIED |
| A16–A19 恢復、結果、稽核及 package | 程序級故障、重啟查詢、package 授權與清理有本機證據 | 受限 VM 實際 CS 核心虛擬斷電、實體掉電、完整日誌／結果保留及獨立審查 UNVERIFIED |
| Windows 原生、Wine、Windows VM | 不支援 | OUT_OF_SCOPE |

完整證據與未完成事項見 `PHASE_7_FINAL_REPORT.md`；局部 PASS 均不得推定產品安全驗收通過。

Phase 7 後續儲存工程狀態見 `PHASE_7_CONTINUATION.md`：Server 與 Client 暫存採管理者配置的有限檔案系統強制邊界，保留使用者發布資料與重放墓碑；宿主 journald、Client 目的地、備份及外部驗收各有獨立責任邊界。受限容器與故障注入不等同原生 System Mode、真實掉電或獨立安全審查。
