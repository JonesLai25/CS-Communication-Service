# CS Communication Service

CS 是 Linux-only 的獨立 Client–Server 通訊服務，包含 TLS 認證、裝置註冊、加密檔案傳輸、續傳及具隔離條件的遠端命令執行。此公開快照不依賴任何上層排程系統。

**安全與驗收狀態：本機整合測試通過不代表完整產品安全驗收通過。** Ubuntu 20.04／22.04 原生 System Mode、實體掉電、跨實體主機及真正獨立安全審查仍為 UNVERIFIED；受限 VM 的實際 CS 核心電源中斷驗證亦未完成。部署前請閱讀 [安全模型](SECURITY_MODEL.md)、[驗收矩陣](ACCEPTANCE_MATRIX.md)、[風險清單](RISK_REGISTER.md) 與 [Phase 7 後續](PHASE_7_CONTINUATION.md)。

- [產品原始規格](references/CS_V0.1_SPEC.md)、[架構](ARCHITECTURE.md)、[通訊協定](PROTOCOL_DESIGN.md)
- [安裝與升級](phase7/INSTALL_GUIDE.md)、[管理](phase7/ADMIN_GUIDE.md)、[Client 使用](phase7/USER_GUIDE.md)
- [來源與測試](phase1)、[測試計畫](TEST_PLAN.md)、[選取的測試證據](evidence)
- 本次提供原始碼預發布版本；先前驗證之二進位 ZIP 含第三方 wheel，因原生依賴與通知條件尚未逐項確認而未公開。Python runtime 亦未納入；安裝前須由管理者取得並驗證相容執行環境及依賴。詳見 [第三方授權盤點](THIRD_PARTY_REVIEW.md)。

已發布資料與重放墓碑不因容量不足而自動刪除。Server 與 Client 暫存需管理者預先配置有界檔案系統；服務只驗證整個檔案系統容量，並不證明 per-user／project quota。宿主 journald、備份與其他使用者的資料由管理者治理。Server 預設只監聽 loopback；遠端部署需要正確的可信憑證與網路政策。

本快照是從私人專案以允許清單製作的新 Git 歷史，不含原始 Git 歷史、完整 Session、私人路徑及私人網路測試腳本。六個含私人位址格式的隔離網路工具暫不公開，因此相關舊文件可能提到不在快照中的工具；本機測試環境、映像、虛擬環境、私鑰及測試暫存不在此倉庫。見 [公開資料說明](PUBLICATION_NOTES.md)。

工程憲章及研究紀錄另存於 [AI-Engineering-Constitution](https://github.com/JonesLai25/AI-Engineering-Constitution)，不構成執行依賴。CS 原始碼與本專案文件採 [Apache License 2.0](LICENSE)；憲章原文副本依 [CC BY 4.0](licenses/CC-BY-4.0.txt) 授權，詳見 [授權說明](LICENSES.md)。
