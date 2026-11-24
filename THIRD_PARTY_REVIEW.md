# 第三方套件初步盤點

先前的發行 ZIP 中含鎖定的 wheel；本次逐一檢查各 wheel 的 METADATA 與實際 LICENSE／COPYING 檔案，盤點如下。因原生依賴的完整通知及再散布條件尚未確認，該 ZIP 及 wheel 未納入公開內容；下表不構成對所有相依元件的授權結論。

| 套件 | 版本 | METADATA 所示 |
|---|---|---|
| attrs | 26.1.0 | MIT |
| cffi | 1.17.1 | MIT |
| cryptography | 44.0.3 | Apache-2.0 OR BSD-3-Clause |
| pyasn1 | 0.6.5 | BSD-2-Clause |
| pyasn1_modules | 0.4.2 | BSD |
| pycparser | 3.12 | BSD-3-Clause |
| pyhpke | 0.6.4 | MIT |
| pyOpenSSL | 25.1.0 | Apache License 2.0 |
| service-identity | 24.2.0 | MIT |
| typing_extensions | 4.16.0 | PSF-2.0 |
| zstandard | 0.25.0 | BSD-3-Clause |

每個 wheel 中可找到至少一份名稱含 LICENSE 或 COPYING 的授權檔；是否涵蓋所有原生依賴及所需 NOTICE 仍為 UNKNOWN。獨立 Python runtime 沒有納入此 Git 候選，發布其原始第三方封包需另確認權利。

原始 wheel 也包含上游專案作者在公開發行的 metadata／程式檔中的電子郵件樣式字串；這些不是本機 Session 資料，未自行刪改，以避免破壞原始套件及授權通知。自動掃描不能判斷每一筆個資公開權利，實際散布前仍須人工確認。已驗證原始 wheel 的一般上游建置路徑與標準 ASN.1 名稱為掃描誤報，未修改 wheel。

RFC 9180 測試向量 JSON 的來源與擷取再散布條件尚未完成確認，已從公開快照排除；`prototypes/hpke_check.py` 因缺少該測試資料而不可直接執行。歷史測試證據依原狀保留，並非此次重跑結果。

先前本機驗證的 ZIP 對應產品版本 `8d41e158ad2dc786336029b0de2bd918a21ab14e`，SHA-256 `694df543d8abf3cd9b0ab2104e371144147798143d49495d80034fe18a9c775d`；其原檔僅保存在私人封存，並非本次公開發行資產。獨立 Python runtime 未散布，需由管理者自行取得，遵循其上游及組合元件的授權。
