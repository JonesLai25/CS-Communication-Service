# 協定設計草案

候選 HTTPS/TLS 1.3 + 版本化 JSON 控制平面、二進位區塊資料平面。所有長度、編碼、超時和限制需在互通測試前固定；本文件尚非可實作的最終 wire specification。錯誤回應提供穩定代碼、request ID 和可公開診斷資訊，不透露密鑰或其他使用者資源是否存在。

Session ID 代表認證上下文，Request ID 代表一項操作，Transfer ID 代表一次傳輸，彼此獨立且由安全亂數產生。Server 用 `(owner, request_id)` 唯一約束及 canonical request digest 將接收與記錄原子化；重送同一內容返回原狀態，不同內容拒絕衝突。權限在執行及狀態查詢時驗證。連線失敗後先查詢，不盲目重跑命令。若崩潰造成副作用是否發生無法確認，回報 unknown，不能宣稱 exactly-once。

候選操作：enroll、challenge/authenticate、request submit/status/cancel、transfer create/status/chunk/commit/cancel、受授權的 outgoing package list；管理 API 僅本機。需在實作前固定 HPKE suite、簽章 canonicalization、所有欄位、大小限制、錯誤碼、併發與跨版本相容性，並用獨立 client/server 測試向量驗證；目前均未凍結。

## Phase 1 認證切片 v1（僅本機測試）

預先以可信本機管道註冊 owner、device 的 Ed25519 公鑰；這不是 Enrollment OTP。TLS 1.3 Server 證書以 CA 與 hostname 驗證；Server identity 為實際 TLS leaf DER SHA-256。每個 TLS 連線計算 `SHA256(tls-exporter)`，其中 exporter 使用 RFC 9266 的 `EXPORTER-Channel-Binding` 標籤、空 context、32 bytes，必須非空。Server 核發隨機 32-byte challenge，綁定 owner、device、連線 context、60 秒期限；簽章訊息為 ASCII `CS-AUTH-v1`、NUL，接著每欄以四位元組大端長度前綴串接：`cs/1`、`client-auth`、server identity（二進位）、channel digest、challenge、UTF-8 owner、UTF-8 device。用 Ed25519 對該訊息簽章；Server 於 SQLite `BEGIN IMMEDIATE` 交易內驗簽並單次核銷。任一欄位改變、跨連線、裝置停用或過期均拒絕。Secret session token 綁定該 TLS context、owner、device 並短時有效；每次操作重檢裝置，斷線後重新認證。不可記錄 challenge、簽章或 token。

此切片採 pyOpenSSL 提供的 [RFC 9266](https://www.rfc-editor.org/rfc/rfc9266.html) TLS 1.3 exporter，每條 TLS 連線最多成功完成一次認證；Client 與 Server 必須都能取得 exporter，不能降級。hostname 與 IP SAN 驗證採固定版 `service-identity`，跨平台互通仍待測試。認證簽章格式為目前切片版本，不代表安全審計完成。

`POST /v1/test` 為受認證的無危險 SQLite 測試操作；(owner, Request ID) 唯一、儲存 payload SHA-256，首次操作、資料庫內測試副作用及結果在同一交易提交；同內容重送只讀取結果，不同內容為 conflict。此保證僅適用交易中的測試效果，**不保證任意遠端命令 exactly-once**。經認證者可用 `GET /v1/result?id=...` 查自己的紀錄；Client 傳送可能產生副作用的請求若通訊結果不確定，保留 Request ID，重連認證後優先查詢，禁止盲目重送。

## CR-017–CR-022 邊界修訂

連線結束時立即刪除該連線的 session token 與未完成 challenge；資料庫忙碌造成清理失敗時由過期清理兜底，token 仍先從記憶體撤銷。每條連線至多簽發一個 challenge，連續四次認證拒絕後關閉連線；未認證的要求不消耗使用者或裝置共享額度，並以 16 個活動連線、每連線期限及 256 個未過期 challenge 的全域上限約束資源。無法完全消除全域連線飽和造成的可用性影響，也不得宣稱防止分散式阻斷服務。

HTTP/1.1 嚴格拒絕重複敏感標頭、Transfer-Encoding、非預期 body、含糊 Content-Length、Expect，以及超過 16 KiB 的 header；訊息錯誤關閉連線。Client 驗證回應 Content-Type、唯一 Content-Length、大小、完整讀取與 JSON 重複欄位；寫入結果不明時保留 Request ID，不推論不存在。SQLite 每次讀寫及連線錯誤經一致分類；忙碌與儲存故障回傳不含內部資訊的錯誤。舊的 `prototypes/legacy_auth_store.py` 僅保留為歷史實驗，不與 `phase1/registry.py` 共享產品維護與安全承諾。

認證 Client 禁止底層 HTTP 函式庫隱式重連：連線關閉後必須新建完整 TLS 連線並重新認證；不可把 session token 或請求送上未包裝的 socket。

## Phase 2 註冊協定

Linux-only 的 Enrollment OTP、雙私鑰持有證明、TLS exporter／Server 身分綁定、原子核銷及 unknown 恢復語義見 [Phase 2 設計](PHASE_2_DESIGN.md)。這是註冊授權，不能當作 Phase 3 Transfer OTP 或傳輸金鑰；註冊涉及的私鑰均只存放於 Client。
