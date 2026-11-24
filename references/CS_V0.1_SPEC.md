# CS Communication Service v0.1

獨立式 Client–Server 安全通訊系統｜整體設計規格草案

## 一、系統定位

CS（Communication Service）是一套可以獨立安裝、部署及運作的安全遠端通訊軟體。

**系統只有兩個主要程式：CS Server 與 CS Client。**

CS Server 提供身分註冊、認證、遠端命令執行、檔案傳輸、Session 管理及安全工作區服務；CS Client 負責連線、註冊、發出請求及接收結果。

本版本不包含 Job Manager、Worker、Agent、工作排程或 AI 專用邏輯。未來其他程式可以透過 CS 的 CLI 或 API 使用通訊服務，但不影響 CS 本身的獨立性。

### 核心設計原則

1. **權限分離**：安裝時可以使用 sudo；Server 正常執行不得具有 root 權限。
2. **先授權再服務**：Client 必須完成 OTP 公鑰註冊，才能使用 Server。
3. **傳輸金鑰由 Server 核發**：檔案傳輸前必須取得專屬 Transfer OTP。
4. **加密壓縮封裝**：檔案傳輸一律使用經認證加密的壓縮封裝，不直接傳送明文檔案。
5. **可續傳、可恢復**：傳輸中斷後，能查詢已驗證進度並恢復。
6. **工作區隔離**：遠端命令與檔案操作只能在授權的隔離環境中進行。
7. **可驗收、可追蹤**：每次請求具有唯一 ID、明確狀態、結果及錯誤紀錄。

## 二、整體架構

**CS Client**

金鑰產生與保存

Enrollment OTP 註冊

遠端命令請求

檔案壓縮與加解密

斷點續傳

結果查詢

TLS 1.3｜Client 公鑰認證｜Request ID / Transfer ID

**CS Server — Non-root**

使用者與權限管理

OTP 核發與核銷

公鑰身分認證

命令執行服務

加密檔案服務

Session 與狀態管理

**Server 受保護資料區**

使用者資料庫

傳輸暫存區

隔離 Workspace

Session / Audit Log

## 三、安裝與執行權限

支援兩種安裝模式：

| 項目 | User Mode | System Service Mode |
|--------|--------|--------|
| 安裝權限 | 一般使用者 | sudo |
| 安裝位置 | 使用者目錄 | 系統目錄 |
| 啟動方式 | `systemd --user` 或前景執行 | 系統級 `systemd` |
| 開機自動啟動 | 視登入及 linger 設定 | 支援 |
| Server 執行身分 | 一般使用者 | 專屬非 root 服務帳號 |
| OTP 與使用者管理 | CS 管理員 | CS 管理員 |
| 遠端命令 | 受限沙箱 | 受限沙箱 |

System Service Mode 安裝時建立專屬服務帳號，例如 `csservice`，並配置必要目錄。Server 不得使用 sudo 執行遠端命令，也不得提供任意提權功能。

預定 CLI：

```bash
# User Mode
./cs-server install --mode user

# System Service Mode
sudo ./cs-server install --mode system

# 管理操作
cs-server status
cs-server user list
cs-server otp create --user alice
```

管理操作必須透過本機受保護的管理介面完成授權，不能只憑執行檔名稱或 Linux 帳號名稱判斷是否具有 CS 管理權限。

## 四、使用者註冊與公鑰認證

系統支援多個 CS 使用者，每個使用者可以註冊多個 Client 裝置及公鑰。

### 首次註冊流程

1. **Server 管理員建立使用者**
   
   `cs-server user add alice`
2. **Server 產生 Enrollment OTP**
   
   `cs-server otp create --user alice --ttl 300`
   
   OTP 綁定使用者、有效期限與允許註冊的裝置數。
3. **Client 產生本機金鑰**
   
   簽章認證使用 Ed25519，加密金鑰交換使用 X25519；私鑰只保存在 Client。
4. **Client 輸入 Server 位址、帳號與 OTP**
   
   Client 先驗證 Server 的 TLS 身分，再提交註冊資料、公鑰及私鑰持有證明。
5. **Server 驗證並完成註冊**
   
   驗證 OTP、綁定公鑰、原子性核銷 OTP，回傳註冊結果。
6. **後續使用公鑰認證**
   
   正常連線不再要求 Enrollment OTP。管理員可以撤銷裝置或金鑰。

Enrollment OTP 僅負責註冊授權，不作為檔案加密金鑰。Server TLS 憑證必須透過可信 CA、預先配置的憑證指紋或其他可信通道驗證，不能讓未知憑證自動通過。

## 五、遠端命令執行服務

Client 可以向 Server 發送命令與參數，Server 驗證身分、權限及執行環境後，在受限沙箱中執行。

### 請求內容

```json
{
  "request_id": "req-001",
  "operation": "exec",
  "workspace": "alice",
  "argv": ["python3", "test.py"],
  "timeout_seconds": 120
}
```

### 回應內容

```json
{
  "request_id": "req-001",
  "status": "succeeded",
  "exit_code": 0,
  "stdout": "PASS\n",
  "stderr": "",
  "duration_ms": 1250
}
```

支援同步等待、非同步提交、查詢狀態、取消執行、逾時終止、stdout/stderr 擷取及斷線後結果查詢。

**命令執行必須採取預設拒絕策略。** Server 不得直接以服務帳號的完整 `$HOME` 執行遠端 shell。執行環境必須隔離 Server 的設定、金鑰、資料庫及其他使用者工作區。

若作業系統缺乏可驗證的非 root 沙箱能力，遠端命令服務必須拒絕啟用；不得退化成不受保護的直接執行。

## 六、檔案傳輸服務

這是 CS v0.1 的核心功能之一。

**所有檔案傳輸都必須先向 Server 申請服務，再由 Server 核發加密的 Transfer OTP。**

Transfer OTP 在協定中定義為一次性高強度傳輸密鑰，不是六位數的人類驗證碼。

### 6.1 上傳流程：Client → Server

**階段 A：取得傳輸授權**

1. Client 向 Server 提出上傳請求，指定目標 Workspace。
2. Server 驗證身分、權限、容量與配額。
3. Server 建立 Transfer ID，產生一次性 Transfer OTP。
4. Server 使用 Client 的 X25519 加密公鑰，透過 HPKE 封裝 OTP 並回傳。
5. Client 解開 OTP，準備傳輸。

**階段 B：加密封裝與上傳**

1. Client 將指定檔案或資料夾壓縮封裝。
2. 使用 Transfer OTP 衍生加密金鑰。
3. 將封裝檔分塊加密並傳送。
4. Server 依 Transfer ID 配對 OTP，驗證並接收區塊。
5. 完成後，Server 解密、解壓縮到隔離暫存工作區。
6. 全部驗證通過後，原子性提交到正式 Workspace。
7. Server 回傳最終結果。

### 6.2 下載流程：Server → Client

**階段 A：取得傳輸授權**

1. Client 指定 Server 傳出暫存區中的壓縮包。
2. Server 驗證 Client 對該壓縮包的讀取權限。
3. Server 建立 Transfer ID，產生一次性 Transfer OTP。
4. Server 加密 OTP 並傳給 Client。
5. Client 解開 OTP，準備接收。

**階段 B：加密封裝與下載**

1. Server 取得指定的壓縮包。
2. Server 使用該次 Transfer OTP 衍生金鑰，加密壓縮包。
3. Server 分塊傳送加密資料。
4. Client 接收區塊，支援斷點續傳。
5. Client 使用配對的 OTP 驗證、解密。
6. Client 安全解壓縮至指定目錄。
7. Client 回報完成，Server 更新傳輸紀錄。

### 6.3 封裝規格

| 項目 | 規格 |
|--------|--------|
| 壓縮 | Zstandard，封裝格式需版本化 |
| 加密 | AES-256-GCM，採獨立區塊認證 |
| 金鑰來源 | Server 核發 256-bit Transfer OTP |
| OTP 封裝 | HPKE，使用 Client 加密公鑰 |
| 完整性 | AEAD 認證、區塊雜湊、整包 SHA-256 |
| 檔案格式 | 僅接受 CS 定義的加密壓縮封裝 |
| 路徑安全 | 禁止絕對路徑、`..`、符號連結越界 |
| 資源限制 | 限制展開大小、檔案數量、深度與處理時間 |

Server 的傳出暫存區只能包含已授權、已建立索引的封裝檔。Client 不得透過任意路徑要求讀取 Server 的系統檔案。

### 6.4 斷點續傳

每次傳輸建立持久化紀錄：

```json
{
  "transfer_id": "tx-001",
  "owner_id": "alice",
  "direction": "upload",
  "status": "interrupted",
  "total_chunks": 100,
  "verified_chunks": 60,
  "archive_sha256": "EXPECTED_HASH",
  "expires_at": "2026-11-25T12:00:00Z"
}
```

續傳規則：

- Client 重新認證，提交 Transfer ID。
- Server 確認傳輸所有權、有效期限與原始封裝識別。
- 雙方比對已驗證區塊，僅傳送缺少的部分。
- 同一 Transfer ID 沿用原本的 Transfer OTP，不重新核發。
- 加密 nonce 必須由傳輸識別與區塊編號等資訊安全衍生，確保同一金鑰下不重複。
- 如果原始檔案或壓縮封裝內容改變，必須重新建立傳輸工作。
- 傳輸完成、取消或逾期後，依政策清除密鑰與暫存資料。

為了讓 Server 重啟後仍能續傳，傳輸密鑰必須以受保護的形式持久化，不能只存在程序記憶體。也不能在日誌中記錄明文 OTP。

## 七、Session 與 Request 管理

CS 必須區分三種識別碼。

| 識別碼 | 用途 |
|--------|--------|
| Session ID | Client 連線與認證上下文 |
| Request ID | 每次命令或服務請求 |
| Transfer ID | 每次檔案傳輸及其續傳狀態 |

Session 中斷不代表工作失敗。Server 必須持久化必要的請求狀態與結果，允許同一授權使用者重新連線查詢。

建議狀態：

```text
created → authorized → running
                         ├─ succeeded
                         ├─ failed
                         ├─ cancelled
                         └─ expired
```

檔案傳輸另外支援 `interrupted`、`resuming`、`verifying`、`extracting` 與 `committing`。

重新提交相同 Request ID 時，Server 應提供冪等性處理，避免因網路重試而重複執行命令或提交檔案。

## 八、資料目錄與工作區隔離

System Service Mode 的預定目錄配置：

```text
/usr/local/bin/
  cs-server

/etc/cs-server/
  config.toml

/var/lib/cs-server/
  identities/
  database/
  transfers/
    incoming/
    outgoing/
    staging/
  workspaces/
    alice/
    bob/

/var/log/cs-server/
```

User Mode 則使用 XDG 使用者目錄。

隔離要求包括：

- Server 身分資料庫、密鑰與設定不得暴露給遠端命令。
- 上傳暫存區、解封裝區、正式 Workspace 必須分離。
- 不允許壓縮包內的路徑覆蓋 Server 系統檔案。
- 不允許跨使用者讀寫工作區。
- 解壓縮失敗時不得留下部分提交的正式檔案。
- 遠端命令不得直接存取傳輸 OTP 或 Server 管理介面。

多個 CS 使用者共用同一個 Linux 服務帳號時，必須透過沙箱與應用層授權實現隔離，不能假設 Linux 目錄權限本身就足夠。

## 九、CLI 與管理介面

以下為預定命令，尚未實作。

### Server

```bash
# 安裝
sudo ./cs-server install --mode system

# 狀態
cs-server status

# 使用者
cs-server user add alice
cs-server user list
cs-server user disable alice

# Enrollment OTP
cs-server otp create --user alice --ttl 300
cs-server otp revoke --user alice

# Client 金鑰
cs-server user keys alice
cs-server user key revoke alice --key-id KEY_ID

# 傳輸管理
cs-server transfer list
cs-server transfer show TRANSFER_ID
cs-server transfer cancel TRANSFER_ID

# 服務健康檢查
cs-server health
```

### Client

```bash
# 安裝
./cs-client install

# 首次註冊
cs-client enroll \
  --server https://host:8443 \
  --user alice \
  --otp XXXXX

# 遠端命令
cs-client exec -- python3 test.py

# 上傳（自動申請 OTP、壓縮、加密）
cs-client upload ./project /workspace/project

# 下載（自動申請 OTP、解密、解壓縮）
cs-client download package-001 ./output

# 續傳
cs-client transfer resume TRANSFER_ID

# 查詢
cs-client transfer status TRANSFER_ID
cs-client result REQUEST_ID
```

CLI 應自動完成 Transfer OTP 的申請、解封裝與配對，不要求使用者手動複製金鑰。

## 十、安裝交付物

| 交付物 | 平台 | 內容 |
|--------|--------|--------|
| CS Server | Ubuntu Linux | Server、安裝器、systemd service |
| CS Client Linux | Ubuntu Linux | CLI、金鑰管理、傳輸功能 |
| CS Client Windows | Windows 11 | CLI、金鑰管理、傳輸功能 |
| Protocol Specification | 跨平台 | API、封裝格式、狀態與錯誤碼 |
| Acceptance Tests | 跨平台 | 自動化測試及驗收報告 |

安裝、更新與解除安裝必須具備版本檢查、資料保護、失敗回滾與明確的退出碼。

## 十一、驗收標準

以下為 v0.1 必須通過的測試。

| 測試 | 預期結果 |
|--------|--------|
| 非 root 執行 | Server 服務程序無 root 權限 |
| 開機常駐 | System Service Mode 開機後可用 |
| 首次註冊 | 正確 Enrollment OTP 成功註冊 |
| OTP 重複使用 | 拒絕 |
| 未授權 Client | 拒絕命令與檔案服務 |
| 遠端命令 | 正確回傳退出碼、stdout、stderr |
| 命令越界 | 無法存取 Server 管理資料 |
| 上傳檔案 | 取得 OTP、加密上傳、自動解封裝 |
| 下載檔案 | 取得 OTP、加密下載、自動解封裝 |
| 明文檔案傳輸 | 拒絕 |
| 錯誤 Transfer OTP | 解密失敗，不提交檔案 |
| 加密區塊遭竄改 | 驗證失敗 |
| 上傳中斷 | 可恢復，不重傳已驗證區塊 |
| 下載中斷 | 可恢復，不重傳已驗證區塊 |
| Server 重啟 | 可恢復符合條件的傳輸 |
| 跨使用者存取 | 拒絕 |
| 壓縮炸彈與路徑穿越 | 拒絕且不污染工作區 |
| 重複 Request ID | 不產生重複副作用 |
| 安裝失敗 | 可回滾，不破壞既有資料 |

驗收除了檢查成功結果，也必須包含故障注入：網路斷線、程序終止、磁碟空間不足、資料損毀、金鑰撤銷與權限變更。

## 十二、版本邊界

**CS v0.1 必須完成**

認證與使用者管理、Enrollment OTP、Transfer OTP、遠端命令、加密壓縮檔傳輸、斷點續傳、安全工作區、Session 結果查詢、Linux Server 與跨平台 Client 安裝。

---

**不納入 CS v0.1**

Job Manager 整合、Worker/Agent、工作排程、AI Provider 調度、分散式運算資源管理、Web 管理看板。

---

## 十三、仍需在實作前固定的技術決策

整體功能已明確，但以下細節必須在開發前寫入協定，避免 Client 與 Server 各自實作出不相容的行為：

1. **封裝格式**：確定 Zstandard 的容器結構、檔案清單、版本欄位及加密區塊格式。
2. **Transfer OTP 生命週期**：區分單次傳輸、續傳有效期限、完成核銷與密鑰清理。
3. **金鑰持久化**：Server 重啟後如何安全恢復尚未完成的傳輸。
4. **沙箱實作**：選定 Ubuntu 20.04／22.04 均可驗證的非 root 隔離方案。
5. **檔案提交語義**：同名檔案覆蓋、目錄更新、失敗回滾及下載包建立方式。
6. **管理員認證**：本機管理 CLI 如何取得 CS 管理權限，而不依賴 Server 以 root 執行。

**最終規格定位：CS 是一套獨立、非 root 執行、Server 統一核發傳輸密鑰、支援加密壓縮檔續傳與安全遠端命令的 Client–Server 通訊服務。**

目前這份是設計規格，不代表功能已實作或驗證。