# 檔案傳輸設計草案

Server 對每次授權傳輸生成 Transfer ID 與 256-bit Transfer OTP，以 HPKE 傳給已註冊 Client；上傳由 Client 壓縮加密、Server 驗證並解封；下載從已授權索引的 outgoing 包取得、由 Server 加密，Client 驗證解封。TLS 與封裝加密皆不可省略。

候選版本化容器：受認證 manifest 描述格式版本、transfer ID、方向、壓縮後長度、chunk size/count、封裝 SHA-256；Zstandard 壓縮檔案樹，AES-256-GCM 每塊獨立驗證；AAD 綁定 manifest 摘要、transfer ID、方向、區塊序號與長度。每 transfer 使用 HKDF 衍生獨立 key；候選 nonce 為固定 32-bit domain + 64-bit big-endian chunk index，嚴格禁止同 key/index 加密不同明文，限定區塊數並持久化已加密 ciphertext 供重送。最終格式、manifest 認證、長度與上限需經密碼學審查及互通測試後凍結，不得自行發明 HPKE。

上傳及下載須保留原始壓縮包與 ciphertext，直到完成或到期；傳輸 key 在兩端以當地受保護方式持久化以跨重啟續傳。Server 重啟後重新授權並核對 hash 與已驗證區塊，補傳缺塊；原始內容改變則新建 transfer，不能重用 key/nonce。驗證 AEAD 後才標記區塊，整包完成後驗 SHA-256。

解壓時限制檔案數、深度、大小、時間與配額，拒絕絕對路徑、`..`、符號連結、特殊檔及硬連結，採不跟隨連結的目錄相對操作；檢查 Unicode 路徑和檔案名稱碰撞。先寫同檔案系統隔離 staging，再原子 rename 到不存在的目標；v0.1 預設同名拒絕，避免非空目錄覆蓋的原子性假設。下載端也採同規則。檔案與目錄 fsync、durable journal 及 crash 注入驗證提交語義。清除金鑰是刪除受保護記錄，不保證 SSD 物理抹除。
