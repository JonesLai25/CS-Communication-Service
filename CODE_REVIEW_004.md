# Code Review 004：Local First 驗收修正

| 項目 | 實作與證據 |
|---|---|
| CR-023 | 修正舊有 QEMU／KVM 不存在說法。宿主 QEMU 6.2.0、qemu-img/qemu-nbd、TCG 與 KVM 存在；沙箱未暴露 /dev/kvm，但宿主 KVM API 12 查詢及無記憶體空 VM 建立成功。實際 TCG 訪客啟動另見 qemu-tcg.txt；沒有宣稱 KVM 訪客開機。 |
| CR-024 | 建立以 Ubuntu 20.04 為基礎的獨立容器使用者空間，不掛載宿主 /usr、/lib 或 venv；獨立 glibc 2.31、Python 3.8，離線以 requirements-ubuntu20.lock 安裝驗證 hash 的 wheel。24 項 Phase 1 測試通過。舊發行版 pyOpenSSL 與原 lock 的 Python 3.8/cffi 不相容，失敗輸出與新版相容組合均保留；授權標頭解析改為 Python 3.8 可用的明確 Bearer 前綴檢查。容器仍共用宿主核心，不等同 Ubuntu 20.04 原生核心驗收。 |
| CR-025 | Review Package 維持固定清單，僅加入原始碼、鎖定檔、文件與文字證據；不包含 `.local-test` image graph、QEMU 核心／initramfs、wheelhouse、任何 venv、qcow2 或其他可重建環境資料。 |

本機 TCG 測試在可用記憶體低於 200 MiB 時拒絕執行；達標時以單 CPU、64 MiB guest、144 MiB scope、32 MiB swap、無磁碟和無網路啟動 Linux，觀察 guest boot marker，再僅終止測試自己建立的 QEMU 程序。測試核心來自 Alpine HTTPS，按首次下載 SHA-256 固定；官方獨立簽章尚未驗證，僅用於隔離的測試客體。早期串列主控台設定失敗及資源預檢阻止啟動均有證據。

跨網路節點測試在 rootless 使用者命名空間新建兩個不同的 network namespace，以私有 veth 相接；兩端的非 root 程序透過兩層 TCP 代理傳遞 TLS，驗證簽章、證書 hostname、錯誤金鑰與重連查詢。未修改宿主介面；這不是跨實體主機或不同核心測試。每次測試的網路、進程、測試用金鑰及暫存目錄均回收。

Ubuntu apt/build 原始終端輸出含回車覆寫控制字元；審查包內的兩份 build 文字已正規化換行與行尾空白，以利檢視及 Git 檢查，原始位元組副本留在忽略版控的 `.local-test/evidence-raw/`，不放入精簡審查包。
