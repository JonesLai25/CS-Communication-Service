# CS Linux 安裝與升級

本發行檔為 x86-64 Linux、Python 3.12，wheel 為 manylinux2014；Ubuntu 20.04／22.04 原生 System Mode 部署尚待驗收。需要 Python 3.12 venv、systemd、Bubblewrap、libseccomp、user namespace、受委派 cgroup v2；遠端 exec 還需服務身分可用的 systemd user manager。設定未達安全條件時 exec 停用，其他服務可繼續；不得改成無隔離執行。

Ubuntu 20.04／22.04 的預設系統 Python 不應假設為 3.12；可由管理者事先安裝與維護相容的 Python 3.12，或使用隨交付獨立提供的 `CS-python-3.12.16-linux-x86_64.tar.gz`。該離線 runtime 源自 python-build-standalone 20261123，原始檔 SHA-256 為 `c85811d35971d06612585a057db3b71806378df6ea8476275fb16aa5c9fe56a0`；應經可信管道驗證來源及摘要後，解壓至安裝者擁有且權限安全的持久位置，再以該位置的 `bin/python3` 傳入以下 `--python`。Python runtime 為獨立第三方組件，應依其授權及安全更新政策維護；不可在執行中的版本下移動或刪除。發行包的 wheelhouse 已提供鎖定 hash 的離線依賴，安裝不需連網。

先以可信管道取得及比對整份發行檔 SHA-256，解壓至受信任的私有目錄後核對 `SHA256_MANIFEST.json`。manifest 自身不是簽章，不能取代可信發行渠道。以下以解壓後目錄為目前目錄；`PREFIX` 必須是由安裝者管理的全新絕對路徑，其父目錄必須存在且安全。

User Mode（非 root）：

```sh
"$PYTHON312" phase6/installer.py install --prefix "$PREFIX" --python "$PYTHON312" --wheelhouse "$PWD/wheels" --lock "$PWD/phase3/requirements-ubuntu20-py312.lock"
"$PREFIX/bin/cs-server" initialize --port 18443 --enable-exec
# 設定 config/server.json 的 storage_capacity_mib，詳見管理手冊，再啟動。
"$PREFIX/bin/cs-server" unit install --mode user
"$PREFIX/bin/cs-server" unit start --mode user
"$PREFIX/bin/cs-server" unit status --mode user
```

System Mode 須由已獲授權的管理者自行執行，安裝工具不提權、不自行啟動服務：

```sh
"$PYTHON312" phase6/system_installer.py install --prefix "$PREFIX" --python "$PYTHON312" --wheelhouse "$PWD/wheels" --lock "$PWD/phase3/requirements-ubuntu20-py312.lock" --service-user csservice --enable-exec
# 設定 config/server.json 的 storage_capacity_mib 後，再啟動。
systemctl --system daemon-reload
"$PREFIX/bin/cs-server" unit start --mode system --service-user csservice
"$PREFIX/bin/cs-server" unit status --mode system --service-user csservice
```

System Mode 安裝會建立專用非 root 帳號及 unit；需由管理者安排該帳號的 user manager。不要將 user manager 和 CS Server 當成 root 執行。首次自簽憑證只可透過可信管道建立信任；正式憑證管理、更新及輪替須另行安排。Client 與 Server 隨同安裝；Client 憑證及工作目錄由各使用者私有保存。

升級前備份並驗證金鑰、設定、資料庫及工作區，使用新發行檔與同一 prefix 重複上述 install；不相容 schema 會拒絕。運行中服務固定舊版，受控重啟後使用新版。確認既有資料與功能後才判定升級成功。解除安裝前由負責的管理者明確停止、停用及移除相應 unit，再執行 installer 的 `uninstall --prefix "$PREFIX"`；System Mode 使用 `phase6/system_installer.py uninstall --prefix "$PREFIX" --service-user csservice`。解除安裝保留設定、資料及身分，需依組織政策另行處理。請勿手動移除正在執行的版本。

必要的專用容量受限檔案系統及 `storage_capacity_mib` 啟動檢查，見管理手冊。若未設定，正式 Server 拒絕啟動。此檢查不自動建立 quota，也不治理系統日誌。

安裝前應將 `$PYTHON312` 設成管理者維護的 Python 3.12 執行檔絕對路徑。初始化後，將由服務使用者擁有的 `config/server.json` 設定整數 `storage_capacity_mib`；資料庫、傳輸、工作區及 socket 必須位於已由管理者設硬容量上限的同一檔案系統。服務不自行建立檔案系統或 quota。
