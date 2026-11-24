# 狀態與恢復草案

Request：created → authorized → running → succeeded / failed / cancelled / timeout；程序或主機故障後不可證明結果時為 unknown。狀態轉移以交易及版本條件更新；terminal 狀態不得重啟。取消與完成競爭時以持久化結果為準；取消不保證撤銷已發生的外部副作用。

Transfer：created → authorized → transferring → verifying → extracting → committing → succeeded；中斷可轉 interrupted → resuming → transferring；另有 failed、cancelled、expired。commit 前均不可對正式目的地顯示部分內容。區塊落盤並持久記錄驗證後才能回報已驗證；重啟重驗狀態，無法證實者重新接收。有效期限、撤銷、owner 與原始封裝識別都必須再驗證；不把 session 斷線當作 transfer 失敗。提交中斷需依 durable journal 與檔案系統狀態決定完成或回滾；不可推測成功。
