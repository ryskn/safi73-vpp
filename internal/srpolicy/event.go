package srpolicy

// Event は制御プレーンから届く SR Policy の更新通知(追加/更新 or 取り消し)。
type Event struct {
	Policy   Policy
	Withdraw bool
}
