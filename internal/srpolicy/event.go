package srpolicy

// Event は制御プレーンから届く candidate path の更新通知。
// Key はその CP が属する SR Policy <color, endpoint>。
type Event struct {
	Key      PolicyKey
	Path     CandidatePath
	Withdraw bool
}
