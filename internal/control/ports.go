// Package control は SR Policy イベントをデータプレーンへ反映する高レベル制御を担う。
// 具象(gobgp/VPP)には依存せず、ここで定義する抽象(Source/Programmer/Store/PolicyTransform)
// のみに依存する(依存性逆転)。各抽象は利用側であるこのパッケージが定義し、
// adapter 側が暗黙的に満たす。
package control

import (
	"context"

	"github.com/ryskn/safi73-vpp/internal/srpolicy"
)

// Source は SR Policy イベントの供給源(制御プレーン)の抽象。
type Source interface {
	// Subscribe は ctx 終了か供給源切断まで、各イベントを handler に渡し続ける。
	Subscribe(ctx context.Context, handler func(srpolicy.Event)) error
}

// Programmer は SR Policy を適用する先(データプレーン)の抽象。
type Programmer interface {
	Add(p srpolicy.Policy) error
	Remove(p srpolicy.Policy) error
}

// Store は投入済み Policy の追跡(状態管理という別関心)の抽象。
type Store interface {
	Get(key srpolicy.Key) (srpolicy.Policy, bool)
	Put(p srpolicy.Policy)
	Delete(key srpolicy.Key)
}

// PolicyTransform はデータプレーン投入前に Policy を加工する拡張点。
// 新しい変換(uSID 圧縮など)を Reconciler 本体を変えずに足せる(開放閉鎖)。
type PolicyTransform interface {
	Apply(p srpolicy.Policy) srpolicy.Policy
}

// identityTransform は何もしない既定の変換。
type identityTransform struct{}

func (identityTransform) Apply(p srpolicy.Policy) srpolicy.Policy { return p }
