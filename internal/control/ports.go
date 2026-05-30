// Package control は SR Policy アーキテクチャ(RFC 9256)の headend 制御を担う。
// 受信した candidate path 群から active CP を選び、その BSID/SID-list を
// データプレーンに instantiate する。具象(gobgp/VPP)には依存せず、ここで定義する
// 抽象(Source/Programmer/PolicyTransform)のみに依存する(依存性逆転)。
package control

import (
	"context"

	"github.com/ryskn/safi73-vpp/internal/srpolicy"
)

// Source は candidate path イベントの供給源(制御プレーン)。
type Source interface {
	Subscribe(ctx context.Context, handler func(srpolicy.Event)) error
}

// Programmer は active candidate path を適用する先(データプレーン)。
type Programmer interface {
	Add(cp srpolicy.CandidatePath) error
	Remove(cp srpolicy.CandidatePath) error
}

// PolicyTransform は instantiate 前に active CP を加工する拡張点(OCP)。uSID 圧縮など。
type PolicyTransform interface {
	Apply(cp srpolicy.CandidatePath) srpolicy.CandidatePath
}

type identityTransform struct{}

func (identityTransform) Apply(cp srpolicy.CandidatePath) srpolicy.CandidatePath { return cp }
