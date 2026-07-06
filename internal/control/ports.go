// Package control は SR Policy アーキテクチャ(RFC 9256)の headend 制御を担う。
// 受信した candidate path 群から active CP を選び、その BSID/SID-list を
// データプレーンに instantiate する。具象(gobgp/VPP)には依存せず、ここで定義する
// 抽象(Source/Programmer/PolicyTransform)のみに依存する(依存性逆転)。
package control

import (
	"context"
	"net/netip"

	"github.com/ryskn/safi73-vpp/internal/srpolicy"
)

// Source は candidate path イベントの供給源(制御プレーン)。
// synced は初期同期(既存 best path の再生)が完了した時点で 1 回呼ぶ。
// handler と synced は別 goroutine から呼ばれてもよい(Reconciler 側で直列化する)。
type Source interface {
	Subscribe(ctx context.Context, handler func(srpolicy.Event), synced func()) error
}

// Programmer は active candidate path を適用する先(データプレーン)。
//
//   - Add は冪等: 同じ BSID の policy が既に居れば置き換える(再起動後の再同期)。
//   - Replace は active CP の切替。BSID が変わる場合は make-before-break
//     (新を入れてから旧を消す)、同一 BSID なら in-place の差分更新を行う。
//   - Remove は冪等: 対象が無ければ成功扱い。
type Programmer interface {
	Add(key srpolicy.PolicyKey, cp srpolicy.CandidatePath) error
	Replace(key srpolicy.PolicyKey, prev, next srpolicy.CandidatePath) error
	Remove(key srpolicy.PolicyKey, cp srpolicy.CandidatePath) error
}

// Resyncer は起動時再同期のための任意ポート。Programmer 実装がこれも満たす場合、
// Reconciler は起動時に dataplane の既存 policy を把握し、初期同期完了後に
// どの candidate path にも対応しない残骸(orphan)を削除できる。
type Resyncer interface {
	InstalledBSIDs() ([]netip.Addr, error)
	RemoveBSID(bsid netip.Addr) error
}

// SIDResolver は SID の到達性を dataplane の FIB で確認する任意ポート。
// RFC 9256 §5.1 の first-SID 解決 / V-Flag の SID verification に使う。
type SIDResolver interface {
	SIDReachable(sid netip.Addr) (bool, error)
}

// PolicyTransform は妥当性判定・選択の前に CP を加工する拡張点(OCP)。uSID 圧縮など。
// 変換は CP の識別子(protocol-origin / originator / discriminator)と preference を
// 変えてはならない。SID-list の妥当性(RFC 9256 §5.1)は変換後の姿で判定される。
type PolicyTransform interface {
	Apply(cp srpolicy.CandidatePath) srpolicy.CandidatePath
}

type identityTransform struct{}

func (identityTransform) Apply(cp srpolicy.CandidatePath) srpolicy.CandidatePath { return cp }
