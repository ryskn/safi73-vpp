// Package srpolicy は BGP SR Policy (SAFI 73) を、制御プレーン(gobgp)とデータプレーン
// (VPP)のどちらの実装詳細にも依存しない形で表すドメイン層。
package srpolicy

import (
	"fmt"
	"net/netip"
)

// SegmentList は SR Policy の candidate path 1 本分の SID リスト。
type SegmentList struct {
	Weight uint32
	SIDs   []netip.Addr // SRv6 SID。headend で最初に処理する SID が先頭。
}

// Policy は SAFI 73 経路 1 本を表すドメインモデル。
type Policy struct {
	Distinguisher uint32
	Color         uint32
	Endpoint      netip.Addr
	BSID          netip.Addr
	Preference    uint32
	SegmentLists  []SegmentList
}

// Key は NLRI 由来の一意キー。BSID が無い withdraw でも追跡できるよう NLRI から作る。
type Key string

// Key は Policy を一意に識別するキーを返す。
func (p Policy) Key() Key {
	return Key(fmt.Sprintf("%d|%d|%s", p.Distinguisher, p.Color, p.Endpoint))
}

// ValidateSRv6 は SRv6 SR Policy として成立しているかを検証し、不成立なら理由を返す。
func (p Policy) ValidateSRv6() error {
	if !p.BSID.Is6() || p.BSID.Is4In6() {
		return fmt.Errorf("binding SID %q is not IPv6", p.BSID)
	}
	if len(p.SegmentLists) == 0 {
		return fmt.Errorf("no segment lists")
	}
	for i, sl := range p.SegmentLists {
		if len(sl.SIDs) == 0 {
			return fmt.Errorf("segment list %d is empty", i)
		}
		for j, sid := range sl.SIDs {
			if !sid.Is6() || sid.Is4In6() {
				return fmt.Errorf("segment list %d sid %d %q is not IPv6", i, j, sid)
			}
		}
	}
	return nil
}
