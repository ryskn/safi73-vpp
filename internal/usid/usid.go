// Package usid は SRv6 uSID (micro-segment) の carrier 圧縮ロジックを提供する。
// gobgp/VPP に依存しないドメイン補助。
package usid

import (
	"fmt"
	"net/netip"
)

// Block は uSID ブロック(共通プレフィクス)と uSID 長(ビット)を表す。
// 実用上 uSID は byte 境界 (block=/16,/24,/32,/48 等, uSID=8/16/32bit) なので、
// ここでも byte 境界のみ対応する。
type Block struct {
	Prefix   netip.Prefix // 例 fcbb:bb00::/32
	USIDBits int          // 例 16
}

// Validate は byte 境界かつ carrier に 1 個以上詰められるかを検証する。
func (b Block) Validate() error {
	if !b.Prefix.IsValid() || b.Prefix.Addr().Is4() {
		return fmt.Errorf("uSID block must be a valid IPv6 prefix")
	}
	if b.Prefix.Bits()%8 != 0 {
		return fmt.Errorf("uSID block length %d must be byte-aligned", b.Prefix.Bits())
	}
	if b.USIDBits <= 0 || b.USIDBits%8 != 0 {
		return fmt.Errorf("uSID length %d must be a positive multiple of 8", b.USIDBits)
	}
	if b.PerCarrier() < 1 {
		return fmt.Errorf("uSID length %d too large for block /%d", b.USIDBits, b.Prefix.Bits())
	}
	return nil
}

// PerCarrier は 1 つの 128bit carrier に詰められる uSID 数。
func (b Block) PerCarrier() int {
	return (128 - b.Prefix.Bits()) / b.USIDBits
}

// Contains は addr が block 配下かを返す。
func (b Block) Contains(addr netip.Addr) bool {
	return addr.Is6() && b.Prefix.Contains(addr)
}

// isSingleUSID は addr が「block + uSID 1 個 + 残り全ゼロ」の形かを返す。
// block 配下でも、複数 uSID が既に詰まった carrier や uSID 部が全ゼロのアドレスは
// 単一 uSID ではないので圧縮してはいけない(ビットを黙って落とすことになる)。
func (b Block) isSingleUSID(addr netip.Addr) bool {
	blockBytes := b.Prefix.Bits() / 8
	usidBytes := b.USIDBits / 8
	s := addr.As16()

	usidZero := true
	for _, x := range s[blockBytes : blockBytes+usidBytes] {
		if x != 0 {
			usidZero = false
			break
		}
	}
	if usidZero {
		return false
	}
	for _, x := range s[blockBytes+usidBytes:] {
		if x != 0 {
			return false
		}
	}
	return true
}

// Compact は block 配下の単一 uSID アドレス列を、最小数の carrier に詰め直す。
// 圧縮対象外のアドレス(block 外、または単一 uSID の形でないもの)は、その時点の
// carrier を確定し単独で温存する(mixed list でも順序と意味を壊さない)。
func (b Block) Compact(sids []netip.Addr) []netip.Addr {
	blockBytes := b.Prefix.Bits() / 8
	usidBytes := b.USIDBits / 8
	per := b.PerCarrier()
	blockPrefix := b.Prefix.Masked().Addr().As16()

	var out []netip.Addr
	var cur [16]byte
	count := 0

	flush := func() {
		if count == 0 {
			return
		}
		out = append(out, netip.AddrFrom16(cur))
		cur = [16]byte{}
		count = 0
	}

	for _, sid := range sids {
		if !b.Contains(sid) || !b.isSingleUSID(sid) {
			flush()
			out = append(out, sid) // 圧縮対象外はそのまま
			continue
		}
		if count == 0 {
			copy(cur[:blockBytes], blockPrefix[:blockBytes])
		}
		s := sid.As16()
		pos := blockBytes + count*usidBytes
		copy(cur[pos:pos+usidBytes], s[blockBytes:blockBytes+usidBytes])
		count++
		if count == per {
			flush()
		}
	}
	flush()
	return out
}
