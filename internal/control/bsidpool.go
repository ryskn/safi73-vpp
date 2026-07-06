package control

import "net/netip"

// bsidPool は BSID 未指定の candidate path に動的 BSID を割り当てるプール
// (RFC 9256 §6.2.1)。指定 prefix の host 部を連番で払い出す。
type bsidPool struct {
	prefix netip.Prefix
	next   uint64
}

func newBSIDPool(prefix netip.Prefix) *bsidPool {
	return &bsidPool{prefix: prefix.Masked()}
}

// alloc は used が false を返す未使用アドレスを払い出す。プール枯渇なら ok=false。
func (p *bsidPool) alloc(used func(netip.Addr) bool) (netip.Addr, bool) {
	hostBits := 128 - p.prefix.Bits()
	max := uint64(1)<<16 - 1 // 走査上限(1 プールに 65535 個あれば PoC には十分)
	if hostBits < 16 {
		max = uint64(1)<<hostBits - 1
	}
	base := p.prefix.Addr().As16()

	for range max {
		p.next++
		if p.next > max {
			p.next = 1
		}
		a := base
		v := p.next
		for i := 15; i >= 0 && v > 0; i-- {
			a[i] = byte(v)
			v >>= 8
		}
		addr := netip.AddrFrom16(a)
		if !used(addr) {
			return addr, true
		}
	}
	return netip.Addr{}, false
}
