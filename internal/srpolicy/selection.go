package srpolicy

// SelectActive は RFC 9256 §2.9 に従い active candidate path を選ぶ。
// valid な CP が無ければ ok=false。
//
// current/hasCurrent は「既存導入パス優先」(§2.9 規則2, 安定化)のために、
// いま active な CP のキーを渡す(初回は hasCurrent=false)。
func SelectActive(cps []CandidatePath, current CPKey, hasCurrent bool) (CandidatePath, bool) {
	var best CandidatePath
	found := false
	for _, cp := range cps {
		if !cp.Valid() {
			continue
		}
		if !found || preferred(cp, best, current, hasCurrent) {
			best, found = cp, true
		}
	}
	return best, found
}

// preferred は a が b より優先されるか(RFC 9256 §2.9)を返す。
// 1.Preference 高 → 2.Protocol-Origin 高 → 3.既存導入パス → 4.Originator 低 → 5.Discriminator 高
func preferred(a, b CandidatePath, current CPKey, hasCurrent bool) bool {
	if a.Preference != b.Preference {
		return a.Preference > b.Preference
	}
	if a.Origin != b.Origin {
		return a.Origin > b.Origin
	}
	if hasCurrent {
		ac, bc := a.Key() == current, b.Key() == current
		if ac != bc {
			return ac // 既存導入パスを優先(フラップ抑制)
		}
	}
	if c := a.Originator.Compare(b.Originator); c != 0 {
		return c < 0 // originator は低い方
	}
	return a.Discriminator > b.Discriminator
}
