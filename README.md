# safi73-vpp

gobgpd が広告する **BGP SR Policy (SAFI 73, RFC 9830)** を購読し、**RFC 9256 の SR Policy
アーキテクチャ**(candidate path 選択) に従って active candidate path を選び、
[govpp](https://github.com/FDio/govpp) 経由で **VPP の SRv6 SR Policy** として instantiate し、
endpoint への L3 steering まで入れる PoC。

- control-plane: gobgpd (gRPC `WatchEvent`)
- policy   : RFC 9256 candidate-path 選択・妥当性・failover・weighted ECMP、RFC 9830 受信規則 (RT / NO_ADVERTISE)
- data-plane: VPP 26.02 (`sr_policy_add(_v2)` / `sr_policy_mod(_v2)` / `sr_policy_del` / `sr_steering_add_del` / `sr_policies_v2_dump`)

```
gobgpd ──gRPC WatchEvent──▶ safi73-vppd ──govpp──▶ VPP /run/vpp/api.sock
       (SAFI73 best-path)        │
                                 │ decode  : NLRI+attrs → candidate path 化 + RFC 9830 受信規則 (RT 照合)
                                 │ select  : RFC 9256 §2.9 で active candidate path を選ぶ
                                 │ program : active CP を SrPolicyAdd(+Mod) / 切替は make-before-break / 同一 BSID は差分 Mod
                                 └ steer   : endpoint/128(/32) → policy の L3 steering (任意, 既定 on)
```

## 設計

RFC 9256 のロジック(candidate path の識別・妥当性・選択)と、gobgp / VPP という
「たまたま今使っているソフトウェア」の事情を混ぜないことを最優先にしている。
SR Policy の意味論は protocol/dataplane 実装が変わっても変わらないので、
それだけを `internal/srpolicy` に純関数として置き、gobgp の API 形式や VPP の
retval といった具象は adapter に閉じ込める。真ん中の `Reconciler` は
「CP 集合から active を選び、dataplane との差分を埋める」ことだけを知っていて、
相手が gobgp なのか固定イベント列なのか、VPP なのか記録用の fake なのかを知らない。

こうしておく理由は主にテスト。BGP と VPP を跨ぐ結合は実機での再現・デバッグが
高くつくので、選択ロジックはドメイン単体で、reconcile の状態遷移(failover・
再同期・BSID 競合)は fake の Source/Programmer で、VPP への API 呼び出し順
(make-before-break や -12 リカバリ)は fake channel で、それぞれ VPP・gobgpd
無しで検証できるようにしてある。

境界のインターフェース(`Source` / `Programmer` / `PolicyTransform`)は利用側の
`control` が「必要とする最小の形」で定義し、adapter 側は control を import せず
暗黙的に満たす。uSID 圧縮のような投入前変換は `PolicyTransform` の差し込みで
追加していて、Reconciler 本体には手を入れない。

```
  レイヤと依存方向 (上 → 下へ依存)

    cmd/safi73-vppd        composition root。具象を生成し Reconciler に注入する
          │ inject
          ▼
    control.Reconciler     candidate path 集約＋active 選択＋反映。Source/Programmer/Transform の抽象だけに依存
          │ uses
          ▼
    internal/srpolicy      ドメイン (CandidatePath / SelectActive など)。依存ゼロ


  抽象 (control が定義)    ←─  実装 (adapter は control を import せず暗黙的に満たす)

    control.Source          ←─  adapter/bgp.Source       gobgpd gRPC WatchEvent を購読 + RFC 9830 受信規則
    control.Programmer      ←─  adapter/vpp.Programmer    sr_policy_add/mod/del + steering (make-before-break / in-place 差分)
    control.Resyncer        ←─  adapter/vpp.Programmer    起動時再同期 (dump / orphan 削除)
    control.PolicyTransform ←─  usid.Compactor            uSID を carrier に圧縮 (任意)


  データの流れ (runtime)

    gobgpd ─▶ adapter/bgp.Source ─▶ control.Reconciler ─▶ adapter/vpp.Programmer ─▶ VPP
                                    │ (任意) PolicyTransform: usid.Compactor ← 妥当性判定・選択の前に適用
                                    │ select active CP (srpolicy.SelectActive)
```

candidate path の選択は純関数 `srpolicy.SelectActive` (ドメイン層) に切り出し、`Reconciler` は
その結果を VPP との差分に落とすだけ。状態 (SR Policy ごとの CP 集合と active、BSID 所有権) は
`Reconciler` が保持する。

## レイアウト

```
internal/srpolicy/        ドメイン層 (gobgp/VPP 非依存)
  policy.go               PolicyKey / CandidatePath / SegmentList / Originator / 妥当性
  selection.go            SelectActive: RFC 9256 §2.9 の active CP 選択 (純関数)
  event.go                Event (candidate path の追加/withdraw)
internal/control/         制御層 (抽象のみに依存)
  ports.go                Source / Programmer / Resyncer / PolicyTransform インターフェース
  reconciler.go           Reconciler: CP 集約 → active 選択 → 差分反映・再同期・BSID 競合検出
internal/usid/            uSID (micro-SID) サポート
  usid.go                 Block: uSID を 128bit carrier に圧縮する純ロジック
  transform.go            Compactor: control.PolicyTransform 実装
internal/adapter/bgp/     control.Source 実装
  source.go               gobgpd gRPC WatchEvent 購読 + SAFI73 選別 + BGP Identifier 取得
  decode.go               api.Path → srpolicy.Event (RFC 9830 受信規則 / sub-TLV デコード)
internal/adapter/vpp/     control.Programmer + Resyncer 実装
  conn.go                 govpp 接続/channel
  programmer.go           SrPolicyAdd(V2) / Mod(V2) / Del / Steering / Dump
cmd/safi73-vppd/          本体 daemon (composition root)
cmd/inject-srpolicy/      テスト用 SR Policy 注入/withdraw クライアント (RT / NO_ADVERTISE 付き)
cmd/smoke/                govpp↔VPP 疎通確認
binapi/                   VPP 26.02 の /usr/share/vpp/api から生成した govpp バインディング
```

## SR Policy アーキテクチャ (RFC 9256 / RFC 9830)

受信した各 BGP 経路を **candidate path** に変換し、SR Policy `<color, endpoint>` ごとにまとめて、
妥当な CP の中から **active candidate path** を 1 本選んで instantiate する。

**受信規則** (RFC 9830 §4.2) — update が使えるのは次の場合のみ:

- Route Target 拡張コミュニティが自ノードの **BGP Identifier** に一致する (`-router-id` または gobgpd の `GetBgp` から取得)
- RT が無い場合は **NO_ADVERTISE** community が付いている

RT も NO_ADVERTISE も無い update は malformed (§4.2.1)、RT 不一致は not usable (§4.2.2) として
**treat-as-withdraw** で SRPM から除去する。gobgpd 自体はこの検証をしない(TODO のまま)ため本 daemon で行う。

**candidate path の識別** (RFC 9256 §2.3-2.6 / RFC 9830 §2.1)

| RFC 9256 | 由来 (BGP) |
|---|---|
| SR Policy = `<color, endpoint>` | NLRI の color / endpoint |
| Protocol-Origin | BGP = `20` 固定 |
| Originator ASN | 経路の source-AS |
| Originator node | **Route Origin community > ORIGINATOR_ID > peer router-id** (RFC 9830 §2.1 の優先順) |
| Discriminator | NLRI の distinguisher |
| Preference / Priority / BSID / Segment List | Tunnel Encap (type 15 のみ) sub-TLV |

CP の集約キーは **distinguisher**。gobgp の TYPE_BEST 購読では BGP best-path 選択が先に走るため
1 distinguisher = 1 CP であり (RFC 9830 §2.5)、originator が変わる best 切替も「同じ distinguisher
の置換」として扱う (gobgp は旧 best の withdraw を流さないため、originator をキーに含めると幽霊 CP が残る)。

**sub-TLV の扱い** (RFC 9830 §2.4)

- Preference (12): 不在時は既定 **100** (RFC 9256 §2.7)。単一インスタンス sub-TLV の重複は最初を採用
- Binding SID (13) と **SRv6 Binding SID (20)** の両対応。type 20 は gobgp がパースしないため raw bytes を自前デコードし、両方あれば type 20 優先 (§2.4.2)
- BSID の S-Flag (Specified-BSID-only) / I-Flag (Drop-upon-invalid) を読み取り。I-Flag は VPP に相当機能が無いため**未対応 (警告ログのみ)**
- Segment List (128): 複数可 (weighted ECMP)。Weight (9) 不在は既定 1 (RFC 9256 §2.2)、明示 0 は invalid
- Segment Type B (SRv6 SID) のみ対応。**Type A (SR-MPLS) が混ざった list は list ごと invalid** (RFC 9256 §5.1 の混在禁止 — 部分的に使わない)

**active candidate path 選択** (§2.9) — 妥当な CP のうち:

1. **Preference** が高いもの
2. (同値) **Protocol-Origin** が高いもの (PCEP=10 < BGP=20 < Config=30)
3. (同値) 既存導入 CP を優先 (§2.9 規則 2 の config 選択肢。フラップ抑制のため常時有効)
4. (同値) **Originator** が低いもの (160bit = ASN+node)
5. (同値) **Discriminator** が高いもの

**妥当性** (§5.1): SID-list は 空 / weight==0 / SR-MPLS と SRv6 の混在 / **16 SID 超**
(VPP binary API の上限。切り詰めず invalid にする) で無効。CP は妥当な SID-list を 1 本以上持てば valid。
妥当性は **PolicyTransform (uSID 圧縮) 適用後** に評価する — 圧縮で 16 SID 以内に収まる CP は valid。
SR Policy は妥当な CP を 1 本以上持てば up。無効・全 withdraw なら down (VPP から削除)。

**BSID** (§6.1/§6.2): 異なる SR Policy 間の BSID 重複は禁止 — 競合 CP は候補から除外し alert ログを出す。

**weighted ECMP** (§2.11): active CP の各 SID-list を weight `w/Σw` で負荷分散 (VPP の load-balance)。

**VPP マッピング**

| 要素 | VPP |
|---|---|
| active CP の Binding SID | `bsid_addr` (SR Policy のキー) |
| Segment List (SegmentTypeB) | `Srv6SidList` (最大 16 SID) |
| 2 本目以降の Segment List (weighted) | `sr_policy_mod` operation=ADD |
| active CP 切替 (BSID 変更) | **make-before-break**: 新 add → steering 付替え → 旧 del |
| active CP 更新 (同一 BSID) | `sr_policies_with_sl_index_dump` で差分をとり mod ADD→DEL (traffic 無停止) |
| endpoint への steering | `sr_steering_add_del` (L3, endpoint/128 or /32)。null endpoint (::) は対象外 |
| 再起動後の再同期 | `sr_policies_v2_dump` + 既存 BSID の置換 (add が -12 でも復旧)。`-orphan-gc` で残骸削除 |

### RFC からの意図的な逸脱 / 制限

- **BSID 必須**: BSID の無い CP は invalid 扱い (RFC 9256 §6.2.1 の動的割当は未実装)。VPP が BSID を
  policy のキーにするため、実質 **Specified-BSID-only (§6.2.3)** 相当で動く
- **first-SID 到達性検証 (§5.1) / V-Flag の SID verification は未実施**: 到達不能な SID でも instantiate される
- **I-Flag (Drop-upon-invalid, §8.2) 未対応**: invalid 時は削除 (IGP フォールバック) になる。検出時は警告ログ
- Priority (§2.12) はデコードするが再計算順序制御には未使用
- ENLP は SR-MPLS 用のため対象外

## uSID (micro-SID)

`-usid-block <prefix>` を指定すると、BGP で受けた segment list 中の per-node uSID
(block 配下の**単一 uSID** アドレス) を 128bit の uSID carrier に圧縮してから VPP に投入する。

```sh
safi73-vppd -usid-block fcbb:bb00::/32 -usid-len 16   # block /32 + 16bit uSID → 1 carrier に最大 6 個
```

例: BGP segment list `[fcbb:bb00:1::, fcbb:bb00:2::, fcbb:bb00:3::]`
→ 圧縮 → VPP の SID リストは `[fcbb:bb00:1:2:3::]` (1 carrier)。単一 SID になった場合、
VPP は **SRH 無し (IPv6-in-IPv6)** で carrier を outer DA に載せる。中継ノードは
`sr localsid prefix fcbb:bb00:1::/48 behavior un 16` (uN) で先頭 uSID を pop し、
DA を `fcbb:bb00:2:3::` にシフトして転送する。

- block 配下でも「block + 1 uSID + 残り全ゼロ」の形でないアドレス (既に複数 uSID が詰まった
  carrier など) は**圧縮せずそのまま温存**する (ビットを黙って落とさない)
- 圧縮は妥当性判定の**前**に適用されるため、素のままでは 16 SID を超える list も圧縮後に収まれば valid
- 注意: VPP の複数 SID encap は T.Encaps (先頭 SID も SRH に入る) であり T.Encaps.Red ではない

## ビルド / テスト

```sh
go build ./...
go test  ./...   # 全レイヤ VPP・gobgp 無しで検証可能 (fake Source/Programmer/Channel)
```

`binapi/` は生成物。VPP バージョンを変えたら再生成する:

```sh
binapi-generator --input=/usr/share/vpp/api --output-dir=./binapi \
  --import-prefix=github.com/ryskn/safi73-vpp/binapi \
  memclnt vpe interface interface_types ip ip_types sr sr_types
```

## 動作確認 — 自己完結 eBGP ラボ (外部 peer 不要)

1 ホスト上で gobgpd を 2 台立て、loopback 越し eBGP を張る。A=本体が watch する側、B=SR Policy 広告役。

| | AS | router-id | listen | gRPC | role |
|---|---|---|---|---|---|
| A (`gobgpd-a.toml`) | 64514 | 192.168.1.15 | 127.0.0.1:179 | :50051 | safi73-vppd が watch |
| B (`gobgpd-b.toml`) | 64515 | 192.168.1.115 | 127.0.0.2:179 | :50052 | SR Policy 広告役 |

```sh
# 1. gobgpd 2 台 (179 バインドは要 root)
sudo gobgpd -f gobgpd-a.toml &
sudo gobgpd -f gobgpd-b.toml --api-hosts 127.0.0.1:50052 &
gobgp neighbor                       # 127.0.0.2 ... Establ

# 2. connector
sudo ./safi73-vppd &                 # /run/vpp/api.sock へ

# 3. B に SR Policy を入れる → eBGP で A へ → VPP
#    RT は A の BGP Identifier (router-id)。RT 無しだと NO_ADVERTISE が付き B から出ない。
go run ./cmd/inject-srpolicy --gobgp 127.0.0.1:50052 --rt 192.168.1.15 \
  --color 100 --bsid 2001:db8:b::1 --segments 2001:db8:cafe::1,2001:db8:cafe::2
gobgp neighbor 127.0.0.2             # Received: 1 / Accepted: 1
sudo vppctl show sr policies         # BSID 2001:db8:b::1 が出る
sudo vppctl show sr steering-policies # endpoint/128 → policy

# 4. withdraw
go run ./cmd/inject-srpolicy --gobgp 127.0.0.1:50052 --rt 192.168.1.15 \
  --color 100 --bsid 2001:db8:b::1 --segments 2001:db8:cafe::1 --withdraw
sudo vppctl show sr policies         # 空

# 後片付け
sudo pkill -f gobgpd ; sudo pkill -f safi73-vppd
```

## 本番接続 (実 peer)

gobgpd の設定に neighbor を追加し `afi-safi-name = "ipv6-srpolicy"` を有効化、

```sh
sudo ./safi73-vppd -gobgp <gobgpd:50051> -vpp /run/vpp/api.sock \
  -encap -encap-src 2001:db8:fe::1 -fib 0 -steer -orphan-gc
```

| flag | 既定 | 説明 |
|---|---|---|
| `-gobgp` | 127.0.0.1:50051 | gobgpd gRPC API |
| `-router-id` | (gobgpd から取得) | RT 照合に使う自ノードの BGP Identifier |
| `-vpp` | /run/vpp/api.sock | VPP binary API socket |
| `-encap` | true | encap モード (T.Encaps) |
| `-encap-src` | (VPP グローバル) | per-policy の outer IPv6 送信元 (`sr_policy_add_v2`) |
| `-policy-type` | default | default / spray / tef (`sr_policy_add_v2`) |
| `-fib` | 0 | BSID を置く VRF **兼 encap 後の egress lookup テーブル** (VPP の仕様で両方に効く) |
| `-steer` | true | endpoint/128(/32) → policy の L3 steering を自動投入 |
| `-orphan-gc` | false | 初期同期後、BGP 側に CP が無い VPP 上の policy を削除。**VPP を他の管理主体と共有しているなら off のまま** |
| `-usid-block` / `-usid-len` | (無効) | uSID carrier 圧縮 |

運用ノート:

- **encap source**: VPP のグローバル encap source の初期値は `::`。`-encap-src` を使わないなら
  `vppctl set sr encaps source addr <ip6>` が必須 (未設定だと outer src が `::` で出る)
- **hop limit**: `vppctl set sr encaps hop-limit <n>` (既定 64)。encap source / hop limit は
  SID-list 作成時に rewrite に焼き込まれるため、変更は既存 policy に遡及しない (再投入が必要)
- gobgpd 再起動・ストリーム断では daemon は落ちず再購読する。再購読の初期 dump に現れなかった
  CP は世代 sweep で除去される
- daemon 再起動時は `sr_policies_v2_dump` で既存 policy を検出し、同じ BSID は置換で引き継ぐ
- **16 SID 超の segment list** は VPP binary API の制約で invalid 扱い (silent truncation はしない)。
  また VPP 既定ビルドの encap headroom (`PRE_DATA_SIZE` 128B) では実用上 ~5 SID 程度が上限

## 動作環境

Ubuntu 24.04 / Go 1.26 / VPP 26.02 (fd.io apt) / gobgp v4.5 で確認。
