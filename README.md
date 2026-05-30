# safi73-vpp

gobgpd が広告する **BGP SR Policy (SAFI 73)** を購読し、**RFC 9256 の SR Policy アーキテクチャ**
(candidate path 選択) に従って active candidate path を選び、[govpp](https://github.com/FDio/govpp)
経由で **VPP の SRv6 SR Policy** として instantiate する PoC。

- control-plane: gobgpd (gRPC `WatchEvent`)
- policy   : RFC 9256 candidate-path 選択 (preference → protocol-origin → originator → discriminator)・妥当性・failover・weighted ECMP
- data-plane: VPP 26.02 (`sr_policy_add` / `sr_policy_mod` / `sr_policy_del`)

```
gobgpd ──gRPC WatchEvent──▶ safi73-vppd ──govpp──▶ VPP /run/vpp/api.sock
       (SAFI73 best-path)        │
                                 │ decode    : 各 NLRI+attrs を candidate path 化 (color/endpoint で SR Policy にまとめる)
                                 │ select     : RFC 9256 §2.9 で active candidate path を選ぶ
                                 └ program  : active CP のみ SrPolicyAdd(+Mod で weighted SL) / 切替・無効化→SrPolicyDel
```

## 設計 (SOLID)

レイヤを「ドメイン / 制御 / adapter」に分け、依存はすべて内側(ドメイン)へ向かう。
`Reconciler` は gobgp/VPP の具象を知らず、抽象だけに依存する (依存性逆転)。

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

    control.Source          ←─  adapter/bgp.Source       gobgpd gRPC WatchEvent を購読
    control.Programmer      ←─  adapter/vpp.Programmer    govpp で sr_policy_add/mod/del
    control.PolicyTransform ←─  usid.Compactor            uSID を carrier に圧縮 (任意/OCP)


  データの流れ (runtime)

    gobgpd ─▶ adapter/bgp.Source ─▶ control.Reconciler ─▶ adapter/vpp.Programmer ─▶ VPP
                                    │ select active CP (srpolicy.SelectActive)
                                    │ (任意) PolicyTransform: usid.Compactor
```

candidate path の選択は純関数 `srpolicy.SelectActive` (ドメイン層) に切り出し、`Reconciler` は
その結果を VPP との差分に落とすだけ。状態 (SR Policy ごとの CP 集合と active) は `Reconciler` が保持する。

| 原則 | 反映箇所 |
|------|----------|
| **S** 単一責任 | `srpolicy`(モデル＋選択) / `control`(反映と状態) / `adapter/bgp`(購読・デコード) / `adapter/vpp`(投入) / `usid`(圧縮) を分離 |
| **O** 開放閉鎖 | 投入前に `PolicyTransform` を差し込める。例: `usid.Compactor` で uSID 圧縮を `Reconciler` 無変更で追加。供給源・投入先も差し替え可能 |
| **L** リスコフ | `Source`/`Programmer` のどの実装でも `Reconciler` は同じ契約で動く(fake で代替してテスト) |
| **I** インターフェース分離 | `Programmer` は `Add`/`Remove` のみ等、利用側が必要とする最小の口だけを定義 |
| **D** 依存性逆転 | `Reconciler` は具象(gobgp/VPP)を知らず抽象のみに依存。結線は composition root に集約 |

抽象(`Source`/`Programmer`/`PolicyTransform`)は利用側 `control` が定義し、adapter 側が暗黙的に満たす
(Go 的な DIP)。adapter は `srpolicy` ドメインにのみ依存し、`control` を import しない。

## レイアウト

```
internal/srpolicy/        ドメイン層 (gobgp/VPP 非依存)
  policy.go               PolicyKey / CandidatePath / SegmentList / Originator / 妥当性
  selection.go            SelectActive: RFC 9256 §2.9 の active CP 選択 (純関数)
  event.go                Event (candidate path の追加/withdraw)
internal/control/         制御層 (抽象のみに依存)
  ports.go                Source / Programmer / PolicyTransform インターフェース
  reconciler.go           Reconciler: CP 集約 → active 選択 → 差分を VPP へ反映 (failover 含む)
internal/usid/            uSID (micro-SID) サポート
  usid.go                 Block: uSID を 128bit carrier に圧縮する純ロジック
  transform.go            Compactor: control.PolicyTransform 実装
internal/adapter/bgp/     control.Source 実装
  source.go               gobgpd gRPC WatchEvent 購読 + SAFI73 選別
  decode.go               api.Path → srpolicy.Event
internal/adapter/vpp/     control.Programmer 実装
  conn.go                 govpp 接続/channel
  programmer.go           SrPolicyAdd / SrPolicyMod / SrPolicyDel
cmd/safi73-vppd/          本体 daemon (composition root)
cmd/inject-srpolicy/      テスト用 SR Policy 注入/withdraw クライアント
cmd/smoke/                govpp↔VPP 疎通確認
binapi/                   VPP 26.02 の /usr/share/vpp/api から生成した govpp バインディング
```

## SR Policy アーキテクチャ (RFC 9256)

受信した各 BGP 経路を **candidate path** に変換し、SR Policy `<color, endpoint>` ごとにまとめて、
妥当な CP の中から **active candidate path** を 1 本選んで instantiate する。複数 controller / 複数
candidate path が同じ SR Policy を広告しても、RFC 9256 のルールで 1 本に収束させるのが headend の責務。

**candidate path の識別** (RFC 9256 §2.3 / BGP マッピング)

| RFC 9256 | 由来 (BGP) |
|---|---|
| SR Policy = `<color, endpoint>` | NLRI の color / endpoint |
| Protocol-Origin | BGP = `20` 固定 |
| Originator `<ASN, node>` | 経路の source-AS / source-id |
| Discriminator | NLRI の distinguisher |
| Preference / Priority / BSID / Segment List | Tunnel Encap sub-TLV |

**active candidate path 選択** (§2.9) — 妥当な CP のうち:

1. **Preference** が高いもの
2. (同値) **Protocol-Origin** が高いもの (PCEP=10 < BGP=20 < Config=30)
3. (同値) 既存導入 CP を優先 (フラップ抑制)
4. (同値) **Originator** が低いもの (160bit = ASN+node)
5. (同値) **Discriminator** が高いもの

**妥当性** (§5.1): SID-list は 空 / weight==0 / SR-MPLSとSRv6混在 で無効。CP は妥当な SID-list を
1 本以上持てば valid。SR Policy は妥当な CP を 1 本以上持てば up。無効・全 withdraw なら down (VPP から削除)。
**weighted ECMP** (§2.11): active CP の各 SID-list を weight `w/Σw` で負荷分散 (VPP の `Srv6SidList.weight`)。

**VPP マッピング**

| 要素 | VPP |
|---|---|
| active CP の Binding SID | `bsid_addr` (SR Policy のキー) |
| Segment List (SegmentTypeB = SRv6 SID) | `Srv6SidList` |
| 2 本目以降の Segment List (weighted) | `sr_policy_mod` operation=ADD |
| active CP 切替 / 無効化 / withdraw | 旧 BSID を `sr_policy_del` → 新 BSID を `sr_policy_add` |

SegmentTypeA (SR-MPLS label) は対象外 (SRv6 dataplane のみ)。BSID が無い/IPv6 でない CP は無効扱い。

### 実機確認済みの挙動

- preference 違いの 2 CP → 高い方が active
- 高 preference だが **無効 (weight 0)** な CP → 選ばれない (妥当性ゲート)
- active CP を withdraw → 無効 CP を飛ばして次点へ **failover**
- 全 CP withdraw → SR Policy down (VPP から消える)
- 1 CP に weight 1 / 3 の 2 SID-list → VPP に両方 (1:3 分散)

## uSID (micro-SID)

`-usid-block <prefix>` を指定すると、BGP で受けた segment list 中の per-node uSID
(block 配下の単一 uSID アドレス) を 128bit の uSID carrier に圧縮してから VPP に投入する。

```sh
safi73-vppd -usid-block fcbb:bb00::/32 -usid-len 16   # block /32 + 16bit uSID → 1 carrier に最大 6 個
```

例: BGP segment list `[fcbb:bb00:1::, fcbb:bb00:2::, fcbb:bb00:3::]`
→ 圧縮 → VPP の SID リストは `[fcbb:bb00:1:2:3::]` (1 carrier)。単一 carrier なので
VPP は **SRH 無し (reduced encap)** で carrier を outer DA に載せる。中継ノードは
`sr localsid prefix fcbb:bb00:1::/48 behavior un 16` (uN) で先頭 uSID を pop し、
DA を `fcbb:bb00:2:3::` にシフトして転送する。

圧縮ロジックは `internal/usid` の純関数 (byte 境界の block/uSID 長に対応、単体テスト済み)。
それを `control.PolicyTransform` として composition root で注入するだけで、圧縮無効時 (既定) の
挙動は一切変わらない (OCP)。実機で headend 圧縮 → reduced encap → uN シフトまで確認済み。

## ビルド / テスト

```sh
go build ./...
go test  ./...   # control / srpolicy は VPP・gobgp 無しで検証可能 (DIP の成果)
```

`binapi/` は生成物。VPP バージョンを変えたら再生成する:

```sh
binapi-generator --input=/usr/share/vpp/api --output-dir=./binapi \
  --import-prefix=github.com/ryskn/safi73-vpp/binapi \
  memclnt vpe interface interface_types ip ip_types sr sr_types
```

## 動作確認 — 自己完結 eBGP ラボ (外部 peer 不要)

1 ホスト上で gobgpd を 2 台立て、loopback 越し eBGP を張る。A=本体が watch する側、B=SR Policy 広告役。

| | AS | listen | gRPC | role |
|---|---|---|---|---|
| A (`gobgpd-a.toml`) | 64514 | 127.0.0.1:179 | :50051 | safi73-vppd が watch |
| B (`gobgpd-b.toml`) | 64515 | 127.0.0.2:179 | :50052 | SR Policy 広告役 |

```sh
# 1. gobgpd 2 台 (179 バインドは要 root)
sudo gobgpd -f gobgpd-a.toml &
sudo gobgpd -f gobgpd-b.toml --api-hosts 127.0.0.1:50052 &
gobgp neighbor                       # 127.0.0.2 ... Establ

# 2. connector
sudo ./safi73-vppd &                 # /run/vpp/api.sock へ

# 3. B に SR Policy を入れる → eBGP で A へ → VPP
go run ./cmd/inject-srpolicy --gobgp 127.0.0.1:50052 \
  --color 100 --bsid 2001:db8:b::1 --segments 2001:db8:cafe::1,2001:db8:cafe::2
gobgp neighbor 127.0.0.2             # Received: 1 / Accepted: 1
sudo vppctl show sr policies         # BSID 2001:db8:b::1 が出る

# 4. withdraw
go run ./cmd/inject-srpolicy --gobgp 127.0.0.1:50052 \
  --color 100 --bsid 2001:db8:b::1 --segments 2001:db8:cafe::1 --withdraw
sudo vppctl show sr policies         # 空

# 後片付け
sudo pkill -f gobgpd ; sudo pkill -f safi73-vppd
```

## 本番接続 (実 peer)

gobgpd の設定に neighbor を追加し `afi-safi-name = "ipv6-srpolicy"` を有効化、

```sh
sudo ./safi73-vppd -gobgp <gobgpd:50051> -vpp /run/vpp/api.sock -encap -fib 0
```

flags: `-gobgp` / `-vpp` / `-encap`(T.Encaps, 既定 true) / `-fib`(FIB table)。

## 動作環境

Ubuntu 24.04 / Go 1.26 / VPP 26.02 (fd.io apt) / gobgp v4.5 で確認。
