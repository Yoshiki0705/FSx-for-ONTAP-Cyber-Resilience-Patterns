# ONTAP コマンドと REST API のスナップショット（FSx for ONTAP、ONTAP 9.18.1P6） / Snapshot of ONTAP Commands and REST APIs on FSx for ONTAP (ONTAP 9.18.1P6)

## 結論 / Conclusion

検証環境の ONTAP 9.18.1P6 で、`fsxadmin` が使える CLI コマンドと、この版が持つ REST API の全体を記録しました。ONTAP の版が変わると内容が変わるので、版ごとに取り直します。

| 記録したもの | 件数 | 何を表すか |
|---|---|---|
| CLI コマンド（`show-user-capability`）| 1,744 コマンド、28 のトップレベル | `fsxadmin` が実行できるコマンド |
| REST エンドポイント（`show-rest`）| 570 | この版の REST API の全体。権限に関係なく全件 |
| REST の GET 実測 | 219 エンドポイント | 167 が 200、43 が 403、9 がその他。パスパラメータのない GET だけ |
| ロール定義（`role show`）| クラスタ 6 ロール、SVM 6 ロール | 実行可否の根拠となる規則 |
| ONTAPI 対応表（`show-ontapi`）| 1,045 件、CLI 743 種 | 旧 API（ZAPI）と CLI の対応 |

**MAV は ONTAP に存在し、`fsxadmin` では使えません。** `show-rest` には `/security/multi-admin-verify` 系の7エンドポイントがあり、この版に MAV があることが分かります。一方で `fsxadmin` では、CLI の一覧に載らず、ロール定義にエントリがなく、REST の GET・POST・PATCH がすべて HTTP 403 でした。3つの面が一致しています [E-025]。ただし、1台のファイルシステム、1つの版、`fsxadmin` だけの観測です。

On ONTAP 9.18.1P6, this records the CLI commands `fsxadmin` can run (1,744) and every REST endpoint the version has (570), with one GET per parameter-free endpoint (219: 167 returned 200, 43 returned 403). MAV exists in this version (seven endpoints in `show-rest`) and is unavailable to `fsxadmin` on three independent views: absent from the CLI capability list, absent from the role definition, and HTTP 403 on every REST call [E-025]. One file system, one version, `fsxadmin` only.

---

## 5 つのコマンドの違い / What Each Command Returns

依頼にあった2つのコマンドに、実機で役割が近い3つを加えました。

| コマンド / Command | 返すもの / Returns | 権限で絞られるか / Filtered by privilege |
|---|---|---|
| `security login role show` | ロール × コマンドディレクトリ × アクセス × 条件 | 絞られない。全ロールの定義が読める |
| `security login role show-user-capability` | ログイン中のユーザーが実行できる CLI コマンド（オブジェクト × 操作）| **絞られる** |
| `security login role show-rest` | REST エンドポイント × 対応 CLI × 対応する操作 | **絞られない。** MAV の7件も載る |
| `security login role show-ontapi` | 旧 API（ONTAPI、ZAPI）名 ↔ CLI コマンド | 絞られない。REST 時代のコマンドは対応表にないことがある（`security multi-admin-verify` は0件）|
| （REST）`GET` の実測 | エンドポイントごとの HTTP コード | 絞られる |

- 「権限に関係なくすべての API」を見るなら `show-rest`、「自分が実行できるコマンド」を見るなら `show-user-capability` です。`show-ontapi` は旧 API の移行の対応づけ向けです。
- NetApp の CLI リファレンスで内容を確認できたのは `show-ontapi` だけです（[security login role show-ontapi](https://docs.netapp.com/us-en/ontap-cli/security-login-role-show-ontapi.html)、2026-11-04 に全文確認）。`show-rest` のページは全文を読み、`show-user-capability` のページは取得時に 404 でした。依頼で挙げられた NetApp の技術資料（PDF）は HTTP 403 で、読めていません。
- `show-user-capability` が「実行できるコマンド」だと言えるのは、実測で確かめたためです。無条件に `none` と計算した11コマンド（`system node run`、`security key-manager onboard enable` など）は一覧になく、条件つきの `none` の2コマンド（`event filter show`、`security login role config show`）は載っていました。13件中13件が計算と一致しています。

---

## 取得方法 / How to Check

### ONTAP CLI

```bash
ssh fsxadmin@<management-endpoint>
security login role show -role fsxadmin -fields cmddirname,access,query
security login role show-user-capability
security login role show-rest
security login role show-ontapi
```

### REST API（CLI パススルー）

管理エンドポイントは VPC 内からのみ到達します。踏み台がパスワードを読めない場合は、Session Manager のポートフォワードで手元に引き込めます。パスワードは SSM のコマンド履歴に残りません。

```bash
aws ssm start-session --region ap-northeast-1 --target <bastion-instance-id> \
  --document-name AWS-StartPortForwardingSessionToRemoteHost \
  --parameters host=<management-endpoint-dns>,portNumber=443,localPortNumber=18443

B=https://localhost:18443/api/private/cli/security/login/role
curl -sk -u "fsxadmin:<password>" "$B?fields=vserver,role,cmddirname,access,query&max_records=20000"
curl -sk -u "fsxadmin:<password>" "$B/show-user-capability?max_records=20000"
curl -sk -u "fsxadmin:<password>" "$B/show-rest?fields=endpoint,commands,supported-operations&max_records=20000"
curl -sk -u "fsxadmin:<password>" "$B/show-ontapi?fields=ontapi,command&max_records=20000"
```

`show-rest` では `fields=*` が使えません（`fields=* is not allowed for CLI-based REST APIs`）。フィールド名を列挙します。

> **シークレットは名前ではなくタグで選ぶ。** FSx for ONTAP の管理ユーザーはどのファイルシステムでも `fsxadmin` なので、別のファイルシステム用のシークレットを使うと認証に失敗し、繰り返すとロックされます。対象のファイルシステム ID が書かれたシークレットを使います。

---

## 検証環境と結果 / Environment and Results

| 項目 / Item | 値 / Value |
|---|---|
| 製品 / Product | Amazon FSx for NetApp ONTAP、SINGLE_AZ_1、ap-northeast-1 |
| ONTAP | 9.18.1P6（`/api/cluster` の値）|
| 取得日 / Read on | 2026-11-04、`fsxadmin` で取得 |

### CLI: fsxadmin が実行できるコマンド

トップレベルのオブジェクトごとのコマンド数です。全件は [データ](data/fsx-ontap-9.18.1P6-cli-user-capability.tsv) にあります。

| トップレベル | コマンド数 | トップレベル | コマンド数 |
|---|---|---|---|
| `vserver` | 778 | `network` | 37 |
| `volume` | 255 | `cluster` | 34 |
| `security` | 220 | `job` | 32 |
| `lun` | 91 | `event` | 28 |
| `snapmirror` | 48 | `snaplock` | 25 |
| `metrocluster` | 39 | `statistics` / `system` | 20 / 20 |
| `qos` | 39 | `storage` / `application` | 19 / 18 |

### REST: ファミリーごとの件数と GET の実測

`show-rest` の570エンドポイントを、先頭のパス要素で分けた表です。GET の実測は、パスパラメータのない219件だけを対象にしています（残りの351件は `{uuid}` などが要り、汎用の呼び出しができません）。

| ファミリー | エンドポイント | GET を実測 | 200 | 403 | その他 |
|---|---|---|---|---|---|
| `/protocols` | 166 | 49 | 47 | 2 | 0 |
| `/security` | 109 | 51 | 32 | 16 | 3 |
| `/storage` | 94 | 33 | 25 | 4 | 4 |
| `/cluster` | 53 | 28 | 18 | 8 | 2 |
| `/network` | 42 | 16 | 12 | 4 | 0 |
| `/name-services` | 31 | 14 | 14 | 0 | 0 |
| `/support` | 30 | 17 | 10 | 7 | 0 |
| `/application` | 18 | 3 | 3 | 0 | 0 |
| `/svm` | 15 | 4 | 3 | 1 | 0 |
| `/snapmirror` | 6 | 2 | 2 | 0 | 0 |
| `/resource-tags` | 4 | 1 | 1 | 0 | 0 |
| `/cloud` | 2 | 1 | 0 | 1 | 0 |
| 合計 | 570 | 219 | 167 | 43 | 9 |

「その他」9件の内訳は次のとおりです。個別のコードは [データ](data/fsx-ontap-9.18.1P6-rest-endpoints.tsv) の `get_http` 列にあります。

- SVM の `vsadmin-snaplock` ロール専用が3件（`/storage/snaplock/event-retention/operations`、`/storage/snaplock/event-retention/policies`、`/storage/snaplock/litigations`。400 が1件、401 が2件）。401 はログイン失敗ではなく、ロールによる認可のメッセージです
- キー指定が必要な 400 が1件（`/storage/snaplock/file-fingerprints`）
- 設定が存在しない 404 が3件（`/security/authentication/cluster/ad-proxy`、`ldap`、`nis`）
- MetroCluster 未構成による 500 が2件

SnapLock の訴訟保全（litigation）と event-retention の API が SVM の `vsadmin-snaplock` ロール専用である点は、`fsxadmin` で運用する設計に影響します。

### fsxadmin が拒否される GET（43件、HTTP 403）

| 分野 | エンドポイント |
|---|---|
| セキュリティ（16）| `/security/anti-ransomware`、`/security/multi-admin-verify`（配下3件を含め4）、`/security/jit-privileges`、`/security/jit-privilege-users`、`/security/key-manager-configs`、`/security/cluster-network`（配下1件を含め2）、`/security/ha-network`、`/security/authentication/cluster/saml-sp`（配下1件を含め2）、`/security/webauthn/*`（3）|
| クラスタ（8）| `/cluster/software`（配下3件を含め4）、`/cluster/chassis`、`/cluster/sensors`、`/cluster/ntp/keys`、`/cluster/web` |
| サポート（7）| `/support/snmp`（配下2件を含め3）、`/support/configuration-backup`（配下1件を含め2）、`/support/coredump/coredumps`、`/support/ems/role-configs` |
| ネットワーク・ストレージほか（12）| `/network/ethernet/switches`、`/network/ethernet/switch/ports`、`/network/fc/fabrics`、`/network/ip/bgp/peer-groups`、`/storage/bridges`、`/storage/ports`、`/storage/switches`、`/storage/tape-devices`、`/protocols/ndmp`（配下1件を含め2）、`/cloud/targets`、`/svm/migrations` |

`/security/anti-ransomware` が403でも、ボリュームごとの ARP は別の経路で扱えます。`security anti-ransomware volume` はロール定義で `all` です。REST では `PATCH /storage/volumes/{uuid}` の `anti_ransomware.state` が使われ、台帳 E-004 の実測もこの経路です。

### fsxadmin のロール定義

- 既定（`DEFAULT`）のアクセスは `all` で、個別に絞る構造です。494 エントリの内訳は `all` 287、`readonly` 126、`none` 81 です。条件（`query`）つきが `all` 178、`readonly` 62、`none` 9 あります。
- `security` は `none`（条件なし）で、その下に `readonly` や `all` の例外が書かれています。例外に載らない `security` 配下のコマンドは `none` です。MAV はこれに当たります。
- ロール一覧は、クラスタが `fsxadmin`（494）、`fsxadmin-readonly`（351）、`snaplock`（12）、`backup`（8）、`autosupport`（3）、`none`（1）です。SVM は `vsadmin`（138）、`-readonly`（132）、`-volume`（94）、`-snaplock`（89）、`-protocol`（87）、`-backup`（55）で、検証した5つの SVM で定義が同一でした。
- SVM ロール（`vsadmin`、`-backup`、`-snaplock`、`-volume`）には、`security multi-admin-verify request` が `all`、`request approve` と `request veto` が `none` のエントリがあります。クラスタ側のどのロールにも、MAV の承認グループやルールを設定するエントリはありません。

### MAV の観測

| 観測 / Observation | 結果 / Result |
|---|---|
| `show-rest` の MAV エンドポイント | 7件が存在（この版に MAV の REST API はある）|
| CLI 一覧（`show-user-capability`）| `multi-admin` を含むコマンドは0件 |
| `fsxadmin` のロール定義 | `multi-admin` のエントリは0件。親の `security` が `none`（条件なし）|
| `PATCH /security/multi-admin-verify`（有効化）| 403 `not authorized for that command`（1回）|
| `POST /security/multi-admin-verify/approval-groups` | 403（1回。最初は私の本文の誤りで 400 だったため、直して再試行）|
| `GET` の MAV エンドポイント（`approval-groups`、`rules`、`requests` を含む）| すべて 403 |
| 対照: `GET /storage/snaplock/compliance-clocks`、`GET /security/roles` | 200 |

---

## 一覧との突き合わせで見つかった食い違い / A Mismatch Found by Checking Against the Catalog

このリポジトリが使う REST パスを `show-rest` の一覧と突き合わせると、1件が一覧にありませんでした。

| 使っている場所 | パス | この版の一覧 |
|---|---|---|
| `solutions/shared/ontap_client.py` の `enable_arp()` と `get_arp_status()`、[ARP 設定](arp-configuration.md) の REST 例 | `/security/anti-ransomware/volumes/{uuid}`（PATCH と GET）| **なし。** `/security/anti-ransomware` 配下で一覧にあるのは `auto-enable`、`suspects`、`volume/entropy-stats` など |
| 台帳 E-004 の実測 | `PATCH /storage/volumes/{uuid}` の `anti_ransomware.state` | あり（`/storage/volumes` は GET と POST。PATCH は `{uuid}` つきの別エントリ）|

同じ検証環境で `GET /api/security/anti-ransomware/volumes` を1回呼んだ結果は HTTP 404 でした。一覧にないことと合わせると、このパスは ONTAP 9.18.1P6 には存在しません [E-028]。ただし、観測は1回、1つの版です。`ontap_client.py` のテストは HTTP を差し替えているため、この不一致は検出されません。修正は別に扱います。

---

## 読み方の注意 / Reading Caveats

1. **`query` を見る。** `query` つきのアクセスは、条件に合う行にだけ適用されます。`event filter show` は `none` ですが条件つきで、`event/filter` への GET は 200 でした。
2. **ディレクトリの `none` は、配下すべてが `none` という意味ではない。** より長く一致するエントリが優先されます。`cluster` は `none` ですが、`cluster show` は許可されています。
3. **REST のパスと CLI コマンドは1対1ではない。** 一部の `none` と計算したコマンドは、REST の GET で 200 を返しました（`security key-manager show` など3件）。対応先が別のコマンドになるためと見ていますが、特定していません。
4. **実効アクセスの計算は、最長一致の規則によるもの。** 公式文書の該当箇所は確認していません。`show-ontapi` データの `fsxadmin_access` 列は計算値で、独立に裏づけがあるのは `show-user-capability` と突き合わせた13件と、MAV 系・`statistics` の403です。
5. **GET の実測は「一度呼んだ結果」。** 空の応答は 200 になるので、200 はデータがあることを意味しません。応答の中身は保存していません。POST・PATCH・DELETE は、副作用があるため、MAV の2件以外は試していません。

---

## データファイル / Data Files

| ファイル / File | 内容 / Content |
|---|---|
| [`data/fsx-ontap-9.18.1P6-cli-user-capability.tsv`](data/fsx-ontap-9.18.1P6-cli-user-capability.tsv) | `fsxadmin` が実行できる CLI コマンド 1,744 件 |
| [`data/fsx-ontap-9.18.1P6-rest-endpoints.tsv`](data/fsx-ontap-9.18.1P6-rest-endpoints.tsv) | REST エンドポイント 570 件。操作、対応 CLI、GET の実測コード |
| [`data/fsx-ontap-9.18.1P6-roles.tsv`](data/fsx-ontap-9.18.1P6-roles.tsv) | クラスタのロールと、1つの SVM のロールの全エントリ |
| [`data/fsx-ontap-9.18.1P6-show-ontapi.tsv`](data/fsx-ontap-9.18.1P6-show-ontapi.tsv) | ONTAPI と CLI の対応 1,045 件に、計算上の `fsxadmin` アクセスを付与 |

クラスタ名と SVM 名はマスクしています。応答の中身（設定値、ライセンスなど）は保存していません。

---

## 確認できていないこと / What Is Not Established

- 権限に関係なくすべての CLI コマンド。`show-rest` と `show-ontapi` は API に対応づいたコマンドだけで、CLI 全体の一覧ではありません。全コマンドを取るには、SSH で `?` を辿る方法がありますが、行っていません
- 他のロール（`fsxadmin-readonly`、`vsadmin` 系）が実行できるコマンドの一覧。ロール定義は取りましたが、`show-user-capability` はロールごとには取っていません
- 他の ONTAP 版、他のファイルシステム、Multi-AZ 構成での結果
- 依頼で挙げられた NetApp の技術資料（PDF）の記述
- AWS 側の管理経路（コンソール、AWS CLI、API）で MAV を設定できるか

---

## 参照 / References

- [fsxadmin Permissions & Limitations](fsxadmin-limitations.md)
- [Multi-Admin Verification (MAV) Configuration](mav-configuration.md)
- [security login role show-ontapi](https://docs.netapp.com/us-en/ontap-cli/security-login-role-show-ontapi.html)、[security login role show-rest](https://docs.netapp.com/us-en/ontap-cli/security-login-role-show-rest.html)（NetApp ONTAP CLI リファレンス）
