# Mihomo protocol compatibility notes

Research target: `Masaiki/subconverter`, with Mihomo **v1.19.33** and **v1.19.34**. Sources are first-party documentation and source code, fetched 2026-11-25.

## Converter scope

Use `/sub?target=clash&list=true` (or `target=mihomo&list=true`) for the native YAML path. For AnyTLS, Hysteria2, TUIC and VLESS, this keeps the original protocol options while applying the converter's rename, filtering and explicit overrides. `target=mixed` is a share-link target, not a lossless interchange format: it adds AnyTLS and Mihomo-style TUIC links and fixes direct Hysteria2 and basic VLESS/XHTTP link handling. It does not encode full nested XHTTP options or export Realm nodes as direct Hysteria2 links. AnyTLS `hpkp` in mixed output is a Mihomo interoperability extension, not part of the official URI spec.

## Executive findings

- There is **no AnyTLS, Hysteria2, TUIC, REALITY, XHTTP, or ECH option-schema change between Mihomo v1.19.33 and v1.19.34**. The relevant outbound files are identical; the only related subscription-converter change in v1.19.34 is `httpupgrade` handling. Do not attribute field loss to Sparkle being one Mihomo patch behind. ([compare](https://github.com/MetaCubeX/mihomo/compare/v1.19.33...v1.19.34), [v1.19.33 AnyTLS](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/adapter/outbound/anytls.go), [v1.19.34 AnyTLS](https://github.com/MetaCubeX/mihomo/blob/v1.19.34/adapter/outbound/anytls.go), [v1.19.33 Hysteria2](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/adapter/outbound/hysteria2.go), [v1.19.34 Hysteria2](https://github.com/MetaCubeX/mihomo/blob/v1.19.34/adapter/outbound/hysteria2.go))
- For **Mihomo YAML → Mihomo YAML**, preserving the original per-proxy mapping (including nested mappings, sequences, scalar types, explicit `false`/`0`, and unknown future fields) is safer than flattening it into `Proxy` and reconstructing it. The cross-format model cannot represent the complete option sets below.
- For **share URIs**, emit only the official grammar. AnyTLS officially carries only auth, address, `sni`, `insecure`, and fragment name. Hysteria2 officially carries auth, a multi-port authority, `obfs`, `obfs-password`, `sni`, `insecure`, `pinSHA256`, and `ech`. YAML-only tuning must not be silently presented as portable URI data. ([AnyTLS URI](https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md), [Hysteria2 URI](https://v2.hysteria.network/docs/developers/URI-Scheme/))
- The principal existing failure modes are converter loss/type coercion, incorrect URI authority parsing (IPv6 and Hysteria multi-port), confusing certificate `fingerprint` with uTLS `client-fingerprint`, and treating documented, implementation-specific, and unofficial URI extensions as one format.

## 1. AnyTLS

### Exact Mihomo YAML fields

Mihomo v1.19.33/v1.19.34 accepts the following `type: anytls` fields (types follow the Go option struct):

| Fields | Type / meaning |
| --- | --- |
| `name`, `server`, `password` | string |
| `port` | integer |
| `alpn` | sequence of strings |
| `sni` | string |
| `ech-opts` | mapping; see ECH below |
| `shadow-tls-opts` | `{password: string, version: int}` |
| `restls-opts` | `{password: string, version-hint: string, restls-script: string}` |
| `jls-opts` | `{username: string, password: string}` |
| `client-fingerprint` | uTLS client profile string |
| `skip-cert-verify` | boolean |
| `name-cert-verify`, `fingerprint`, `certificate`, `private-key` | strings; `fingerprint` is certificate pinning, not a uTLS profile |
| `udp` | boolean |
| `client-metadata` | string |
| `idle-session-check-interval`, `idle-session-timeout`, `min-idle-session` | integers; the first two are seconds |
| `disable-reuse` | boolean |
| common outbound fields | notably `tfo`, `mptcp`, `interface-name`, `routing-mark`, `ip-version`, `dialer-proxy` |

Source: pinned [`AnyTLSOption`](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/adapter/outbound/anytls.go) and common [`BasicOption`](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/adapter/outbound/base.go). The first-party [Mihomo AnyTLS documentation](https://github.com/MetaCubeX/Meta-Docs/blob/main/docs/config/proxies/anytls.en.md) also records that `client-metadata` stopped being sent by default in v1.19.30.

Pooling behavior is observable, not decorative: Mihomo passes all four pooling controls into the AnyTLS session client. A check interval or timeout `<= 5s` is normalized to `30s`; `disable-reuse` avoids the idle pool and closes a session after its stream closes. ([transport client](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/transport/anytls/client.go), [session client](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/transport/anytls/session/client.go))

Security-mode constraints:

- ShadowTLS, Restls, and JLS are mutually exclusive in `NewAnyTLS`.
- Mihomo intentionally does **not** support AnyTLS + REALITY. Use ECH, ShadowTLS, Restls, or JLS instead. ([constructor](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/adapter/outbound/anytls.go), [Mihomo docs](https://github.com/MetaCubeX/Meta-Docs/blob/main/docs/config/proxies/anytls.en.md))

**Preservation consequence:** all fields above, especially the three nested security mappings, `client-metadata`, the session controls, `disable-reuse`, and explicit booleans, must survive native Mihomo YAML round trips. Hard-coding `30/30/0` is not equivalent to preserving input.

### Official AnyTLS share URI

Official form:

```text
anytls://[auth@]hostname[:port]/?[key=value]...[#name]
```

Official semantics:

- Scheme is only `anytls`.
- `auth` is the password and must be percent-encoded as URI userinfo when it contains reserved characters.
- Port defaults to `443` when omitted.
- Official query keys are only `sni` and `insecure`; `insecure` is `1` or `0`.
- If `sni` is an IP literal, the client must omit SNI.
- The fragment is the percent-encoded display name. ([AnyTLS URI specification](https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md))

A maximally interoperable emitted link should still include the port explicitly:

```text
anytls://p%40ss@example.com:443/?sni=real.example.com&insecure=0#display%20name
```

Why explicit port is safer despite the specification default:

- The current AnyTLS reference CLI parses only `sni`, ignores `insecure`, and later requires `net.SplitHostPort`, so an omitted port fails there. It also assigns `serverURL.User.String()` rather than a decoded username, so it is not a reliable conformance oracle for percent-encoded auth. ([reference client](https://github.com/anytls/anytls-go/blob/main/cmd/client/main.go))
- Mihomo v1.19.33/v1.19.34's built-in subscription converter also rejects AnyTLS links with no explicit port. It additionally accepts non-standard `hpkp` and maps it to YAML `fingerprint`. ([Mihomo converter v1.19.33](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/common/convert/converter.go))

Therefore:

- **Emit:** official `sni`/`insecure`, explicit port, encoded auth/fragment.
- **May accept on input for compatibility:** `hpkp`, `fingerprint`, `peer`, `alpn`, `udp`, `tfo`, `client-fingerprint`.
- **Do not label those compatibility keys official.** In particular, `hpkp` is a misleading legacy spelling: Mihomo's `fingerprint` is the SHA-256 fingerprint of the complete certificate, not an HPKP public-key fingerprint. ([Mihomo TLS docs](https://github.com/MetaCubeX/Meta-Docs/blob/main/docs/config/proxies/tls.en.md))

## 2. Hysteria2

### Exact Mihomo YAML fields

Mihomo v1.19.33/v1.19.34 accepts these `type: hysteria2` fields:

| Fields | Type / meaning |
| --- | --- |
| `name`, `server` | string |
| `port` | integer, optional if `ports` is usable |
| `ports` | string port/range list; enables hopping and takes precedence over `port` |
| `hop-interval` | string; one integer or one `min-max` range, seconds |
| `password` | string |
| `up`, `down` | strings parsed as bandwidth; no unit means Mbps |
| `obfs` | string: `salamander` or `gecko` |
| `obfs-password` | required non-empty string when `obfs` is set |
| `obfs-min-packet-size`, `obfs-max-packet-size` | integers, Gecko only |
| `sni`, `fingerprint`, `name-cert-verify`, `certificate`, `private-key` | strings |
| `skip-cert-verify` | boolean |
| `alpn` | sequence of strings |
| `ech-opts` | mapping; see ECH below |
| `cwnd`, `udp-mtu`, `handshake-timeout` | integers |
| `bbr-profile` | string |
| `realm-opts` | mapping described below |
| `initial-stream-receive-window`, `max-stream-receive-window`, `initial-connection-receive-window`, `max-connection-receive-window` | unsigned integers |
| common outbound fields | `interface-name`, `routing-mark`, `ip-version`, `dialer-proxy`, etc. |

Sources: pinned [`Hysteria2Option`](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/adapter/outbound/hysteria2.go) and [Mihomo Hysteria2 docs](https://github.com/MetaCubeX/Meta-Docs/blob/main/docs/config/proxies/hysteria2.en.md).

#### Port hopping

Official Hysteria multi-port syntax belongs in the address authority:

```text
example.com:1234,5678,9012
example.com:20000-50000
example.com:1234,5000-6000,7044,8000-9000
```

The client randomly chooses an initial port and switches periodically. The official interval defaults to `30s`, must be at least `5s`, and can be fixed or randomly selected between minimum/maximum values. ([official port-hopping docs](https://v2.hysteria.network/docs/advanced/Port-Hopping/))

Mihomo YAML uses `ports` plus `hop-interval`. Its code:

- parses comma-separated ranges through `NewUnsignedRanges[uint16]`;
- treats `hop-interval: "15-30"` as a random interval range;
- defaults zero/empty to 30 seconds and clamps the minimum to 5 seconds;
- ignores `port` for dialing when `ports` expands to a non-empty list. ([Hysteria2 constructor](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/adapter/outbound/hysteria2.go), [range parser](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/common/utils/ranges.go))

**Root-cause lead:** parsing the authority with a final `:<digits>` regex rejects valid `:443,5000-6000`; concatenating `port + "," + ports` can duplicate the first port. Parse bracketed IPv6 and the complete port-list authority first, retain the complete list in `ports`, and use one valid member only as the model's scalar fallback `port`.

#### Salamander and Gecko

- Official URI/YAML obfuscators are `salamander` and `gecko`.
- Gecko is Salamander plus fragmentation/padding of QUIC long-header handshake packets; short-header data packets pass through.
- Official Gecko defaults are `minPacketSize: 512`, `maxPacketSize: 1200`; max must be at least min and no more than 2048. ([official full client config](https://v2.hysteria.network/docs/advanced/Full-Client-Config/#obfuscation), [official Gecko code](https://github.com/apernet/hysteria/blob/master/extras/obfs/gecko.go))
- Mihomo represents the sizes as top-level `obfs-min-packet-size` and `obfs-max-packet-size` and passes them only for `obfs: gecko`. Unknown obfs values and a missing obfs password are constructor errors. ([pinned Mihomo source](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/adapter/outbound/hysteria2.go))

The official URI includes `obfs=gecko&obfs-password=...` but has **no Gecko min/max query parameters**. The official share generator consequently drops custom Gecko sizes. Preserve them in Mihomo YAML; do not invent URI keys. ([official URI generator/parser](https://github.com/apernet/hysteria/blob/master/app/cmd/client.go#L517-L618))

### Official direct Hysteria2 URI

```text
hysteria2://[auth@]hostname[:port-list]/?[query]#name
hy2://[auth@]hostname[:port-list]/?[query]#name
```

Official direct query keys:

- `obfs=salamander|gecko`
- `obfs-password`
- `sni`
- `insecure=1|0`
- `pinSHA256`
- `ech` (base64 ECH config list)

`auth` is percent-encoded userinfo. For Hysteria `userpass` authentication it is `username:password`; otherwise it is the auth string. Port defaults to 443 and the port component may be the multi-port format above. The fragment is only a display name. ([official URI specification](https://v2.hysteria.network/docs/developers/URI-Scheme/), [official parser tests](https://github.com/apernet/hysteria/blob/master/app/cmd/client_test.go#L160-L247))

Example:

```text
hysteria2://user:pass@example.com:443,5000-6000/?insecure=0&obfs=gecko&obfs-password=pw&sni=real.example.com&pinSHA256=AB%3ACD&ech=AAj%2BDQAEAAAAAA%3D%3D#node
```

Base64 `ech` must be query-escaped (`+`, `/`, `=` are significant). The official tests include this exact escaping behavior.

`up`, `down`, `alpn`, `ports`/`mport` query keys are implementation extensions, **not** official portable share fields. The official specification explicitly excludes bandwidth/client-mode settings. Accepting legacy extensions is reasonable; emitting them as official is not.

Mihomo's v1.19.33/v1.19.34 built-in converter supports direct multi-port, `pinSHA256`, `up`, `down`, and `alpn`, but does **not** copy official `ech` into `ech-opts`. It also obtains direct auth with `User.String()`, which can retain percent escaping. A subconverter should decode userinfo itself and map official `ech` to:

```yaml
ech-opts:
  enable: true
  config: <base64 config list>
```

Source: [Mihomo converter v1.19.33](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/common/convert/converter.go).

### Realm forms: documented versus implemented

There are three distinct interoperability levels:

1. **Official runtime Realm address (implemented by Hysteria master):**

   ```text
   realm://token@rendezvous.example/realm-name
   realm+http://token@rendezvous.example/realm-name
   ```

   This address contains rendezvous credentials, not the Hysteria password; Hysteria auth remains a separate config field. Repeated `stun` and a single `lport=1..65535` are supported. Fragments are rejected. ([Realm docs](https://v2.hysteria.network/docs/advanced/Realms/), [Realm parser](https://github.com/apernet/hysteria/blob/master/extras/realm/addr.go))

2. **Official URI documentation's bundled share form:**

   ```text
   hysteria2+realm://token@rendezvous.example/realm-name?auth=hy-password&...
   hysteria2+realm+http://token@rendezvous.example/realm-name?auth=hy-password&...
   ```

   It carries the direct Hysteria query fields plus `auth`, repeated `stun`, and `lport`. Port hopping is not supported. ([official URI docs](https://v2.hysteria.network/docs/developers/URI-Scheme/#realm-mode))

3. **What the inspected clients actually accept:**

   - Hysteria master first checks only `realm://`/`realm+http://`, then its direct parser accepts only `hysteria2://`/`hy2://`; no bundled-scheme parser is present in the inspected client source. ([client dispatch](https://github.com/apernet/hysteria/blob/master/app/cmd/client.go#L573-L667), [Realm scheme constants](https://github.com/apernet/hysteria/blob/master/extras/realm/addr.go#L12-L18))
   - Mihomo v1.19.33/v1.19.34's built-in subscription converter accepts `hysteria2+realm://` and undocumented alias `hy2+realm://`, maps them to HTTPS `realm-opts`, but does not accept the documented `hysteria2+realm+http://` spelling. ([Mihomo converter](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/common/convert/converter.go))

Thus bundled Realm URIs are not yet universally portable. For a Mihomo target, the lossless representation is YAML:

```yaml
- name: realm-node
  type: hysteria2
  server: rendezvous.example       # scalar fallback; keep original native value when present
  port: 443
  password: hy-password
  realm-opts:
    enable: true
    server-url: https://rendezvous.example
    token: token
    realm-id: realm-name
    stun-servers:
      - stun1.example:3478
      - stun2.example:3478
    # optional TLS fields for server-url:
    sni: rendezvous.example
    skip-cert-verify: false
    name-cert-verify: rendezvous.example
    fingerprint: "..."
    certificate: "..."
    private-key: "..."
    alpn: [h2]
```

Those are the exact fields in Mihomo's `Hysteria2RealmOption`. Mihomo has no `realm-opts` field corresponding to URI `lport`, so `lport` cannot be preserved as executable v1.19.33/v1.19.34 Mihomo YAML. ([pinned source](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/adapter/outbound/hysteria2.go))

## 3. Smaller Mihomo-YAML preservation notes

These matter primarily because a generic rebuild can damage otherwise valid native YAML.

### TUIC

Mihomo's `tuic://` handling is explicitly described in its own source as a **temporary unofficial** share-link standard. It uses `token@host` for TUIC v4 and `uuid:password@host` for TUIC v5. Do not call it an official TUIC URI. The built-in URI converter recognizes only `congestion_control`, `alpn`, `sni`, `disable_sni=1`, and `udp_relay_mode`; it does not carry the complete YAML option set. ([converter](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/common/convert/converter.go))

For native YAML, preserve the whole mapping. In particular, preserve v4 `token` versus v5 `uuid` + `password` (they are mutually exclusive), plus `ip`, `heartbeat-interval`, `alpn` as a sequence, `reduce-rtt`, `request-timeout`, `udp-relay-mode`, `congestion-controller`, `disable-sni`, `max-udp-relay-packet-size`, `fast-open`, `max-open-streams`, `cwnd`, `bbr-profile`, TLS/ECH fields, `recv-window-conn`, `recv-window`, `disable-mtu-discovery`, `max-datagram-frame-size`, `udp-over-stream`, and `udp-over-stream-version`. Exact types and defaults are in pinned [`TuicOption`](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/adapter/outbound/tuic.go); first-party descriptions are in [Mihomo's TUIC docs](https://github.com/MetaCubeX/Meta-Docs/blob/main/docs/config/proxies/tuic.en.md).

### REALITY

Preserve this subtree exactly:

```yaml
reality-opts:
  public-key: <raw URL-safe base64 X25519 key>
  short-id: <hex, at most 8 decoded bytes>
  support-x25519mlkem768: true
```

Mihomo requires a raw URL-safe base64 public key decoding to exactly 32 bytes. `short-id` is hex and at most 8 decoded bytes. The hybrid-support flag is a boolean, not part of either key string. REALITY is a TLS security mode and is mutually exclusive with ShadowTLS, Restls, and JLS. ([option parser](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/adapter/outbound/reality.go), [maximum short ID](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/component/tls/reality.go), [VLESS constructor](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/adapter/outbound/vless.go))

For VLESS share links, Mihomo's own converter maps `pbk`, `sid`, and boolean `support-x25519mlkem768`. Preserve native YAML rather than reconstructing merely from `PublicKey`/`ShortId`, or the hybrid flag is lost. ([v1.19.33 V share converter](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/common/convert/v.go))

### XHTTP

XHTTP is VLESS-only. The request authority is **`xhttp-opts.host`**, not `xhttp-opts.headers.Host`; `headers` is a separate arbitrary string map. Modes are `auto`, `stream-one`, `stream-up`, and `packet-up`. ALPN selects HTTP carrier support: default H2, `[h3]` for HTTP/3, `[http/1.1]` for HTTP/1.1. H3 requires TLS, and Mihomo rejects H3 combined with REALITY/ShadowTLS/Restls/JLS. ([Mihomo transport docs](https://github.com/MetaCubeX/Meta-Docs/blob/main/docs/config/proxies/transport.en.md), [pinned `XHTTPOptions` and constructor](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/adapter/outbound/vless.go))

Preserve `xhttp-opts` opaquely. Besides `path`, `host`, `mode`, and `headers`, v1.19.33 already supports padding, placement/key/method fields, uplink method/data chunking, session and sequence fields, `reuse-settings` (XMUX), and nested `download-settings` with its own endpoint, TLS, ECH, security mode, and reuse settings. A reduced `Path`/`Host`/`Mode` model cannot round-trip this safely.

### ECH

Mihomo's exact shape is:

```yaml
ech-opts:
  enable: true
  config: <standard-base64 ECHConfigList>   # optional
  query-server-name: example.com            # optional
```

- With `enable: false`, ECH is off.
- With `enable: true` and non-empty `config`, Mihomo standard-base64 decodes the supplied ECH config list.
- With `enable: true` and empty `config`, Mihomo resolves ECH via DNS, optionally using `query-server-name` instead of the TLS server name. ([pinned ECH parser](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/adapter/outbound/ech.go), [Mihomo TLS docs](https://github.com/MetaCubeX/Meta-Docs/blob/main/docs/config/proxies/tls.en.md))

Do not preserve only `config`: that loses the distinction between disabled ECH and DNS-resolved ECH. In a Hysteria2 URI, `ech=<base64>` maps to `enable: true` + `config`; Hysteria's ECH client fails closed if the server rejects ECH. ([official Hysteria ECH docs](https://v2.hysteria.network/docs/advanced/ECH/))

## 4. Concrete root-cause checklist for this repository

Relevant locations are `src/parser/subparser.cpp`, `src/parser/config/proxy.h`, and `src/generator/config/subexport.cpp`.

1. **Lossy native-YAML model:** fields absent from `Proxy` disappear when YAML is regenerated. This affects nearly every AnyTLS pooling/security option, Hysteria2 hop/Gecko/Realm/QUIC options, TUIC tuning, `reality-opts.support-x25519mlkem768`, ECH DNS mode, and most XHTTP fields. Keep the original native proxy mapping and overlay only intentional converter changes (`name`, override flags, etc.).
2. **Scalar/type loss:** ALPN must remain a YAML sequence; booleans and integers must not become strings; explicit `false`, zero, and an empty sequence may have semantics distinct from omission. The pinned Mihomo structs use all of these distinctions.
3. **Fingerprint conflation:** `fingerprint` is certificate pinning; `client-fingerprint` is uTLS. Hysteria URI `pinSHA256` maps to the former. Do not put `fp` into certificate `fingerprint` indiscriminately.
4. **Authority parsing:** use the last `@` for userinfo, bracket-aware IPv6 parsing, AnyTLS/Hysteria default port 443, and Hysteria's complete comma/range port component. A `host:(digits)` regex is insufficient.
5. **URI component decoding:** percent-decode userinfo and fragment as RFC 3986 components. Query parsing treats `+` as space, so emitted base64 and arbitrary secrets must be percent-encoded. Do not double-encode an already decoded password.
6. **Official versus accepted extensions:** accept common legacy aliases on input when useful (`mport`, AnyTLS `hpkp`, etc.), but emit only official fields. A YAML node with Realm, custom Gecko sizes, full XHTTP, or AnyTLS security wrappers cannot be losslessly exported as an official direct URI.
7. **Realm:** preserve `realm-opts` in Mihomo YAML. Do not turn a Realm node into an ordinary direct `hysteria2://` endpoint. Bundled Realm URI support differs between official docs, official current client code, and Mihomo's converter as described above.
8. **Version diagnosis:** v1.19.34 does not add the fields in question. If Sparkle v1.19.33 rejects generated output, first inspect generated YAML names/types and converter field loss rather than requiring a core upgrade.
