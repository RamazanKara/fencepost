# Signed rule updates

Fencepost embeds an Ed25519-signed, versioned bundle for FP001 poisoning expressions. Structural checks, secret detectors and severity definitions remain compiled. New text patterns reach scan/vet and proxy/gateway output filtering without a binary release; structural algorithm changes still need one.

There is no automatic network check. Select a publisher explicitly:

```sh
fencepost rules update --url https://publisher.example/fencepost/rules.json
```

This is a syntax example, not a live update service. Only the release key in `internal/rulebundle/public-key.txt` is trusted; the URL cannot supply a replacement key. Downloads require HTTPS, refuse redirects, time out after 30 seconds, and are limited to 1 MiB. Invalid signatures, malformed/unknown fields, invalid expressions and rollbacks leave the existing bundle untouched. Payloads contain a positive integer version and 1–256 Go/RE2 expressions of at most 4096 bytes each.

Bundles are stored atomically with private file modes at the platform config directory's `fencepost/rules.json`: `%APPDATA%` on Windows, `~/Library/Application Support` on macOS, `$XDG_CONFIG_HOME` or `~/.config` on Linux. Older versions and different content reusing the installed version fail. Restart running processes after updates. Scan, vet, proxy and gateway reverify cached signatures at startup; corrupt caches fail closed. A missing cache uses embedded rules.

The envelope has base64 `payload` and `signature`; Ed25519 signs **exact decoded payload bytes**. Example payload:

```json
{"version":2,"patterns":["(?i)ignore previous instructions","(?i)new reviewed poisoning pattern"]}
```

Publishers must retain existing expressions when adding patterns, review changes and test benign/malicious descriptions. Keep the private release key outside source control; only the public key and signed initial bundle ship. The release operator needs the corresponding private key through a separate local handoff. Rotation requires a reviewed binary release. Signatures establish publisher identity, not heuristic completeness.

Node's standard library can sign a reviewed `payload.json`, with the PEM path supplied locally in `RULES_SIGNING_KEY`:

```js
const fs = require('node:fs');
const crypto = require('node:crypto');
const payload = fs.readFileSync('payload.json');
const signature = crypto.sign(null, payload, fs.readFileSync(process.env.RULES_SIGNING_KEY));
fs.writeFileSync('rules.json', JSON.stringify({payload: payload.toString('base64'), signature: signature.toString('base64')}));
```

Deleting/rolling back the whole config directory defeats the local high-water mark, but the embedded version remains a floor. Local administrators and binary/key replacement are outside this boundary. Bundles cannot execute code or fetch schema references.
