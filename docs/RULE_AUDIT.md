# Detection rule audit: near-miss gaps

Gitleaks rules are regular expressions, and a regular expression can make an
assumption that is slightly wrong in the real world. This page records what
`scripts/audit_rules.py` looks for, what it found in the Gitleaks 8.30.1 default
rules, and what SecretSentinel did about it.

The trigger was a real find: the default Twitter/X bearer-token rule wants
exactly 22 leading `A` characters, a token in a public repository had 21, and
a scan reported nothing.

## Method

For every rule with a regex, the script builds one synthetic string the rule
should match (sampled from the regex itself, so it never contains a real
credential), checks that Gitleaks detects it, and then changes it slightly:

| Variant | What it tests |
|---|---|
| **Length** | Every exact-count repeat (`A{22}`, `[a-z0-9]{32}`) one shorter and one longer. |
| **Delimiter** | The character after the value replaced by `&`, `,`, `)`, `]`, `}`, `<`, `|`, `/` or `.`, next to a baseline of space, quotes, `;`, backtick and end of line. |

The audit shows which assumptions a rule makes. It does not prove that a real
token is missed: only the issuer's documentation (or a real token) can say
whether a format varies. Samples are written to a temporary directory and never
printed.

Run it again after every Gitleaks upgrade:

```bash
curl -sSL https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/config/gitleaks.toml -o gitleaks-default.toml
python scripts/audit_rules.py --config gitleaks-default.toml --gitleaks "$(which gitleaks)" --list-delimiters
python scripts/audit_rules.py --config rules/web3_rules.toml --gitleaks "$(which gitleaks)"
```

## Results for Gitleaks 8.30.1 (221 rules with a regex)

- **209 rules** were sampled and detected by their own rule. The other 12 need
  context a sampler cannot build (multi-line, entropy-gated or key/value
  combinations): `airtable-personnal-access-token`, `curl-auth-header`,
  `curl-auth-user`, `facebook-access-token`, `freemius-secret-key`,
  `generic-api-key`, `hashicorp-tf-password`, `kubernetes-secret-yaml`,
  `nuget-config-password`, `sidekiq-sensitive-url`, `slack-config-access-token`,
  `slack-webhook-url`. They were not audited.

### 1. Runs of one literal character

Only one rule has one: `twitter-bearer-token` (exactly 22 `A`s; one fewer is
missed). This is the shape that hid the real token. **Fixed** by
`twitter-bearer-token-short-prefix` (see below).

### 2. Exact-length character runs

146 rules reject a value that is one character shorter and one that is one
character longer. That is correct for fixed-length formats (AWS access key IDs,
GitHub tokens) and wrong for formats that vary. The regex cannot say which is
which. **No change made**: tightening or widening a rule without the issuer's
documentation would be a guess. Check the list in the script's output against
vendor documentation when a vendor you use matters to you.

### 3. Delimiter after the value

Most keyword rules end with "a quote, whitespace, `;`, or the end of the
line". 148 of the 209 sampled rules stop matching when an **unquoted** value is
followed directly by `,` `)` `]` `}` `<` `|` `/` or `.`, and 149 when it is
followed by `&`:

| After the value | Rules that stop matching (of 209) |
|---|---|
| space, quotes, backtick, end of line | 0 |
| `;` | 1 |
| `&` `]` `}` `|` | 149 |
| `,` `)` `<` | 148 |
| `/` `.` | 145 |

Two shapes that happen in practice:

- a URL query string: `https://api.example.test/v1/items?api_key=VALUE&limit=10`
- an unquoted value followed by a comma or bracket, as in CSV or a flow-style
  YAML/JSON-like line (`API_KEY=VALUE,`)

I confirmed with the real engine that the default rules detect the quoted form
of the first example and miss both. **Partly fixed**:

- `url-query-credential` covers credential-named query parameters (below).
- The remaining default rules are **not** changed. Replacing ~150 upstream
  regexes with our own copies would freeze them at 8.30.1 and miss every
  upstream improvement. The better fix is upstream, in the shared
  `secretSuffix` of Gitleaks' rule generator
  (`cmd/generate/config/utils/generate.go`); until then this is a known limit.
  The default config on Gitleaks `master` (checked 2026-11-13) is unchanged.

Widening the terminator is not free. On a copy of the default config, scanned
against a 762 MB Go module cache that has 727 findings with the stock rules:

| Change | Extra findings |
|---|---|
| Add `, ) ] } > & \| <` to every rule | +126, of which 121 are `generic-api-key` on identifiers followed by `,` |
| Add them to every rule except `generic-api-key`, which only gets `&` | +7 (3 of them are sample tokens in Gitleaks' own rule tests) |

So the comma is what makes `generic-api-key` noisy, and the provider-specific
rules can take the wider terminator.

## What SecretSentinel added

| Rule | Severity | Covers | Notes |
|---|---|---|---|
| `twitter-bearer-token-short-prefix` | high (blocking) | A Twitter/X bearer token after a `twitter`, `x_api`, `x_bearer` name or a `Bearer` prefix, starting with 18 or more `A`s, followed by `,` `)` `]` `}` `>` `&` `|` `<` as well as the usual delimiters. | The context part is case-insensitive; the token itself is case-sensitive. A token matched by both this rule and the default rule is reported once. |
| `url-query-credential` | medium (does not block) | A `?` or `&` parameter named `api_key`, `apikey`, `access_token`, `auth_token`, `client_secret`, `secret`, `token`, `password` or `pwd` with a 20+ character value of at least 3.5 bits of entropy per character. | Medium and non-blocking on purpose: it is a generic detector, like the default `generic-api-key`. Raise it in `rules/severity_mapping.yaml` if you want it to block. Placeholders, `${VAR}` references, `page_token` and low-entropy values are ignored. |

Both are covered by synthetic fixtures (generated at test time, never committed
as secret-shaped text) and tests in `backend/tests/test_rules.py`; the audit
script has its own tests in `backend/tests/test_audit_rules.py`.

## Limits

- The sampler builds one value per rule. Rules that need a particular
  surrounding line are reported as "not detected" and skipped.
- A passing audit is not proof of coverage. Gitleaks only knows the formats its
  authors have seen.
- Rules in `rules/web3_rules.toml` that must end at a closing quote
  (`web3-cli-mnemonic-flag`, `web3-evm-private-key-in-code`, ...) show up under
  the delimiter table because they require a quote; that is intended.
