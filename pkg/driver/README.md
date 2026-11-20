# `pkg/driver` — platform drivers

A driver tells kai what a platform looks like. It is data, not a plugin: adding a
platform means adding a directory here, and nothing in the core learns the platform's
name.

```
pkg/driver/drivers/<id>/manifest.json     embedded with //go:embed drivers/*/manifest.json
```

## manifest.json — schema version 1

| Field | Type | What it is |
|---|---|---|
| `version` | int | schema version; must be `1`. A newer version is refused, never guessed at |
| `id` | string | stable id, matches the directory name |
| `name` | string | display name |
| `homepage` | string | optional |
| `description` | string | what the driver claims and what still needs building |
| `parser` | string | reader id registered in `pkg/program` (`hackerone`, `generic`) |
| `intake_urls` | []string | `host/path` patterns the driver claims |
| `requires_auth` | bool | the policy needs an authenticated session to read |
| `policy_fetch` | object | `kind` (`graphql`\|`html`\|`securitytxt`) + `endpoint`/`path`/`notes` |
| `scope_extraction` | object | `kind` (`structured`\|`html`) + `in_headings`/`out_headings`/`notes` |
| `mandatory_conditions` | []object | `{id, text}` rules that are not scope rules |
| `report_field_set` | []string | the fields the platform's report form has |
| `reward_fields` | []string | how the platform expresses money, if it does |
| `submit_channel` | string | `platform`, `email`, … |
| `submit_url` | string | where a report goes, when it is a URL |

## Matching

`*` matches every host; `*.example.com` matches one label under `example.com`;
`example.com/*` matches that exact host. The most specific pattern wins — an exact host
beats a wildcard — and a lookalike host (`example.com.evil.test`, `notexample.com`)
never matches, because a wrong claim would serve one program another program's rules.
The `selfhosted` manifest matches `*` and is the fallback.

## Rules for adding a driver

1. **A driver claims a target; it does not decide anything.** It supplies vocabulary
   (scope headings, report fields, mandatory conditions). The gate, the queue and the
   writer are not its business.
2. **Do not promise a reader you have not built.** If the platform's policy is not
   plain HTML, leave the reader name in place and say so in `description` and
   `policy_fetch.notes`, with the measurement that proved it. `kai intake` fails loudly
   ("driver X (reader Y) could not read …") rather than writing an empty contract.
3. **Mandatory conditions are not scope.** A research-identity requirement or a report
   taxonomy belongs in `mandatory_conditions`, never as a host rule.
4. **Record what you measured.** Notes carry the date and the observation (status code,
   byte count, what was missing) so the next person does not repeat the probe.
