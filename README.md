# LUNARA AI Assistant Classic

Private WordPress plugin source for the Lunara Film Classic Editor AI assistant.

## Role

This plugin powers the Classic Editor meta box and private suggestion service for Lunara editorial packaging, rewrites, Journal support, Review support, and provider-routed suggestion calls.

## Public markup contract

Theme owns public presentation. Suggestions destined for articles must use
semantic headings, paragraphs, lists and links, inheriting the existing Theme
classes and tokens. Do not bundle style tags, inline layout/corner rules, fonts
or a separate layout stylesheet with generated content. Keep editor assets
private. See the Theme's `DESIGN.md`, `docs/PUBLIC-GEOMETRY.md` and
`docs/REPOSITORY-ALIGNMENT.md`; `AGENTS.md` records the shared release rules.
This is a contributor/review requirement, not an automatic output sanitizer.
Existing saved prompts and provider settings are unchanged.

## Source Locations

- Local source: `G:\01-Lunara-Website\Backups-And-Exports\lunara-backups\work\lunara-ai-assistant-classic`
- Live plugin: `/home/151589083/htdocs/wp-content/plugins/lunara-ai-assistant-classic`
- Continuity workspace: `C:\Users\silve_i21do49\OneDrive\Desktop\New folder`

## Version

Current baseline: `0.6.1`.

### 0.6.1 Gemini credential hardening

- Sends the Gemini key in the `x-goog-api-key` header instead of placing it in the request URL.
- Adds a release contract so credential transport and version metadata cannot silently regress.

## Secrets

Do not commit OpenAI, Anthropic, Gemini, Google, WordPress application passwords, option exports, or environment files. Runtime credentials belong in server constants or private WordPress settings and should never be printed back into the admin UI.

## Verification

- Run PHP lint and `php tests/release-contract.php` after edits.
- Confirm Settings > LUNARA AI Classic loads.
- Confirm Classic Editor screens still show the LUNARA AI meta box for configured post types.
- Confirm public routes do not leak AI settings, prompts, keys, or admin assets.
