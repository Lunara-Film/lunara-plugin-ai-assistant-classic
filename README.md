# LUNARA FILM AI Assistant Classic

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

The version lives in one file: the plugin header and
`LUNARA_AI_ASSISTANT_CLASSIC_VERSION` in `lunara-ai-assistant-classic.php`.
The release contract checks that the two agree; no test pins the number.

### 0.6.2 Always LUNARA FILM

- Every name a person sees says LUNARA FILM: the plugin header, Settings > LUNARA FILM AI Classic (menu and page), the LUNARA FILM AI meta box, the system prompt label, two provider error messages and the default system prompt.
- A saved system prompt is never rewritten. A site that saved settings keeps its own prompt text until it is edited in that settings field.
- `tests/brand-name-contract.php` fails CI on a bare LUNARA in visible strings. The release contract no longer pins a version number.

### 0.6.1 Gemini credential hardening

- Sends the Gemini key in the `x-goog-api-key` header instead of placing it in the request URL.
- Adds a release contract so credential transport and version metadata cannot silently regress.

## Secrets

Do not commit OpenAI, Anthropic, Gemini, Google, WordPress application passwords, option exports, or environment files. Runtime credentials belong in server constants or private WordPress settings and should never be printed back into the admin UI.

## Verification

- Run PHP lint, `php tests/release-contract.php` and `php tests/brand-name-contract.php` after edits.
- Confirm Settings > LUNARA FILM AI Classic loads.
- Confirm Classic Editor screens still show the LUNARA FILM AI meta box for configured post types.
- Confirm public routes do not leak AI settings, prompts, keys, or admin assets.
