# Freja documentation site

This directory contains the English and Japanese Freja documentation built
with Astro Starlight. Product behavior is documented from the Rust
implementation, `examples/config/`, packaging files, and integration tests;
temporary plans are not documentation sources.

## Local development

Requirements:

- a current Node.js release supported by Astro;
- pnpm 11 or newer.

```sh
pnpm install --frozen-lockfile
pnpm dev
```

The development server runs in background mode. Manage it with:

| Command | Purpose |
| --- | --- |
| `pnpm dev` | Start the background development server |
| `pnpm dev:status` | Show server status |
| `pnpm dev:logs` | Read server logs |
| `pnpm dev:stop` | Stop the server |
| `pnpm build` | Build the static site and search indexes |
| `pnpm check` | Check locale parity, build, and validate generated links |
| `pnpm preview` | Preview `dist/` |

## Content structure

English is the root locale. Japanese pages live below `ja/` and must use the
same relative path so Starlight can connect translations.

```text
src/content/docs/
├── guides/             # Task-oriented operator guides
├── reference/          # CLI, configuration, and schema reference
├── troubleshooting/    # Symptoms, causes, and recovery
├── developer/          # Architecture, security, hooks, tests, ADRs
└── ja/                 # Matching Japanese tree
```

Every page needs a title and description. Reuse a small stable tag vocabulary,
set `sidebar.order` for intentional navigation, and update both locales in the
same change. Use `.mdx` only for pages that import components.

## Validation

```sh
pnpm check
```

This validates frontmatter, English/Japanese route parity, generated routes,
internal links and anchors, and Pagefind indexing. When changing layout or
components, also inspect desktop and mobile widths in both color modes and
verify keyboard focus.

Production hosting is intentionally not encoded in this directory. Add Astro's
`site` (and `base` when needed) only when the deployment hostname and path are
known, so canonical URLs and asset paths do not advertise a placeholder.
