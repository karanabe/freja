# Freja documentation agent guide

This directory is Freja's canonical Astro Starlight documentation site. Keep
it fast, readable, accessible, bilingual, and consistent with implemented and
tested Freja behavior.

## Sources of truth

- The Rust implementation, integration tests, `examples/config/`, and Cargo
  metadata own product behavior.
- `astro.config.mjs` owns site metadata, locales, navigation, code themes, and
  Markdown processing.
- `src/styles/theme.css` owns the configurable project color.
- `src/styles/site.css` owns typography, spacing, navigation states, diagrams,
  and landing-page presentation.
- `src/content/docs/` owns English content at the site root.
- `src/content/docs/ja/` owns Japanese content under `/ja/`.

Do not edit generated files in `dist/` or `.astro/`, and do not patch files in
`node_modules/`.

## Development workflow

Install the pinned dependency graph and run the complete production check:

```sh
pnpm install --frozen-lockfile
pnpm check
```

Always start the development server in background mode with `pnpm dev`. Manage
it without starting a second server by using `pnpm dev:status`,
`pnpm dev:logs`, and `pnpm dev:stop`.

Consult the relevant official documentation before changing framework behavior:

- [Astro documentation](https://docs.astro.build/)
- [Astro routing](https://docs.astro.build/en/guides/routing/)
- [Astro components](https://docs.astro.build/en/basics/astro-components/)
- [Astro content collections](https://docs.astro.build/en/guides/content-collections/)
- [Astro styling](https://docs.astro.build/en/guides/styling/)
- [Astro internationalization](https://docs.astro.build/en/guides/internationalization/)
- [Starlight documentation](https://starlight.astro.build/)

## Content rules

- Treat English as the primary language and keep a Japanese page at the same
  relative path.
- Update both languages when changing meaning, commands, links, frontmatter,
  diagrams, or page structure.
- Give every page a specific `title` and concise `description`. Reuse a small,
  stable tag vocabulary and use `sidebar.order` only for intentional ordering.
- Write task-oriented guides around outcomes. Put exhaustive fields, options,
  defaults, and schemas in reference pages.
- Add only implemented use cases with identified evidence and explicit manual
  validation gaps. Preserve old published routes and known fragment links when
  moving content.
- Prefer Markdown. Use MDX only when a Starlight or Astro component materially
  improves the explanation.
- Give each Mermaid diagram `accTitle` and `accDescr` text in the page's locale.
- Make examples safe to copy and identify placeholders, credentials, platform
  assumptions, and destructive commands.

## Design and accessibility rules

- Preserve semantic heading order and use native HTML elements for controls
  and links.
- Give interactive elements an accessible name and keep keyboard focus visible.
- Do not encode meaning with color alone. Check both color modes and narrow
  screens.
- Keep fonts local to the operating system. Do not add font downloads without
  an explicit requirement.
- Change the accent through `--project-accent-hue` in `src/styles/theme.css`.
- Keep code blocks on Slack Ochin and Tokyo Night unless project requirements
  intentionally change.

## Completion checklist

1. Confirm matching English and Japanese routes, content, and links.
2. Run `pnpm check`.
3. Confirm `/`, `/ja/`, and both localized versions of changed pages build.
4. For visual changes, inspect desktop and mobile layouts in light and dark
   modes, including keyboard focus and menus with and without a sidebar.
5. Update `README.md` when commands, structure, configuration, or the content
   workflow changes.
