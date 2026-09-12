# Freja documentation site

This directory contains the English and Japanese Freja documentation built
with Astro Starlight. It includes responsive shared navigation, localized tag
search, page metadata, themed Mermaid diagrams, KaTeX equations, and local
system-font styling. Product behavior is documented from the Rust
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
├── guides/             # General feature and configuration operations
├── use-cases/          # Concrete scenarios, from a goal to observed evidence
│   └── browser-form-lab/ # Overview, setup, GET, interventions, recovery, contract
├── reference/          # CLI, configuration, and schema reference
├── troubleshooting/    # Symptoms, causes, and recovery
├── developer/          # Architecture, security, hooks, tests, ADRs
└── ja/                 # Matching Japanese tree
```

Every page needs a title and description. Reuse a small stable tag vocabulary,
set `sidebar.order` for intentional navigation, and update both locales in the
same change. Regular pages render the description below the title and show the
most recent date plus up to three tags; larger tag sets collapse behind a
disclosure. Splash pages omit this metadata row. Use `.mdx` only for pages that
import components.

Add diagrams with a fenced `mermaid` block. Diagrams follow the project accent,
rerender when the color mode changes, and fall back to their source if rendering
fails. Include localized `accTitle` and `accDescr` directives in every diagram
so its purpose and relationship remain available to assistive technology.

Inline math uses single dollar delimiters and display math uses double dollar
delimiters. KaTeX renders both forms during the build without client-side
JavaScript. Escape a literal dollar sign as `\$` when it could be read as math.

## Navigation and visual system

Desktop pages show the shared Docs and Tags links in the header. On mobile the
same links move into the sidebar menu; pages without a sidebar, including the
home and tag pages, receive a compact menu with theme and language controls.
The table of contents includes H2 through H4 headings.

`src/components/PageTitle.astro` owns the visible description and metadata row.
`src/components/PrimaryNavigation.astro` owns the links reused by desktop and
mobile layouts. `src/styles/site.css` owns the shared typography and content
surfaces, while `src/styles/theme.css` derives the palette from
`--project-accent-hue`. The Starlight header loads `src/assets/FrejaLogo.png`.
Both localized landing-page heroes and the browser icon use
`public/favicon.png`. Fonts remain local to the reader's operating system.

## Adding a use case

Use cases explain how to achieve a concrete purpose end to end and how to tell
what happened. Guides explain general feature/configuration operations;
Reference documents complete contracts. Link to those shared explanations
instead of duplicating them in a scenario. A fixture-specific HTTP contract can
live beside its use case, clearly scoped to that fixture.

Add only an implemented scenario with identified evidence and explicit manual
validation gaps. Do not create placeholder pages or implied roadmaps. Add its
purpose and entry link to both `use-cases/index.md` pages and a translated group
under the top-level Use cases sidebar in `astro.config.mjs`. Keep the home entry
pointing to the use-case list.

Give each scenario an overview/page map. Split preparation, first success,
interventions, recovery/cleanup and detailed contracts by reader task when the
content needs multiple pages. Each page states its starting state, completion
point and next destination; use explicit localized `prev`/`next` frontmatter
and an overview link. Use descriptive page titles and semantic heading levels,
not global step numbers across pages. Nest local actions under their topic
(e.g. H3 preparation actions under H2 Quickstart). Keep ordered lists for actual
local sequences and figure legends, and preserve previous fragments with
invisible anchor aliases when renaming headings. Keep both locales' paths,
commands, examples, figure labels and safety/evidence meanings aligned. Keep shared image paths and capture instructions stable.

When moving an existing page, update canonical links in content and READMEs.
Retain a short old-route migration page with `sidebar.hidden: true` and
`pagefind: false`; preserve known fragment IDs with a direct link to each new
destination. It remains an ordinary static page, usable without JavaScript or
host-specific redirects. Do not keep the full article in both places. The old
`guides/browser-form-lab/` route preserves `#quickstart`, `#cleanup`,
`#web-surfaces` and `#failure-and-re-entry` in both locales.

## Validation

```sh
pnpm check
```

This validates frontmatter, English/Japanese route parity, generated routes,
internal links and anchors, and Pagefind indexing. When changing layout or
components, also inspect desktop and mobile widths in both color modes and
verify keyboard focus.

For a move, also test old URLs/fragments and their destination links on the
built local site, plus the new sidebar, home entry, previous/next and locale
switcher at desktop/mobile widths. Compare pre-move content to confirm that
steps, code blocks, figures, contracts and cleanup guards survived the split.

Production hosting is intentionally not encoded in this directory. Add Astro's
`site` (and `base` when needed) only when the deployment hostname and path are
known, so canonical URLs and asset paths do not advertise a placeholder.
