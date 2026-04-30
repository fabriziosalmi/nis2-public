---
# v2.4.27: replaced the VitePress default `home` layout (Hero +
# Features grid) with the custom bilingual landing component
# (.vitepress/theme/components/Home.vue), wired through the global
# theme registration in .vitepress/theme/index.ts.
#
# layout / sidebar / aside flags:
#   - `layout: page` keeps the VitePress nav at the top (visitors
#     still need to reach Guide / API / etc) but drops the doc-page
#     chrome.
#   - `sidebar: false` is required because the VitePress config has a
#     site-wide sidebar tree; without this flag the home page would
#     render with the doc sidebar pinned to the left, which collapses
#     the marketing canvas to ~70% width and breaks the hero centring.
#   - `aside: false` for the same reason on the right rail.
#   - `pageClass: docs-home` lets us target this page from CSS without
#     leaking utility selectors into other docs pages.
layout: page
sidebar: false
aside: false
pageClass: docs-home
---

<Home />
