// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import DefaultTheme from 'vitepress/theme'
import type { App } from 'vue'
import './custom.css'
// Tailwind v4 entry — feeds the Home component below. Imported AFTER
// custom.css so utility classes win over the older VitePress-targeted
// rules wherever they collide.
import './style.css'
import Home from './components/Home.vue'

export default {
  ...DefaultTheme,
  enhanceApp({ app }: { app: App }) {
    // Registered globally so docs/index.md can `<Home />` without an
    // explicit script-setup import.
    app.component('Home', Home)
  },
}
