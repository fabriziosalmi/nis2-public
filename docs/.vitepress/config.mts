import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
    title: "NIS2 Checker",
    description: "Enterprise NIS2 Compliance & Audit Platform",
    base: "/nis2-public/",
    ignoreDeadLinks: true,
    themeConfig: {
        // https://vitepress.dev/reference/default-theme-config
        nav: [
            { text: 'Home', link: '/' },
            { text: 'Guide', link: '/guide/getting-started' },
            { text: 'Governance', link: '/governance/checklist' }
        ],

        sidebar: [
            {
                text: 'Guide',
                items: [
                    { text: 'Getting Started', link: '/guide/getting-started' },
                    { text: 'Configuration', link: '/guide/configuration' },
                    { text: 'Usage', link: '/guide/usage' }
                ]
            },
            {
                text: 'Governance',
                items: [
                    { text: 'Checklist', link: '/governance/checklist' }
                ]
            },
            {
                text: 'Reference',
                items: [
                    { text: 'API Reference', link: '/reference/api' },
                    { text: 'Strategic Checks', link: '/reference/strategic_checks' }
                ]
            }
        ],

        socialLinks: [
            { icon: 'github', link: 'https://github.com/fabriziosalmi/nis2-public' }
        ],

        footer: {
            message: 'Released under the MIT License.',
            copyright: 'Copyright © 2025-2026 Fabrizio Salmi'
        }
    }
})
