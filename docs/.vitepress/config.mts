import { defineConfig } from 'vitepress'

export default defineConfig({
    title: "NIS2 Platform",
    description: "NIS2 Compliance Scanning & Management Platform",
    base: "/nis2-public/",
    ignoreDeadLinks: true,
    themeConfig: {
        nav: [
            { text: 'Home', link: '/' },
            { text: 'Guide', link: '/guide/getting-started' },
            { text: 'Reference', link: '/reference/api' },
            { text: 'Governance', link: '/governance/checklist' }
        ],

        sidebar: [
            {
                text: 'Guide',
                items: [
                    { text: 'Getting Started', link: '/guide/getting-started' },
                    { text: 'Configuration', link: '/guide/configuration' },
                    { text: 'Usage', link: '/guide/usage' },
                    { text: 'Deployment', link: '/guide/deployment' }
                ]
            },
            {
                text: 'Reference',
                items: [
                    { text: 'API Reference', link: '/reference/api' },
                    { text: 'Scanner Checks', link: '/reference/scanner-checks' },
                    { text: 'Architecture', link: '/reference/architecture' }
                ]
            },
            {
                text: 'Governance',
                items: [
                    { text: 'Checklist', link: '/governance/checklist' }
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
