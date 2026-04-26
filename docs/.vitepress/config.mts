import { defineConfig } from 'vitepress'

export default defineConfig({
    title: "NIS2 Platform",
    description: "Enterprise NIS2 Directive compliance scanning, certificate intelligence, and AI-powered remediation.",
    base: "/nis2-public/",
    ignoreDeadLinks: true,
    appearance: 'dark',
    head: [
        ['meta', { name: 'author', content: 'Fabrizio Salmi' }],
        ['meta', { name: 'keywords', content: 'NIS2, compliance, scanner, certificate, remediation, AGPL, EU directive' }],
    ],
    themeConfig: {
        nav: [
            { text: 'Home', link: '/' },
            { text: 'Guide', link: '/guide/getting-started' },
            { text: 'Reference', link: '/reference/api' },
            { text: 'Governance', link: '/governance/checklist' },
            { text: 'Services', link: '/guide/services' }
        ],

        sidebar: [
            {
                text: 'Guide',
                items: [
                    { text: 'Getting Started', link: '/guide/getting-started' },
                    { text: 'Configuration', link: '/guide/configuration' },
                    { text: 'Usage', link: '/guide/usage' },
                    { text: 'Deployment', link: '/guide/deployment' },
                    { text: 'Secrets Rotation', link: '/guide/secrets-rotation' },
                    { text: 'Services', link: '/guide/services' }
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

        search: {
            provider: 'local'
        },

        footer: {
            message: 'Licensed under AGPL-3.0. Professional NIS2 consulting: fabrizio.salmi@gmail.com',
            copyright: 'Copyright 2024-2026 Fabrizio Salmi'
        }
    }
})
