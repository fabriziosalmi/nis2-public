import { defineConfig } from 'vitepress'

export default defineConfig({
    title: "NIS2 Platform",
    description: "Open-source GRC platform for NIS2 Directive (EU 2022/2555). Governance framework, technical validation engine, incident response, and supply chain risk management.",
    base: "/nis2-public/",
    ignoreDeadLinks: true,
    appearance: 'dark',
    lastUpdated: true,
    head: [
        ['meta', { name: 'author', content: 'Fabrizio Salmi' }],
        ['meta', { name: 'keywords', content: 'NIS2, EU 2022/2555, GRC, governance, compliance, remediation, BIA, Art 21, CSIRT, supply chain, self-hosted' }],
        ['link', { rel: 'icon', type: 'image/svg+xml', href: '/nis2-public/favicon.svg' }],
        ['meta', { property: 'og:title', content: 'NIS2 Platform' }],
        ['meta', { property: 'og:description', content: 'Open-source GRC platform for NIS2 Directive compliance. Governance, remediation, incident response, supply chain risk.' }],
        ['meta', { property: 'og:type', content: 'website' }],
        ['meta', { property: 'og:url', content: 'https://fabriziosalmi.github.io/nis2-public/' }],
        ['meta', { name: 'twitter:card', content: 'summary' }],
        ['meta', { name: 'twitter:title', content: 'NIS2 Platform' }],
        ['meta', { name: 'twitter:description', content: 'Open-source GRC platform for NIS2 Directive compliance.' }],
    ],
    themeConfig: {
        logo: '/logo.svg',
        siteTitle: 'NIS2 Platform',

        nav: [
            { text: 'Home', link: '/' },
            { text: 'Guide', link: '/guide/getting-started' },
            { text: 'National Modules', link: '/guide/acn-compliance' },
            { text: 'API', link: '/reference/api' },
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
                ]
            },
            {
                text: 'Compliance',
                collapsed: true,
                items: [
                    { text: 'Italy: D.Lgs 138/2024 + ACN', link: '/guide/acn-compliance' },
                    { text: 'Governance Checklist', link: '/governance/checklist' },
                    { text: 'Services', link: '/guide/services' }
                ]
            },
            {
                text: 'Reference',
                collapsed: true,
                items: [
                    { text: 'API Reference', link: '/reference/api' },
                    { text: 'Scanner Checks', link: '/reference/scanner-checks' },
                    { text: 'Architecture', link: '/reference/architecture' }
                ]
            }
        ],

        socialLinks: [
            { icon: 'github', link: 'https://github.com/fabriziosalmi/nis2-public' }
        ],

        search: {
            provider: 'local'
        },

        editLink: {
            pattern: 'https://github.com/fabriziosalmi/nis2-public/edit/main/docs/:path',
            text: 'Edit this page on GitHub'
        },

        footer: {
            message: 'AGPL-3.0 | Commercial license available | <a href="mailto:fabrizio.salmi@gmail.com">fabrizio.salmi@gmail.com</a>',
            copyright: 'Copyright 2024-2026 Fabrizio Salmi'
        }
    }
})
