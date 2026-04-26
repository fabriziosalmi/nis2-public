import { defineConfig } from 'vitepress'

export default defineConfig({
    title: "NIS2 Platform",
    description: "NIS2 Directive (EU 2022/2555) Continuous Posture Management. GRC framework, technical validation, incident response, supply chain risk.",
    base: "/nis2-public/",
    ignoreDeadLinks: true,
    appearance: 'dark',
    head: [
        ['meta', { name: 'author', content: 'Fabrizio Salmi' }],
        ['meta', { name: 'keywords', content: 'NIS2, D.Lgs 138/2024, ACN, governance, compliance, remediation, BIA, Art 21, CSIRT, supply chain' }],
    ],
    themeConfig: {
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
                items: [
                    { text: 'Italy: D.Lgs 138/2024 + ACN', link: '/guide/acn-compliance' },
                    { text: 'Governance Checklist', link: '/governance/checklist' },
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
            }
        ],

        socialLinks: [
            { icon: 'github', link: 'https://github.com/fabriziosalmi/nis2-public' }
        ],

        search: {
            provider: 'local'
        },

        footer: {
            message: 'AGPL-3.0 | Licenza commerciale disponibile | fabrizio.salmi@gmail.com',
            copyright: 'Copyright 2024-2026 Fabrizio Salmi'
        }
    }
})
