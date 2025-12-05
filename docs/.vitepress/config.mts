import { defineConfig } from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
    title: "NIS2 Checker",
    description: "Automated NIS2 Compliance & Governance Tool",
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
                    { text: 'API Reference', link: '/reference/api' }
                ]
            }
        ],

        socialLinks: [
            { icon: 'github', link: 'https://github.com/fabriziosalmi/nis2-checker' }
        ],

        footer: {
            message: 'Released under the MIT License.',
            copyright: 'Copyright © 2025 NIS2 Checker Team'
        }
    }
})
