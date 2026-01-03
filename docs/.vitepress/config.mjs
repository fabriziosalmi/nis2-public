import { defineConfig } from 'vitepress'

export default defineConfig({
    title: 'NIS2 Compliance Scanner',
    description: 'Automated NIS2 Directive compliance scanning and reporting tool',
    base: '/nis2-public/',

    ignoreDeadLinks: [
        /^https?:\/\/localhost/,
    ],

    themeConfig: {
        logo: '/logo.svg',

        nav: [
            { text: 'Home', link: '/' },
            { text: 'Guide', link: '/guide/getting-started' },
            { text: 'Examples', link: '/examples/' },
            { text: 'Reference', link: '/reference/cli' }
        ],

        sidebar: {
            '/guide/': [
                {
                    text: 'Introduction',
                    items: [
                        { text: 'Getting Started', link: '/guide/getting-started' },
                        { text: 'Quick Start', link: '/guide/quick-start' },
                        { text: 'Features', link: '/guide/features' }
                    ]
                },
                {
                    text: 'Docker Deployment',
                    items: [
                        { text: 'Docker Guide', link: '/guide/docker' },
                        { text: 'Configuration', link: '/guide/configuration' },
                        { text: 'Deployment Options', link: '/guide/deployment' }
                    ]
                },
                {
                    text: 'Advanced',
                    items: [
                        { text: 'Troubleshooting', link: '/guide/troubleshooting' },
                        { text: 'CI/CD Integration', link: '/guide/cicd' }
                    ]
                }
            ],
            '/examples/': [
                {
                    text: 'Examples',
                    items: [
                        { text: 'Overview', link: '/examples/' },
                        { text: 'Basic Scan', link: '/examples/basic-scan' },
                        { text: 'Production Setup', link: '/examples/production' },
                        { text: 'Multi-Target Scan', link: '/examples/multi-target' }
                    ]
                }
            ],
            '/reference/': [
                {
                    text: 'Reference',
                    items: [
                        { text: 'Configuration Schema', link: '/reference/config-schema' },
                        { text: 'CLI Commands', link: '/reference/cli' },
                        { text: 'API', link: '/reference/api' }
                    ]
                }
            ]
        },

        socialLinks: [
            { icon: 'github', link: 'https://github.com/fabriziosalmi/nis2-public' }
        ],

        footer: {
            message: 'Released under the MIT License.',
            copyright: 'Copyright © 2024-present'
        },

        search: {
            provider: 'local'
        }
    }
})
