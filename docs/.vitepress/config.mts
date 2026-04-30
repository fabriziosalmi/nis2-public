import { defineConfig } from 'vitepress'
import tailwindcss from '@tailwindcss/vite'

const SITE_URL = 'https://fabriziosalmi.github.io/nis2-public/'
const OG_IMAGE = `${SITE_URL}og.png`

const jsonLd = {
    '@context': 'https://schema.org',
    '@type': 'SoftwareApplication',
    name: 'NIS2 Platform',
    applicationCategory: 'BusinessApplication',
    operatingSystem: 'Linux',
    description: 'Open-source GRC platform for NIS2 Directive (EU 2022/2555) — governance framework, technical validation, incident response, supply chain risk.',
    url: SITE_URL,
    image: OG_IMAGE,
    offers: { '@type': 'Offer', price: '0', priceCurrency: 'EUR' },
    license: 'https://www.gnu.org/licenses/agpl-3.0.html',
    softwareVersion: '2.4.4',
    author: {
        '@type': 'Person',
        name: 'Fabrizio Salmi',
        url: 'https://github.com/fabriziosalmi',
    },
    publisher: {
        '@type': 'Person',
        name: 'Fabrizio Salmi',
    },
    keywords: 'NIS2, EU 2022/2555, GRC, Art 21, ACN, D.Lgs 138/2024, CSIRT, BIA, supply chain',
}

export default defineConfig({
    title: "NIS2 Platform",
    description: "Open-source GRC platform for NIS2 Directive (EU 2022/2555). Governance framework, technical validation engine, incident response, and supply chain risk management.",
    base: "/nis2-public/",
    ignoreDeadLinks: true,
    appearance: 'dark',
    lastUpdated: true,
    head: [
        ['meta', { name: 'author', content: 'Fabrizio Salmi' }],
        ['meta', { name: 'keywords', content: 'NIS2, EU 2022/2555, GRC, governance, compliance, remediation, BIA, Art 21, CSIRT, supply chain, self-hosted, ACN, D.Lgs 138/2024' }],
        ['meta', { name: 'theme-color', content: '#0071e3' }],
        ['link', { rel: 'icon', type: 'image/svg+xml', href: '/nis2-public/favicon.svg' }],
        // Open Graph (LinkedIn, Slack, Telegram preview)
        ['meta', { property: 'og:title', content: 'NIS2 Platform' }],
        ['meta', { property: 'og:description', content: 'Open-source GRC platform for NIS2 Directive compliance. Governance, remediation, incident response, supply chain risk.' }],
        ['meta', { property: 'og:type', content: 'website' }],
        ['meta', { property: 'og:url', content: SITE_URL }],
        ['meta', { property: 'og:image', content: OG_IMAGE }],
        ['meta', { property: 'og:image:width', content: '1200' }],
        ['meta', { property: 'og:image:height', content: '630' }],
        ['meta', { property: 'og:image:alt', content: 'NIS2 Platform — open-source GRC for NIS2 Directive (EU 2022/2555)' }],
        ['meta', { property: 'og:locale', content: 'en_US' }],
        // Twitter card with large image
        ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
        ['meta', { name: 'twitter:title', content: 'NIS2 Platform' }],
        ['meta', { name: 'twitter:description', content: 'Open-source GRC platform for NIS2 Directive compliance.' }],
        ['meta', { name: 'twitter:image', content: OG_IMAGE }],
        // Structured data for rich search results
        ['script', { type: 'application/ld+json' }, JSON.stringify(jsonLd)],
        // hreflang signals to Google that the home page exists in EN and IT —
        // even though the URL is the same (we render both versions in the DOM
        // and CSS-hide one based on `<html class="locale-X">`). This is the
        // canonical way to declare bilingual content without per-locale URLs.
        ['link', { rel: 'alternate', hreflang: 'en', href: SITE_URL }],
        ['link', { rel: 'alternate', hreflang: 'it', href: SITE_URL }],
        ['link', { rel: 'alternate', hreflang: 'x-default', href: SITE_URL }],
        // Pre-paint locale detection. Runs synchronously in <head> (before
        // <body> renders) so the user never sees the "wrong" language flash.
        // Read order: explicit user choice in localStorage > navigator.language
        // > default 'en'. Sets `class="locale-en|it"` on <html>; the home
        // CSS hides the inactive language. ~280 chars, no deps.
        [
            'script',
            {},
            `(function(){try{var s=localStorage.getItem('nis2-doc-locale');var l=s||((navigator.language||'en').toLowerCase().split('-')[0]);var c=l==='it'?'locale-it':'locale-en';document.documentElement.classList.add(c);}catch(e){document.documentElement.classList.add('locale-en');}})();`,
        ],
    ],
    // Wire Tailwind v4 into the VitePress Vite pipeline so the custom Home
    // component (theme/components/Home.vue) can use utility classes parity-
    // matched with the dashboard app. Scoped to the docs build only — does
    // not leak into the dashboard's webpack pipeline.
    vite: {
        plugins: [tailwindcss()],
    },
    themeConfig: {
        logo: '/logo.svg',
        siteTitle: 'NIS2 Platform',

        nav: [
            { text: 'Home', link: '/' },
            { text: 'Guide', link: '/guide/getting-started' },
            { text: 'National Modules', link: '/guide/acn-compliance' },
            { text: 'API', link: '/reference/api' },
            { text: 'Services', link: '/guide/services' },
            {
                text: 'v2.4',
                items: [
                    { text: 'Releases', link: 'https://github.com/fabriziosalmi/nis2-public/releases' },
                    { text: 'Changelog', link: 'https://github.com/fabriziosalmi/nis2-public/blob/main/CHANGELOG.md' },
                    { text: 'Security policy', link: 'https://github.com/fabriziosalmi/nis2-public/blob/main/SECURITY.md' },
                ],
            },
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
            { icon: 'github', link: 'https://github.com/fabriziosalmi/nis2-public' },
            { icon: 'linkedin', link: 'https://www.linkedin.com/in/fabriziosalmi/' },
        ],

        search: {
            provider: 'local'
        },

        editLink: {
            pattern: 'https://github.com/fabriziosalmi/nis2-public/edit/main/docs/:path',
            text: 'Edit this page on GitHub'
        },

        footer: {
            message: 'AGPL-3.0 · <a href="https://github.com/fabriziosalmi/nis2-public/releases">Releases</a> · <a href="https://github.com/fabriziosalmi/nis2-public/blob/main/CHANGELOG.md">Changelog</a> · <a href="https://github.com/fabriziosalmi/nis2-public/blob/main/SECURITY.md">Security policy</a> · Commercial license: <a href="mailto:fabrizio.salmi@gmail.com">contact</a>',
            copyright: '© 2024–2026 Fabrizio Salmi · built from Italy 🇮🇹'
        }
    }
})
