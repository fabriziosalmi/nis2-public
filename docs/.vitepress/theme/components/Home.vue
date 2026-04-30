<!--
  Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
  SPDX-License-Identifier: AGPL-3.0-only
  NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
-->
<script setup lang="ts">
/*
 * Home.vue — bilingual (EN + IT) marketing landing for the docs site.
 *
 * v2.4.27 — replaces the VitePress default-home (Hero + Features) on
 * `/`. The dashboard app's landing got rewritten the same release and
 * landed at a level the boilerplate VitePress hero couldn't compete
 * with; this brings the docs surface up to parity, with CTA wiring
 * bent towards "install / get started" instead of "register / login".
 *
 * Bilingual rendering strategy — important to understand:
 *   - The DOM contains BOTH the English and Italian copy, paired
 *     through `<span class="locale-en">…</span><span class="locale-it">…</span>`.
 *   - The active language is gated via CSS in theme/style.css —
 *     `html.locale-it .locale-en { display: none }` and the mirror.
 *   - The class on `<html>` is set BEFORE first paint by an inline
 *     script in config.mts head[]; the user never sees a flash.
 *   - The toggle component below writes `localStorage.nis2-doc-locale`
 *     and flips the class at runtime.
 *
 * Why dual-DOM and not Vue refs that re-render on locale change:
 *   - Statically-generated HTML lets crawlers see both languages.
 *     hreflang links in <head> tell Google we're aware of the duplicate.
 *   - Reactive swap on a ref would mean the SSG'd HTML always carries
 *     ONE language; the IT user would see EN until hydration completed.
 *     Even ~50ms of "wrong" copy is a worse first impression than
 *     slightly larger HTML.
 */
import { ref, onMounted } from 'vue'
import { withBase } from 'vitepress'
import {
  ShieldCheck,
  Radar,
  AlertCircle,
  Building2,
  Activity,
  Bot,
  ArrowRight,
  Github,
  Lock,
  Server,
  Code2,
  Check,
  Globe,
  Terminal,
} from 'lucide-vue-next'
import Logo from './Logo.vue'

// Reactive locale state — drives the toggle's pressed-state, NOT the
// DOM rendering (the DOM stays bilingual). Initialised on mount from
// the same source the inline script uses, so toggle and CSS always
// agree.
const locale = ref<'en' | 'it'>('en')

onMounted(() => {
  try {
    const stored = localStorage.getItem('nis2-doc-locale') as
      | 'en'
      | 'it'
      | null
    if (stored === 'en' || stored === 'it') {
      locale.value = stored
      return
    }
    const nav = (navigator.language || 'en').toLowerCase().split('-')[0]
    locale.value = nav === 'it' ? 'it' : 'en'
  } catch {
    locale.value = 'en'
  }
})

function setLocale(next: 'en' | 'it') {
  locale.value = next
  try {
    localStorage.setItem('nis2-doc-locale', next)
  } catch {
    /* private browsing / disabled storage — fail silently, the in-page
       toggle still works for this session via the class swap below. */
  }
  // Swap the class on <html> live so the CSS hide rules pick the new
  // language without a reload.
  const root = document.documentElement
  root.classList.toggle('locale-it', next === 'it')
  root.classList.toggle('locale-en', next === 'en')
}

// ─────────────────────────────────────────────────────────────────
// Legal-disclaimer interstitial (v2.5.2)
// ─────────────────────────────────────────────────────────────────
// Mirror of packages/web/src/components/legal/legal-disclaimer-modal.tsx
// for the docs surface. Different origin → distinct localStorage; same
// pattern: blocking dialog on first visit, persisted acknowledgement,
// versionable key. Bumping `LEGAL_STORAGE_KEY` forces every prior
// acceptance to expire when the disclaimer text changes materially.
const LEGAL_STORAGE_KEY = 'nis2-doc-legal-disclaimer-v1'
const showLegal = ref(false)

onMounted(() => {
  try {
    if (localStorage.getItem(LEGAL_STORAGE_KEY) !== 'accepted') {
      showLegal.value = true
    }
  } catch {
    showLegal.value = true
  }
})

function acceptLegal() {
  try {
    localStorage.setItem(LEGAL_STORAGE_KEY, 'accepted')
  } catch {
    /* fail silently — user will see the dialog again next visit */
  }
  showLegal.value = false
}

// Tech-stack pills — language-neutral product names.
const STACK = [
  'Next.js 15',
  'React 19',
  'FastAPI',
  'PostgreSQL 16',
  'Celery',
  'Tailwind v4',
  'MCP',
] as const

/*
 * Feature cards — bilingual copy in pairs.
 *
 * The order matches the dashboard landing for visual parity. CTA links
 * point at the docs surface (anchors in this site), not at /register —
 * a docs visitor wants to learn the feature, not provision an account.
 */
const FEATURES = [
  {
    icon: ShieldCheck,
    label: 'Art. 21',
    href: '/governance/checklist',
    en: {
      title: 'Governance Framework',
      body: '30-item checklist mapped to NIS2 Art. 21 (a)–(j), with owner, evidence, and review-cadence tracking. Cross-referenced to the Italian D.Lgs 138/2024 transposition and ACN determine.',
    },
    it: {
      title: 'Framework di Governance',
      body: "Checklist a 30 punti mappata sull'Art. 21 NIS2 (a)–(j), con tracciamento di responsabile, evidenze e cadenza di revisione. Riferimenti incrociati al D.Lgs 138/2024 e alle determine ACN.",
    },
  },
  {
    icon: Radar,
    label: 'Scanner',
    href: '/reference/scanner-checks',
    en: {
      title: 'Technical Validation',
      body: '30+ async checks on TLS, DNS, certificates, HTTP headers, port exposure, secrets, and resilience. The probe that verifies if the policy your governance framework documents is actually enforced on the wire.',
    },
    it: {
      title: 'Validazione Tecnica',
      body: 'Oltre 30 controlli asincroni su TLS, DNS, certificati, header HTTP, esposizione porte, secret e resilienza. La sonda che verifica se le policy del framework sono davvero applicate sulla rete.',
    },
  },
  {
    icon: AlertCircle,
    label: 'Art. 23',
    href: '/guide/acn-compliance',
    en: {
      title: 'Incident Response',
      body: 'Art. 23 lifecycle with the 24h / 72h / 1-month deadlines tracked as live countdowns. The Red Button generates a CSIRT-ready Early Warning JSON from three fields plus the latest asset inventory.',
    },
    it: {
      title: 'Gestione Incidenti',
      body: "Ciclo di vita Art. 23 con countdown in tempo reale per le scadenze 24h / 72h / 1 mese. Il Red Button genera in pochi secondi un payload Early Warning pronto per il CSIRT, da 3 campi più l'inventario asset.",
    },
  },
  {
    icon: Building2,
    label: 'Art. 18',
    href: '/reference/api',
    en: {
      title: 'Supply Chain Risk',
      body: 'Vendor inventory with 4-level criticality, security scoring, contract tracking (SLA, audit rights, security clauses), and ACN Art. 18 fields for Italian transposition.',
    },
    it: {
      title: 'Rischio Supply Chain',
      body: "Inventario fornitori con criticità a 4 livelli, scoring di sicurezza, tracciamento dei contratti (SLA, diritti di audit, clausole di sicurezza) e i campi specifici per l'Art. 18 e l'ACN.",
    },
  },
  {
    icon: Activity,
    label: 'BIA',
    href: '/reference/api',
    en: {
      title: 'Business Impact Analysis',
      body: 'Process inventory with RTO / RPO / MTPD, five-dimension impact scoring, asset and vendor dependency mapping, and automatic BCP / DRP gap detection.',
    },
    it: {
      title: 'Business Impact Analysis',
      body: "Inventario processi con RTO / RPO / MTPD, scoring d'impatto su 5 dimensioni, mappatura delle dipendenze tra asset e fornitori e rilevamento automatico dei gap BCP / DRP.",
    },
  },
  {
    icon: Bot,
    label: 'MCP',
    href: '/reference/api',
    en: {
      title: 'AI Copilot + MCP',
      body: 'Optional remediation copilot via Ollama (air-gapped) or OpenAI. Native Model Context Protocol server lets Claude, Cursor, and other AI agents query your compliance posture directly.',
    },
    it: {
      title: 'Copilot AI + MCP',
      body: 'Copilot opzionale di remediation via Ollama (air-gapped) o OpenAI. Server Model Context Protocol nativo: Claude, Cursor e altri agenti AI possono interrogare direttamente la tua postura di compliance.',
    },
  },
] as const

const STEPS = [
  {
    n: '01',
    showCmd: true,
    en: {
      title: 'Clone and run locally',
      body: 'make dev — the platform comes up on http://localhost:8077 with Postgres, Redis, and the API in one compose file.',
    },
    it: {
      title: 'Clona e avvia in locale',
      body: "make dev — la piattaforma si avvia su http://localhost:8077 con Postgres, Redis e l'API in un unico file compose.",
    },
  },
  {
    n: '02',
    showCmd: false,
    en: {
      title: 'Map your governance',
      body: 'Walk the 30-item Art. 21 checklist with owners and evidence. Add assets, vendors, and processes. Generate the executive PDF for the board.',
    },
    it: {
      title: 'Mappa la tua governance',
      body: "Percorri la checklist a 30 punti dell'Art. 21 con responsabili ed evidenze. Aggiungi asset, fornitori e processi. Genera il PDF direzionale per il consiglio.",
    },
  },
  {
    n: '03',
    showCmd: false,
    en: {
      title: 'Run the technical probe',
      body: 'Schedule scans against your domains and IP ranges. Findings flow into the same workspace as the governance posture. Cross-reference each finding to the Art. 21 sub-paragraph it weakens.',
    },
    it: {
      title: 'Avvia la sonda tecnica',
      body: "Pianifica scansioni su domini e range IP. I finding confluiscono nello stesso workspace della governance. Ogni finding può essere collegato alla lettera dell'Art. 21 che indebolisce.",
    },
  },
] as const

const AUDIENCES = [
  {
    en: {
      role: 'CISO',
      body: 'Bridge the gap between the policy you signed off and what the network actually does. Boardroom-ready evidence on a deadline.',
    },
    it: {
      role: 'CISO',
      body: "Colma il divario tra la policy che hai firmato e ciò che fa la rete. Evidenze pronte per il CdA, in tempo per la scadenza.",
    },
  },
  {
    en: {
      role: 'DPO',
      body: 'GDPR / ePrivacy posture surfaced separately from NIS2 — never aggregated into the wrong score. Vendor risk and incident workflows aligned to your obligations.',
    },
    it: {
      role: 'DPO',
      body: "Postura GDPR / ePrivacy gestita separatamente da NIS2 — mai aggregata nello score sbagliato. Workflow di rischio fornitore e gestione incidenti allineati ai tuoi obblighi.",
    },
  },
  {
    en: {
      role: 'NIS2 Consultant',
      body: 'Multi-tenant by design. Manage every client in one self-hosted instance. White-label PDF reports per organisation; switch tenants without logging out.',
    },
    it: {
      role: 'Consulente NIS2',
      body: "Multi-tenant per design. Gestisci ogni cliente in un'unica istanza self-hosted. Report PDF white-label per organizzazione; cambia tenant senza fare logout.",
    },
  },
  {
    en: {
      role: 'IT / SecOps',
      body: '30+ async checks shipped, MCP-ready for AI agents, Prometheus-friendly metrics, scheduled scans via cron. No third-party SaaS in your tenant blast radius.',
    },
    it: {
      role: 'IT / SecOps',
      body: "Oltre 30 controlli asincroni inclusi, server MCP per agenti AI, metriche compatibili con Prometheus, scansioni pianificate via cron. Nessun SaaS terzo nel perimetro del tuo tenant.",
    },
  },
] as const
</script>

<template>
  <!-- Outer wrapper: the page background overrides VitePress's default
       so the gradients we render in the hero blend correctly. We use
       Tailwind tokens that resolve to neutral-50 / neutral-950 to track
       VitePress dark/light themes without hardcoding hex. -->
  <div class="docs-home min-h-screen bg-white text-slate-900 dark:bg-neutral-950 dark:text-slate-100">
    <!-- Legal-disclaimer interstitial (v2.5.2). Blocking dialog on
         first visit; persisted via versioned localStorage key. The
         dual-locale dual-DOM pattern (EN+IT both rendered, gated by
         CSS via html.locale-X) keeps zero-flash behaviour consistent
         with the rest of the bilingual home. -->
    <div
      v-if="showLegal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="legal-disclaimer-title"
      aria-describedby="legal-disclaimer-body"
      class="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/95 p-4 backdrop-blur-sm"
    >
      <div class="w-full max-w-xl rounded-2xl border border-slate-800 bg-slate-900 p-8 shadow-2xl sm:p-10">
        <svg
          class="mx-auto mb-6 h-10 w-10 text-slate-400"
          xmlns="http://www.w3.org/2000/svg"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.75"
          stroke-linecap="round"
          stroke-linejoin="round"
          aria-hidden="true"
        >
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
          <path d="m9 12 2 2 4-4"></path>
        </svg>
        <h2 id="legal-disclaimer-title" class="text-center text-2xl font-bold tracking-tight text-slate-100">
          <span class="locale-en">Legal Notice</span>
          <span class="locale-it">Avviso Legale</span>
        </h2>
        <p id="legal-disclaimer-body" class="mt-6 text-center text-base leading-relaxed text-slate-300">
          <span class="locale-en">This tool provides automated classifications based on a subset of the NIS2 Directive (EU 2022/2555). It does not constitute legal advice. Consult a qualified lawyer to determine the obligations applicable to you.</span>
          <span class="locale-it">Questo strumento fornisce classificazioni automatizzate basate su un sottoinsieme della Direttiva NIS2 (UE 2022/2555). Non costituisce consulenza legale. Consultare un avvocato qualificato per determinare gli obblighi applicabili.</span>
        </p>
        <div class="mt-6 flex flex-wrap items-center justify-center gap-x-3 gap-y-1 text-sm">
          <a href="https://github.com/fabriziosalmi/nis2-public/blob/main/docs/terms.md" target="_blank" rel="noopener noreferrer" class="font-medium text-blue-400 underline-offset-4 hover:underline">
            <span class="locale-en">Terms of Use</span>
            <span class="locale-it">Termini di utilizzo</span>
          </a>
          <span aria-hidden="true" class="text-slate-600">·</span>
          <a href="https://github.com/fabriziosalmi/nis2-public/blob/main/docs/privacy.md" target="_blank" rel="noopener noreferrer" class="font-medium text-blue-400 underline-offset-4 hover:underline">
            <span class="locale-en">Privacy Policy</span>
            <span class="locale-it">Privacy Policy</span>
          </a>
        </div>
        <button
          type="button"
          @click="acceptLegal"
          class="mt-8 w-full rounded-md bg-blue-600 px-8 py-3 text-base font-semibold text-white transition-colors hover:bg-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-400 focus:ring-offset-2 focus:ring-offset-slate-900"
        >
          <span class="locale-en">I understand — Proceed</span>
          <span class="locale-it">Ho compreso — Procedi</span>
        </button>
      </div>
    </div>

    <!-- Locale toggle: top-right, sticks above hero. Tiny, unobtrusive,
         keyboard-focusable. Persists in localStorage. -->
    <div class="pointer-events-none fixed top-20 right-4 z-40 flex justify-end sm:top-24 sm:right-8">
      <div
        role="group"
        aria-label="Page language"
        class="pointer-events-auto inline-flex items-center gap-0.5 rounded-full border border-slate-200 bg-white/90 p-0.5 text-xs font-medium shadow-sm backdrop-blur dark:border-neutral-800 dark:bg-neutral-900/80"
      >
        <button
          type="button"
          @click="setLocale('en')"
          :class="[
            'rounded-full px-3 py-1 transition-colors',
            locale === 'en'
              ? 'bg-slate-900 text-white dark:bg-white dark:text-slate-900'
              : 'text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white'
          ]"
          :aria-pressed="locale === 'en'"
        >
          EN
        </button>
        <button
          type="button"
          @click="setLocale('it')"
          :class="[
            'rounded-full px-3 py-1 transition-colors',
            locale === 'it'
              ? 'bg-slate-900 text-white dark:bg-white dark:text-slate-900'
              : 'text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white'
          ]"
          :aria-pressed="locale === 'it'"
        >
          IT
        </button>
      </div>
    </div>

    <main>
      <!-- Hero -->
      <section class="relative overflow-hidden">
        <div
          aria-hidden="true"
          class="pointer-events-none absolute inset-0 -z-10 bg-[radial-gradient(60%_50%_at_50%_-10%,rgba(59,130,246,0.15),transparent_60%),radial-gradient(40%_40%_at_80%_30%,rgba(110,64,201,0.10),transparent_70%)]"
        ></div>
        <div class="mx-auto max-w-7xl px-4 pb-16 pt-20 sm:px-6 sm:pt-24 lg:px-8 lg:pt-32">
          <div class="mx-auto max-w-3xl text-center">
            <div class="mx-auto inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/80 px-3 py-1 text-xs font-medium text-slate-500 shadow-sm dark:border-neutral-800 dark:bg-neutral-900/80 dark:text-slate-400">
              <span class="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" aria-hidden="true"></span>
              <span class="locale-en">Open-source · AGPL-3.0 · self-hosted by design</span>
              <span class="locale-it">Open-source · AGPL-3.0 · progettato per il self-hosting</span>
            </div>
            <h1 class="mt-6 text-balance text-4xl font-bold tracking-tight sm:text-5xl lg:text-6xl">
              <span class="locale-en">NIS2 governance, technical validation, and incident response —</span>
              <span class="locale-it">Governance NIS2, validazione tecnica e gestione incidenti —</span>
              <span class="bg-gradient-to-br from-blue-600 to-violet-600 bg-clip-text text-transparent">
                <span class="locale-en"> under one roof.</span>
                <span class="locale-it"> in un'unica piattaforma.</span>
              </span>
            </h1>
            <p class="mx-auto mt-6 max-w-2xl text-pretty text-lg text-slate-600 dark:text-slate-400">
              <span class="locale-en">The open-source platform for the EU NIS2 Directive (2022/2555). Bridge the gap between Art. 21 policy and what your network actually does — without sending a single byte of scan data to a third party.</span>
              <span class="locale-it">La piattaforma open-source per la Direttiva NIS2 (UE 2022/2555). Colma il divario tra ciò che dichiarano le tue policy ex Art. 21 e ciò che fa realmente la tua rete — senza inviare un solo byte a terze parti.</span>
            </p>
            <div class="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
              <!-- Primary CTA — install path. Differs from the app
                   landing (which sends users to /register). -->
              <!-- `!text-white` / `!text-slate-900` use the Tailwind v4
                   `!` prefix so the colour is compiled with !important
                   and beats `.docs-home a { color: inherit }` from
                   style.css. Without this the CTA would render as a
                   black-or-white box with invisible text. -->
              <a
                :href="withBase('/guide/getting-started')"
                class="inline-flex w-full items-center justify-center gap-2 rounded-md bg-slate-900 px-8 py-3 text-sm font-medium !text-white transition-colors hover:bg-slate-800 dark:bg-white dark:!text-slate-900 dark:hover:bg-slate-100 sm:w-auto"
              >
                <span class="locale-en">Get started — free</span>
                <span class="locale-it">Inizia ora — gratis</span>
                <ArrowRight class="h-4 w-4" :stroke-width="2" aria-hidden="true" />
              </a>
              <a
                href="https://github.com/fabriziosalmi/nis2-public"
                target="_blank"
                rel="noopener noreferrer"
                class="inline-flex w-full items-center justify-center gap-2 rounded-md border border-slate-300 bg-white px-8 py-3 text-sm font-medium !text-slate-900 transition-colors hover:bg-slate-50 dark:border-neutral-700 dark:bg-neutral-900 dark:!text-slate-100 dark:hover:bg-neutral-800 sm:w-auto"
              >
                <Github class="h-4 w-4" :stroke-width="2" aria-hidden="true" />
                <span class="locale-en">Star on GitHub</span>
                <span class="locale-it">Star su GitHub</span>
              </a>
            </div>
            <p class="mt-4 text-xs text-slate-500 dark:text-slate-500">
              <span class="locale-en">Need a guided tour?
                <a :href="withBase('/guide/getting-started')" class="font-medium text-slate-900 underline-offset-4 hover:underline dark:text-slate-100">Read the Guide</a>
              </span>
              <span class="locale-it">Serve un tour guidato?
                <a :href="withBase('/guide/getting-started')" class="font-medium text-slate-900 underline-offset-4 hover:underline dark:text-slate-100">Leggi la guida</a>
              </span>
            </p>
          </div>
        </div>
      </section>

      <!-- Trust strip -->
      <section class="border-y border-slate-200 bg-slate-50/50 dark:border-neutral-800 dark:bg-neutral-900/50">
        <div class="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
          <dl class="grid grid-cols-2 gap-6 sm:grid-cols-4 sm:gap-4">
            <div class="text-center">
              <dt class="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">
                <span class="locale-en">automated checks</span>
                <span class="locale-it">controlli automatici</span>
              </dt>
              <dd class="mt-1 text-2xl font-bold tracking-tight">30+</dd>
            </div>
            <div class="text-center">
              <dt class="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">
                <span class="locale-en">EU languages</span>
                <span class="locale-it">lingue UE</span>
              </dt>
              <dd class="mt-1 text-2xl font-bold tracking-tight">5</dd>
            </div>
            <div class="text-center">
              <dt class="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">
                <span class="locale-en">NIS2 coverage</span>
                <span class="locale-it">copertura NIS2</span>
              </dt>
              <dd class="mt-1 text-2xl font-bold tracking-tight">Art. 18 / 21 / 23</dd>
            </div>
            <div class="text-center">
              <dt class="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">
                <span class="locale-en">SaaS dependencies</span>
                <span class="locale-it">dipendenze SaaS</span>
              </dt>
              <dd class="mt-1 text-2xl font-bold tracking-tight">0</dd>
            </div>
          </dl>
        </div>
      </section>

      <!-- Feature grid -->
      <section
        aria-labelledby="features-heading"
        class="mx-auto max-w-7xl px-4 py-20 sm:px-6 sm:py-24 lg:px-8"
      >
        <div class="mx-auto max-w-2xl text-center">
          <p class="text-sm font-semibold uppercase tracking-wider text-blue-600 dark:text-blue-400">
            <span class="locale-en">Six modules, one workspace</span>
            <span class="locale-it">Sei moduli, un solo workspace</span>
          </p>
          <h2 id="features-heading" class="mt-3 text-balance text-3xl font-bold tracking-tight sm:text-4xl">
            <span class="locale-en">Everything Art. 21 asks for, in one auditable platform.</span>
            <span class="locale-it">Tutto ciò che chiede l'Art. 21, in una piattaforma auditabile.</span>
          </h2>
          <p class="mt-4 text-slate-600 dark:text-slate-400">
            <span class="locale-en">Most NIS2 work is human work. The platform automates the parts that should be automated, and tracks the parts that legally require a person to sign their name to.</span>
            <span class="locale-it">La maggior parte del lavoro NIS2 resta lavoro umano. La piattaforma automatizza ciò che è automatizzabile e tiene traccia di ciò che richiede legalmente la firma di una persona.</span>
          </p>
        </div>
        <ul class="mt-14 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          <li
            v-for="f in FEATURES"
            :key="f.label"
            class="group relative flex flex-col rounded-xl border border-slate-200 bg-white p-6 transition-shadow hover:shadow-md dark:border-neutral-800 dark:bg-neutral-900/40"
          >
            <div class="flex items-center justify-between">
              <div class="rounded-lg bg-blue-50 p-2.5 dark:bg-blue-950/40">
                <component :is="f.icon" class="h-5 w-5 text-blue-600 dark:text-blue-400" aria-hidden="true" :stroke-width="2" />
              </div>
              <span class="rounded-full border border-slate-200 bg-white px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500 dark:border-neutral-700 dark:bg-neutral-900 dark:text-slate-400">
                {{ f.label }}
              </span>
            </div>
            <h3 class="mt-5 text-lg font-semibold tracking-tight">
              <span class="locale-en">{{ f.en.title }}</span>
              <span class="locale-it">{{ f.it.title }}</span>
            </h3>
            <p class="mt-2 flex-1 text-sm text-slate-600 dark:text-slate-400">
              <span class="locale-en">{{ f.en.body }}</span>
              <span class="locale-it">{{ f.it.body }}</span>
            </p>
            <a
              :href="withBase(f.href)"
              class="mt-4 inline-flex items-center gap-1 text-sm font-medium underline-offset-4 hover:underline"
            >
              <span class="locale-en">Learn more</span>
              <span class="locale-it">Scopri di più</span>
              <ArrowRight class="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" aria-hidden="true" :stroke-width="2" />
            </a>
          </li>
        </ul>
      </section>

      <!-- Showcase -->
      <section
        class="border-y border-slate-200 bg-gradient-to-b from-slate-50/40 to-transparent dark:border-neutral-800 dark:from-neutral-900/40"
      >
        <div class="mx-auto max-w-7xl px-4 py-20 sm:px-6 sm:py-24 lg:px-8">
          <div class="mx-auto max-w-2xl text-center">
            <h2 class="text-balance text-3xl font-bold tracking-tight sm:text-4xl">
              <span class="locale-en">Posture you can read in 30 seconds.</span>
              <span class="locale-it">Una postura leggibile in 30 secondi.</span>
            </h2>
            <p class="mt-4 text-slate-600 dark:text-slate-400">
              <span class="locale-en">One dashboard for total scans, average compliance score, open findings, and monitored assets — with the recent-scan trend on the same screen.</span>
              <span class="locale-it">Una sola dashboard per scansioni totali, score medio di conformità, finding aperti e asset monitorati — con il trend delle scansioni recenti sulla stessa schermata.</span>
            </p>
          </div>
          <div class="mx-auto mt-12 max-w-5xl rounded-2xl border border-slate-200 bg-white p-2 shadow-2xl shadow-blue-500/5 ring-1 ring-black/5 dark:border-neutral-800 dark:bg-neutral-900 dark:ring-white/5">
            <div class="flex items-center gap-1.5 px-3 pt-2 pb-3">
              <span class="h-2.5 w-2.5 rounded-full bg-red-400" aria-hidden="true"></span>
              <span class="h-2.5 w-2.5 rounded-full bg-yellow-400" aria-hidden="true"></span>
              <span class="h-2.5 w-2.5 rounded-full bg-green-400" aria-hidden="true"></span>
              <span class="ml-auto text-[10px] font-mono text-slate-400">localhost:8077/dashboard</span>
            </div>
            <img
              :src="withBase('/screenshot.png')"
              alt="NIS2 Platform dashboard"
              width="1208"
              height="683"
              loading="lazy"
              decoding="async"
              class="w-full rounded-lg border border-slate-200 dark:border-neutral-800"
            />
          </div>
        </div>
      </section>

      <!-- How it works -->
      <section
        aria-labelledby="how-heading"
        class="mx-auto max-w-7xl px-4 py-20 sm:px-6 sm:py-24 lg:px-8"
      >
        <div class="mx-auto max-w-2xl text-center">
          <p class="text-sm font-semibold uppercase tracking-wider text-blue-600 dark:text-blue-400">
            <span class="locale-en">How it works</span>
            <span class="locale-it">Come funziona</span>
          </p>
          <h2 id="how-heading" class="mt-3 text-balance text-3xl font-bold tracking-tight sm:text-4xl">
            <span class="locale-en">From clone to first executive report in an afternoon.</span>
            <span class="locale-it">Dal clone al primo report direzionale in un pomeriggio.</span>
          </h2>
        </div>
        <ol class="mx-auto mt-14 grid max-w-5xl gap-8 sm:grid-cols-3">
          <li
            v-for="s in STEPS"
            :key="s.n"
            class="relative flex flex-col rounded-xl border border-slate-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900/40"
          >
            <div class="flex items-center gap-3">
              <span class="font-mono text-xs font-semibold text-blue-600 dark:text-blue-400">{{ s.n }}</span>
              <span class="h-px flex-1 bg-slate-200 dark:bg-neutral-800" aria-hidden="true"></span>
            </div>
            <h3 class="mt-4 text-lg font-semibold tracking-tight">
              <span class="locale-en">{{ s.en.title }}</span>
              <span class="locale-it">{{ s.it.title }}</span>
            </h3>
            <p class="mt-2 flex-1 text-sm text-slate-600 dark:text-slate-400">
              <span class="locale-en">{{ s.en.body }}</span>
              <span class="locale-it">{{ s.it.body }}</span>
            </p>
            <pre v-if="s.showCmd" class="mt-4 overflow-x-auto rounded-md bg-slate-100 p-3 text-xs dark:bg-neutral-800/60"><code class="font-mono text-slate-900 dark:text-slate-100"><span class="text-slate-500">$ </span>git clone … &amp;&amp; make dev</code></pre>
          </li>
        </ol>
      </section>

      <!-- Audiences -->
      <section
        aria-labelledby="audiences-heading"
        class="border-y border-slate-200 bg-slate-50/40 dark:border-neutral-800 dark:bg-neutral-900/40"
      >
        <div class="mx-auto max-w-7xl px-4 py-20 sm:px-6 sm:py-24 lg:px-8">
          <div class="mx-auto max-w-2xl text-center">
            <h2 id="audiences-heading" class="text-balance text-3xl font-bold tracking-tight sm:text-4xl">
              <span class="locale-en">Built with the people who actually use it.</span>
              <span class="locale-it">Costruita con le persone che la usano davvero.</span>
            </h2>
            <p class="mt-4 text-slate-600 dark:text-slate-400">
              <span class="locale-en">One platform that speaks fluently to the boardroom and to the SOC.</span>
              <span class="locale-it">Una piattaforma che parla con scioltezza sia al CdA sia al SOC.</span>
            </p>
          </div>
          <div class="mx-auto mt-14 grid max-w-5xl gap-6 sm:grid-cols-2">
            <div
              v-for="a in AUDIENCES"
              :key="a.en.role"
              class="rounded-xl border border-slate-200 bg-white p-6 dark:border-neutral-800 dark:bg-neutral-900"
            >
              <p class="text-sm font-semibold uppercase tracking-wider text-blue-600 dark:text-blue-400">
                <span class="locale-en">For {{ a.en.role }}</span>
                <span class="locale-it">Per {{ a.it.role }}</span>
              </p>
              <p class="mt-3 text-sm text-slate-600 dark:text-slate-400">
                <span class="locale-en">{{ a.en.body }}</span>
                <span class="locale-it">{{ a.it.body }}</span>
              </p>
            </div>
          </div>
        </div>
      </section>

      <!-- Self-hosted commitment -->
      <section
        aria-labelledby="self-hosted-heading"
        class="mx-auto max-w-7xl px-4 py-20 sm:px-6 sm:py-24 lg:px-8"
      >
        <div class="mx-auto grid max-w-6xl gap-12 lg:grid-cols-2 lg:items-center">
          <div>
            <div class="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-medium text-slate-500 dark:border-neutral-800 dark:bg-neutral-900 dark:text-slate-400">
              <Lock class="h-3 w-3" aria-hidden="true" :stroke-width="2" />
              <span class="locale-en">Designed for on-premise</span>
              <span class="locale-it">Pensato per l'on-premise</span>
            </div>
            <h2 id="self-hosted-heading" class="mt-4 text-balance text-3xl font-bold tracking-tight sm:text-4xl">
              <span class="locale-en">Your scan data never leaves your infrastructure.</span>
              <span class="locale-it">I tuoi dati non lasciano mai la tua infrastruttura.</span>
            </h2>
            <p class="mt-4 text-slate-600 dark:text-slate-400">
              <span class="locale-en">A CISO of an essential entity will not upload their vulnerability data to a third-party SaaS. So we built the platform around the assumption that it won't.</span>
              <span class="locale-it">Un CISO di un soggetto essenziale non caricherà mai i propri dati di vulnerabilità su un SaaS terzo. La piattaforma è costruita partendo da questo presupposto.</span>
            </p>
            <ul class="mt-8 space-y-3">
              <li class="flex items-start gap-3 text-sm">
                <Check class="mt-0.5 h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400" aria-hidden="true" :stroke-width="2.5" />
                <span class="text-slate-600 dark:text-slate-400">
                  <span class="locale-en">Your PostgreSQL, your data — no telemetry, no external calls, no cloud dependencies.</span>
                  <span class="locale-it">Il tuo PostgreSQL, i tuoi dati — nessuna telemetria, nessuna chiamata esterna, nessuna dipendenza cloud.</span>
                </span>
              </li>
              <li class="flex items-start gap-3 text-sm">
                <Check class="mt-0.5 h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400" aria-hidden="true" :stroke-width="2.5" />
                <span class="text-slate-600 dark:text-slate-400">
                  <span class="locale-en">Air-gapped support: Ollama AI copilot runs entirely local. OpenAI is opt-in.</span>
                  <span class="locale-it">Supporto air-gapped: il copilot Ollama gira interamente in locale. OpenAI è opt-in.</span>
                </span>
              </li>
              <li class="flex items-start gap-3 text-sm">
                <Check class="mt-0.5 h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400" aria-hidden="true" :stroke-width="2.5" />
                <span class="text-slate-600 dark:text-slate-400">
                  <span class="locale-en">Postgres FORCE ROW LEVEL SECURITY enforces tenant isolation in the database, not just the app.</span>
                  <span class="locale-it">FORCE ROW LEVEL SECURITY di Postgres garantisce l'isolamento tra tenant nel database, non solo nell'applicazione.</span>
                </span>
              </li>
              <li class="flex items-start gap-3 text-sm">
                <Check class="mt-0.5 h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400" aria-hidden="true" :stroke-width="2.5" />
                <span class="text-slate-600 dark:text-slate-400">
                  <span class="locale-en">AGPL-3.0 — own your fork forever. Commercial dual-licensing available.</span>
                  <span class="locale-it">AGPL-3.0 — il tuo fork è tuo, per sempre. Doppia licenza commerciale disponibile.</span>
                </span>
              </li>
            </ul>
          </div>
          <div class="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm dark:border-neutral-800 dark:bg-neutral-900">
            <p class="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
              <span class="locale-en">Tech stack</span>
              <span class="locale-it">Stack tecnologico</span>
            </p>
            <ul class="mt-4 flex flex-wrap gap-2">
              <li
                v-for="t in STACK"
                :key="t"
                class="rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-medium dark:border-neutral-700 dark:bg-neutral-800/40"
              >
                {{ t }}
              </li>
            </ul>
            <p class="mt-8 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
              <span class="locale-en">Run it</span>
              <span class="locale-it">Avvialo</span>
            </p>
            <pre class="mt-4 overflow-x-auto rounded-lg bg-slate-100 p-4 text-xs leading-relaxed dark:bg-neutral-800/60"><code class="font-mono"><span class="text-slate-500"># <span class="locale-en">60 seconds, one compose file</span><span class="locale-it">60 secondi, un solo file compose</span></span>
<span class="text-slate-500">$</span> git clone https://github.com/fabriziosalmi/nis2-public.git
<span class="text-slate-500">$</span> cd nis2-public
<span class="text-slate-500">$</span> cp .env.example .env
<span class="text-slate-500">$</span> make dev</code></pre>
            <p class="mt-3 text-xs text-slate-500 dark:text-slate-400">
              <span class="locale-en">Production: <code class="font-mono">make prod</code> — Caddy auto-HTTPS, all services healthy-gated.</span>
              <span class="locale-it">Produzione: <code class="font-mono">make prod</code> — Caddy con HTTPS automatico, tutti i servizi vincolati all'healthcheck.</span>
            </p>
          </div>
        </div>
      </section>

      <!-- Final CTA -->
      <section class="border-t border-slate-200 dark:border-neutral-800">
        <div class="mx-auto max-w-7xl px-4 py-24 sm:px-6 lg:px-8">
          <div class="relative overflow-hidden rounded-3xl border border-slate-900/10 bg-gradient-to-br from-slate-900 to-slate-800 p-10 text-center text-white sm:p-16">
            <div
              aria-hidden="true"
              class="pointer-events-none absolute inset-0 -z-10 bg-[radial-gradient(80%_60%_at_50%_0%,rgba(255,255,255,0.15),transparent_70%)]"
            ></div>
            <h2 class="text-balance text-3xl font-bold tracking-tight sm:text-4xl">
              <span class="locale-en">Stop talking about NIS2. Start showing the matrix.</span>
              <span class="locale-it">Smetti di parlare di NIS2. Inizia a mostrare la matrice di conformità.</span>
            </h2>
            <p class="mx-auto mt-4 max-w-xl text-pretty text-white/80">
              <span class="locale-en">Self-host the platform in 60 seconds. AGPL-3.0 — yours, forever. Need a hand? Reach out.</span>
              <span class="locale-it">Self-host della piattaforma in 60 secondi. AGPL-3.0 — tua, per sempre. Serve una mano? Scrivimi.</span>
            </p>
            <div class="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
              <!-- Primary CTA differs from app landing: docs visitor
                   wants the Guide, not /register. -->
              <!-- `!text-slate-900` / `!text-white` overrides the
                   `.docs-home a { color: inherit }` reset; without it
                   these CTAs would render with invisible text on the
                   dark gradient panel. -->
              <a
                :href="withBase('/guide/getting-started')"
                class="inline-flex w-full items-center justify-center gap-2 rounded-md bg-white px-8 py-3 text-sm font-medium !text-slate-900 transition-colors hover:bg-slate-100 sm:w-auto"
              >
                <Terminal class="h-4 w-4" aria-hidden="true" :stroke-width="2" />
                <span class="locale-en">Read the Guide</span>
                <span class="locale-it">Leggi la guida</span>
              </a>
              <a
                href="mailto:fabrizio.salmi@gmail.com"
                class="inline-flex w-full items-center justify-center gap-2 rounded-md border border-white/30 bg-transparent px-8 py-3 text-sm font-medium !text-white transition-colors hover:bg-white/10 sm:w-auto"
              >
                <span class="locale-en">Request Consultation</span>
                <span class="locale-it">Richiedi consulenza</span>
                <ArrowRight class="h-4 w-4" :stroke-width="2" aria-hidden="true" />
              </a>
            </div>
          </div>
        </div>
      </section>

      <!-- Footer -->
      <footer class="border-t border-slate-200 bg-white dark:border-neutral-800 dark:bg-neutral-950">
        <div class="mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8">
          <div class="grid gap-10 sm:grid-cols-2 lg:grid-cols-4">
            <div class="sm:col-span-2">
              <a :href="withBase('/')" class="flex items-center gap-2.5">
                <Logo :size="28" />
                <span class="font-semibold tracking-tight">NIS2 Platform</span>
              </a>
              <p class="mt-4 max-w-md text-sm text-slate-600 dark:text-slate-400">
                <span class="locale-en">Open-source NIS2 continuous posture management. Maintained by
                  <a href="mailto:fabrizio.salmi@gmail.com" class="font-medium text-slate-900 underline-offset-4 hover:underline dark:text-slate-100">Fabrizio Salmi</a>, independent NIS2 consultant.
                </span>
                <span class="locale-it">Posture management continuo NIS2 open-source. Mantenuto da
                  <a href="mailto:fabrizio.salmi@gmail.com" class="font-medium text-slate-900 underline-offset-4 hover:underline dark:text-slate-100">Fabrizio Salmi</a>, consulente NIS2 indipendente.
                </span>
              </p>
            </div>
            <div>
              <h3 class="text-sm font-semibold tracking-tight">
                <span class="locale-en">Project</span>
                <span class="locale-it">Progetto</span>
              </h3>
              <ul class="mt-4 space-y-3">
                <li>
                  <a href="https://github.com/fabriziosalmi/nis2-public" target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1.5 text-sm text-slate-600 transition-colors hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100">
                    <Github class="h-3.5 w-3.5" aria-hidden="true" :stroke-width="2" /> GitHub
                  </a>
                </li>
                <li>
                  <a href="https://github.com/fabriziosalmi/nis2-public#readme" target="_blank" rel="noopener noreferrer" class="text-sm text-slate-600 transition-colors hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100">
                    README
                  </a>
                </li>
                <li>
                  <a href="https://github.com/fabriziosalmi/nis2-public/blob/main/LICENSE" target="_blank" rel="noopener noreferrer" class="text-sm text-slate-600 transition-colors hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100">
                    <span class="locale-en">License (AGPL-3.0)</span>
                    <span class="locale-it">Licenza (AGPL-3.0)</span>
                  </a>
                </li>
                <li>
                  <a href="https://github.com/fabriziosalmi/nis2-public/blob/main/SECURITY.md" target="_blank" rel="noopener noreferrer" class="text-sm text-slate-600 transition-colors hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100">
                    <span class="locale-en">Security policy</span>
                    <span class="locale-it">Policy di sicurezza</span>
                  </a>
                </li>
              </ul>
            </div>
            <div>
              <h3 class="text-sm font-semibold tracking-tight">
                <span class="locale-en">Documentation</span>
                <span class="locale-it">Documentazione</span>
              </h3>
              <ul class="mt-4 space-y-3">
                <li>
                  <a :href="withBase('/guide/getting-started')" class="text-sm text-slate-600 transition-colors hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100">
                    <span class="locale-en">Getting started</span>
                    <span class="locale-it">Per iniziare</span>
                  </a>
                </li>
                <li>
                  <a :href="withBase('/reference/api')" class="text-sm text-slate-600 transition-colors hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100">
                    <span class="locale-en">API reference</span>
                    <span class="locale-it">Riferimento API</span>
                  </a>
                </li>
                <li>
                  <a :href="withBase('/guide/acn-compliance')" class="text-sm text-slate-600 transition-colors hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100">
                    <span class="locale-en">National modules (ACN)</span>
                    <span class="locale-it">Moduli nazionali (ACN)</span>
                  </a>
                </li>
                <li>
                  <a href="mailto:fabrizio.salmi@gmail.com" class="text-sm text-slate-600 transition-colors hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100">
                    <span class="locale-en">Contact</span>
                    <span class="locale-it">Contatti</span>
                  </a>
                </li>
                <!--
                  v2.5.1 legal-review: privacy + terms must be reachable
                  from every page of a commercial site (Art. 13 GDPR +
                  Art. 7-12 D.Lgs 70/2003). The maintainer-operated
                  docs site is one of those pages.
                -->
                <li>
                  <a href="https://github.com/fabriziosalmi/nis2-public/blob/main/docs/privacy.md" target="_blank" rel="noopener noreferrer" class="text-sm text-slate-600 transition-colors hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100">
                    <span class="locale-en">Privacy</span>
                    <span class="locale-it">Privacy</span>
                  </a>
                </li>
                <li>
                  <a href="https://github.com/fabriziosalmi/nis2-public/blob/main/docs/terms.md" target="_blank" rel="noopener noreferrer" class="text-sm text-slate-600 transition-colors hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100">
                    <span class="locale-en">Terms</span>
                    <span class="locale-it">Termini</span>
                  </a>
                </li>
              </ul>
            </div>
          </div>
          <div class="mt-12 flex flex-col items-start gap-4 border-t border-slate-200 pt-8 sm:flex-row sm:items-center sm:justify-between dark:border-neutral-800">
            <p class="text-xs text-slate-500 dark:text-slate-500">
              <span class="locale-en">© 2026 Salmi Fabrizio — VAT IT 03072120995 — Via Sapri 9, 16134 Genova · This is not legal advice.</span>
              <span class="locale-it">© 2026 Salmi Fabrizio — P.IVA IT 03072120995 — Via Sapri 9, 16134 Genova · Questo non è un parere legale.</span>
            </p>
            <div class="flex items-center gap-4 text-xs text-slate-500 dark:text-slate-500">
              <span class="inline-flex items-center gap-1.5">
                <Server class="h-3 w-3" aria-hidden="true" :stroke-width="2" />
                <span class="locale-en">Self-hosted</span>
                <span class="locale-it">Self-hosted</span>
              </span>
              <span class="inline-flex items-center gap-1.5">
                <Globe class="h-3 w-3" aria-hidden="true" :stroke-width="2" />
                <span class="locale-en">5 EU languages</span>
                <span class="locale-it">5 lingue UE</span>
              </span>
              <span class="inline-flex items-center gap-1.5">
                <Code2 class="h-3 w-3" aria-hidden="true" :stroke-width="2" /> AGPL-3.0
              </span>
            </div>
          </div>
        </div>
      </footer>
    </main>
  </div>
</template>

<style scoped>
/* Scope-leak guard: Tailwind utilities used inside <code> child of a
   <pre> sometimes inherit from the VitePress code-block CSS (which
   overrides background/border). Keep our pre/code transparent so the
   bg-slate-100 / dark:bg-neutral-800 wrapper wins. */
.docs-home pre {
  background: inherit;
}
.docs-home pre code {
  background: transparent;
  padding: 0;
  border: 0;
}
</style>
