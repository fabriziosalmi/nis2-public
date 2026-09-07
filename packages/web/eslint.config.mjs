// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
//
// The web package had no linting at all. `package.json` declared
// `"lint": "next lint"`, which Next.js 16 removed, so the script errored — and
// CI never ran it, so nobody found out. 12,500 lines of TypeScript were checked
// only by `tsc`, which says nothing about unused state, missing hook
// dependencies, or an <a> where a <Link> belongs.
//
// eslint-config-next 16 ships native flat configs, so no FlatCompat shim.
//
// Deliberately not a maximal rule set. A first lint run emitting hundreds of
// findings gets suppressed wholesale, and the gate is then worse than none. This
// takes the Next.js recommended rules — correctness and accessibility, the ones
// that catch real defects — and softens only what would otherwise arrive as a
// wall of pre-existing noise.

import nextCoreWebVitals from "eslint-config-next/core-web-vitals"
import nextTypeScript from "eslint-config-next/typescript"

export default [
  {
    ignores: [".next/**", "node_modules/**", "next-env.d.ts", "**/*.tsbuildinfo"],
  },
  ...nextCoreWebVitals,
  ...nextTypeScript,
  {
    rules: {
      // `any` appears ~147 times, most of it at the untyped API boundary.
      // Erroring today would mean a blanket disable; as a warning it stays
      // visible and shrinks. The real fix is generating types from the OpenAPI
      // schema FastAPI already publishes.
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrorsIgnorePattern: "^_" },
      ],

      // React Compiler-era rules, kept visible but not blocking.
      //
      // These flag the standard SSR-safe idiom this app is built on: read
      // localStorage or a persisted store after mount and setState, because the
      // value does not exist during the server render. That is the theme
      // toggle, the legal-disclaimer modal, the auth-store hydration flag and
      // the controlled dialogs — eleven sites, all deliberate.
      //
      // The advice behind them is sound and the eventual answer is
      // useSyncExternalStore. Turning eleven pre-existing patterns red on the
      // day linting is introduced would mean a blanket disable, and a rule
      // disabled wholesale is worse than one that warns: nobody reads it again.
      // They stay as warnings so new occurrences are visible and the count can
      // be driven down deliberately.
      "react-hooks/set-state-in-effect": "warn",
      "react-hooks/purity": "warn",
      "react-hooks/immutability": "warn",
    },
  },
]
