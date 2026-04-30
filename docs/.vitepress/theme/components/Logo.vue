<!--
  Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
  SPDX-License-Identifier: AGPL-3.0-only
  NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
-->
<script setup lang="ts">
// Vue port of packages/web/src/components/brand/logo.tsx.
// Single source of truth for the gradient stops, so the in-product hero
// and the marketing home read as visually identical.
//
// `useId` is React-only; in Vue we use a simple incrementing module
// counter to keep the gradient `<defs>` id unique per instance —
// otherwise multiple Logo.vue on the same page would collide on the
// first occurrence and the second instance would lose the gradient.
let _id = 0
const gradientId = `nis2-logo-grad-${++_id}`

withDefaults(
  defineProps<{
    size?: number
  }>(),
  { size: 32 }
)
</script>

<template>
  <svg
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 64 64"
    :width="size"
    :height="size"
    fill="none"
    class="shrink-0"
    aria-label="NIS2 Platform"
    role="img"
    focusable="false"
  >
    <defs>
      <linearGradient
        :id="gradientId"
        x1="0"
        y1="0"
        x2="64"
        y2="64"
        gradientUnits="userSpaceOnUse"
      >
        <stop offset="0" stop-color="#0071e3" />
        <stop offset="1" stop-color="#6e40c9" />
      </linearGradient>
    </defs>
    <circle cx="32" cy="32" r="30" :fill="`url(#${gradientId})`" />
    <circle
      cx="32"
      cy="32"
      r="26"
      fill="none"
      stroke="#fff"
      stroke-width="0.6"
      opacity="0.25"
    />
    <!-- Back mark — dimmed echo -->
    <path
      d="M18 32l7 7 13-14"
      stroke="#fff"
      stroke-width="5"
      stroke-linecap="round"
      stroke-linejoin="round"
      fill="none"
      opacity="0.55"
    />
    <!-- Front mark — full opacity -->
    <path
      d="M26 32l7 7 13-14"
      stroke="#fff"
      stroke-width="5"
      stroke-linecap="round"
      stroke-linejoin="round"
      fill="none"
    />
  </svg>
</template>
