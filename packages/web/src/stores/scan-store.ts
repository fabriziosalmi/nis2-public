// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import { create } from 'zustand'

interface ScanState {
  activeScanId: string | null
  setActiveScan: (id: string | null) => void
}

export const useScanStore = create<ScanState>()((set) => ({
  activeScanId: null,
  setActiveScan: (id) => set({ activeScanId: id }),
}))
