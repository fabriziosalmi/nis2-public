import { create } from 'zustand'

interface ScanState {
  activeScanId: string | null
  setActiveScan: (id: string | null) => void
}

export const useScanStore = create<ScanState>()((set) => ({
  activeScanId: null,
  setActiveScan: (id) => set({ activeScanId: id }),
}))
