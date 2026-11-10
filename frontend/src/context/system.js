import { createContext, useContext } from "react";

/** System status shared app-wide (hosted vs local mode, enabled features). */
export const SystemContext = createContext({ status: null, reload: () => {} });

export function useSystem() {
  return useContext(SystemContext);
}

export function localScanningEnabled(status) {
  // Unknown status (still loading): keep local behaviour.
  return status ? Boolean(status.local_scanning_enabled) : true;
}
