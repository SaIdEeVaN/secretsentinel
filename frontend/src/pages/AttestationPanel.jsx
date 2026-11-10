import { useState } from "react";
import { api } from "../api/client.js";
import { ErrorState, Loading } from "../components/States.jsx";
import { KeyValue } from "../components/Widgets.jsx";
import { useAsync } from "../hooks/useAsync.js";

export const DISCLAIMER =
  "An attestation shows who attested to this scan result and that it was not modified. It does not prove the code is secure.";

export default function AttestationPanel({ scanId }) {
  const att = useAsync(() => api.attestation(scanId).catch((e) => (e.code === "NOT_FOUND" ? null : Promise.reject(e))), [scanId]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.createAttestation(scanId);
      att.reload();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card p-4" aria-labelledby="att-h">
      <h2 id="att-h" className="font-semibold">
        Signed scan attestation (optional)
      </h2>
      <p className="mt-1 text-xs text-muted">{DISCLAIMER} Only a digest of non-sensitive scan metadata is ever published.</p>
      {att.loading && !att.data && <Loading />}
      <ErrorState error={att.error || error} />
      {!att.loading && !att.data && !att.error && (
        <button type="button" className="btn btn-ghost mt-3" onClick={create} disabled={busy}>
          {busy ? "Signing…" : "Create signed attestation"}
        </button>
      )}
      {att.data && (
        <div className="mt-3 space-y-3">
          <KeyValue
            items={[
              ["Digest", <span className="mono">{att.data.attestation_digest}</span>],
              ["Signer", <span className="mono">{att.data.signer_address}</span>],
              ["Chain", att.data.chain_id],
              ["Registry", <span className="mono">{att.data.contract_address ?? "not configured"}</span>],
              ["Transaction", <span className="mono">{att.data.transaction_hash ?? "not published (use secretsentinel attest publish)"}</span>],
            ]}
          />
          <details>
            <summary className="cursor-pointer text-sm text-accent">Canonical payload</summary>
            <pre className="mono mt-2 overflow-x-auto rounded-lg border border-line bg-surface-2 p-3 text-xs">
              {JSON.stringify(att.data.payload, null, 2)}
            </pre>
          </details>
        </div>
      )}
    </section>
  );
}
