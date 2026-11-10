import { useState } from "react";
import { api } from "../api/client.js";
import { ErrorState } from "../components/States.jsx";
import { Field, PageHeader } from "../components/Widgets.jsx";
import { DISCLAIMER } from "./AttestationPanel.jsx";

export default function Attestations() {
  const [bundle, setBundle] = useState("");
  const [onchain, setOnchain] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const verify = async (e) => {
    e.preventDefault();
    setError(null);
    setResult(null);
    let parsed;
    try {
      parsed = JSON.parse(bundle);
    } catch {
      setError({ message: "The bundle is not valid JSON.", code: "VALIDATION_ERROR" });
      return;
    }
    setBusy(true);
    try {
      setResult(
        await api.verifyAttestation({
          payload: parsed.payload,
          signature: parsed.signature,
          signer_address: parsed.signer_address,
          check_onchain: onchain,
        }),
      );
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeader title="Attestations" subtitle="Verify a signed SecretSentinel scan attestation bundle (optional Sepolia anchoring)." />
      <div className="grid gap-5 lg:grid-cols-2">
        <form className="card space-y-3 p-4" onSubmit={verify} aria-label="Verify attestation">
          <Field label="Attestation bundle JSON" htmlFor="bundle" hint="Produced by `secretsentinel attest create <scan-id> --output bundle.json`.">
            <textarea id="bundle" className="input mono" rows={12} value={bundle} onChange={(e) => setBundle(e.target.value)} required spellCheck={false} />
          </Field>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={onchain} onChange={(e) => setOnchain(e.target.checked)} /> Also check the on-chain registry
          </label>
          <button type="submit" className="btn btn-primary" disabled={busy || !bundle.trim()}>
            {busy ? "Verifying…" : "Verify"}
          </button>
          <ErrorState error={error} />
        </form>
        <section className="card p-4" aria-live="polite" aria-labelledby="vr-h">
          <h2 id="vr-h" className="font-semibold">
            Result
          </h2>
          {!result && <p className="mt-2 text-sm text-muted">Paste a bundle and verify.</p>}
          {result && (
            <>
              <p className={`mt-2 text-lg font-bold ${result.verified ? "text-ok" : "text-critical"}`}>
                <span aria-hidden="true">{result.verified ? "✓ " : "✕ "}</span>
                {result.label}
              </p>
              <ul className="mt-3 space-y-1 text-sm">
                {result.checks.map((c) => (
                  <li key={c.name}>
                    <span className={c.ok ? "text-ok" : "text-critical"}>{c.ok ? "✓" : "✕"}</span> <span className="mono">{c.name}</span> —{" "}
                    <span className="text-muted">{c.detail}</span>
                  </li>
                ))}
              </ul>
              {result.recovered_signer && (
                <p className="mt-3 text-xs">
                  Recovered signer <span className="mono">{result.recovered_signer}</span>
                </p>
              )}
            </>
          )}
          <p className="mt-4 rounded-md border border-line bg-surface-2 p-2 text-xs text-muted">{DISCLAIMER}</p>
        </section>
      </div>
    </>
  );
}
