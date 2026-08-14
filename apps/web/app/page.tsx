"use client";

import { useEffect, useState } from "react";

type HealthState = "checking" | "ready" | "not_ready";

interface HealthResponse {
  service: string;
  status: "ready" | "not_ready";
  components?: Record<string, { status: "up" | "down" }>;
}

const authApiUrl = process.env.NEXT_PUBLIC_AUTH_API_URL ?? "http://localhost:8000";

export default function HomePage() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [state, setState] = useState<HealthState>("checking");

  useEffect(() => {
    const controller = new AbortController();

    async function loadHealth() {
      try {
        const response = await fetch(`${authApiUrl}/health/ready`, {
          cache: "no-store",
          signal: controller.signal,
        });
        const payload = (await response.json()) as HealthResponse;
        setHealth(payload);
        setState(response.ok ? "ready" : "not_ready");
      } catch (error) {
        if (!(error instanceof DOMException && error.name === "AbortError")) {
          setState("not_ready");
        }
      }
    }

    void loadHealth();
    return () => controller.abort();
  }, []);

  return (
    <main>
      <section className="hero" aria-labelledby="page-title">
        <span className="eyebrow">Vittavaan Auth-Core</span>
        <h1 id="page-title">Project foundation</h1>
        <p>
          This page confirms that the website can communicate with the authentication backend and
          its local services before account features are added.
        </p>
      </section>

      <section className="status-panel" aria-live="polite">
        <div className="status-heading">
          <div>
            <span className="eyebrow">Milestone 1</span>
            <h2>System status</h2>
          </div>
          <span className={`badge badge-${state}`}>
            {state === "checking" ? "Checking" : state === "ready" ? "Connected" : "Not ready"}
          </span>
        </div>

        <div className="status-grid">
          <StatusCard label="Authentication API" status={state === "ready" ? "up" : state} />
          <StatusCard label="PostgreSQL" status={health?.components?.postgresql.status ?? state} />
          <StatusCard label="Redis" status={health?.components?.redis.status ?? state} />
        </div>

        <p className="note">
          No login or customer information is being processed yet. This is only the development
          foundation.
        </p>
      </section>
    </main>
  );
}

function StatusCard({ label, status }: { label: string; status: string }) {
  const available = status === "up" || status === "ready";
  const description =
    status === "checking" ? "Checking connection" : available ? "Available" : "Unavailable";

  return (
    <article className="status-card">
      <span className={`status-dot ${available ? "status-dot-up" : ""}`} aria-hidden="true" />
      <div>
        <h3>{label}</h3>
        <p>{description}</p>
      </div>
    </article>
  );
}
