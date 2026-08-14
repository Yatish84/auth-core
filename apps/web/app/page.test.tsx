import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import HomePage from "./page";

describe("HomePage", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows connected services when the API is ready", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          service: "auth-core",
          status: "ready",
          components: {
            postgresql: { status: "up" },
            redis: { status: "up" },
          },
        }),
        { status: 200 },
      ),
    );

    render(<HomePage />);

    expect(await screen.findByText("Connected")).toBeInTheDocument();
    expect(screen.getByText("PostgreSQL")).toBeInTheDocument();
    expect(screen.getByText("Redis")).toBeInTheDocument();
  });
});
