import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { StrengthMeter } from "./StrengthMeter";

describe("StrengthMeter", () => {
  it("renders nothing for an empty password", () => {
    const { container } = render(<StrengthMeter password="" />);
    expect(container.firstChild).toBeNull();
  });

  it("shows a strength label for a non-empty password", () => {
    render(<StrengthMeter password="a" />);
    // "Very weak" for a single char.
    expect(screen.getByText(/very weak/i)).toBeInTheDocument();
  });
});
