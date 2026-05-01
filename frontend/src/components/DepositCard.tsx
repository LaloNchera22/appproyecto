"use client";

import { useState } from "react";
import { api } from "../lib/api";

interface DepositCardProps {
  eventId: string;
  option: string;
}

interface ParticipateResponse {
  subaddress: string;
}

const GENERIC_ERROR_MESSAGE =
  "Unable to generate deposit address. Please check your connection and try again.";

export default function DepositCard({ eventId, option }: DepositCardProps) {
  const [subaddress, setSubaddress] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [hasError, setHasError] = useState<boolean>(false);

  const handleGenerate = async () => {
    setIsLoading(true);
    setHasError(false);
    const result = await api.post<ParticipateResponse>("/participate", {
      eventId,
      option,
    });
    if (result.success && result.data?.subaddress) {
      setSubaddress(result.data.subaddress);
      setHasError(false);
    } else {
      setSubaddress(null);
      setHasError(true);
    }
    setIsLoading(false);
  };

  const handleClear = () => {
    setSubaddress(null);
    setHasError(false);
  };

  return (
    <div
      style={{
        border: "1px solid #444",
        borderRadius: "4px",
        padding: "1rem",
        margin: "1rem 0",
        fontFamily: "monospace",
      }}
    >
      <div
        role="note"
        style={{
          border: "1px solid #c80",
          background: "#2a1f00",
          color: "#fc0",
          padding: "0.75rem",
          marginBottom: "1rem",
          borderRadius: "4px",
          fontWeight: "bold",
        }}
      >
        <span aria-hidden="true">&#9888;</span> A fixed 1% platform fee will be
        deducted from your total deposit.
      </div>

      <div style={{ marginBottom: "0.75rem" }}>
        <div>
          <strong>Event:</strong> {eventId}
        </div>
        <div>
          <strong>Option:</strong> {option}
        </div>
      </div>

      {subaddress === null ? (
        <button
          type="button"
          onClick={handleGenerate}
          disabled={isLoading}
          style={{
            padding: "0.6rem 1rem",
            border: "1px solid #444",
            background: isLoading ? "#222" : "#111",
            color: "#eee",
            cursor: isLoading ? "not-allowed" : "pointer",
            borderRadius: "4px",
            fontFamily: "monospace",
          }}
        >
          {isLoading ? "Generating address…" : "Generate Deposit Address"}
        </button>
      ) : (
        <div>
          <label
            htmlFor="monero-subaddress"
            style={{ display: "block", marginBottom: "0.25rem" }}
          >
            Monero deposit subaddress:
          </label>
          <input
            id="monero-subaddress"
            type="text"
            value={subaddress}
            readOnly
            onFocus={(e) => e.currentTarget.select()}
            style={{
              width: "100%",
              padding: "0.5rem",
              border: "1px solid #444",
              background: "#000",
              color: "#0f0",
              fontFamily: "monospace",
              boxSizing: "border-box",
            }}
          />
          <button
            type="button"
            onClick={handleClear}
            style={{
              marginTop: "0.75rem",
              padding: "0.5rem 1rem",
              border: "1px solid #444",
              background: "#111",
              color: "#eee",
              cursor: "pointer",
              borderRadius: "4px",
              fontFamily: "monospace",
            }}
          >
            Clear
          </button>
        </div>
      )}

      {hasError ? (
        <div
          role="alert"
          style={{
            marginTop: "0.75rem",
            color: "#a33",
          }}
        >
          {GENERIC_ERROR_MESSAGE}
        </div>
      ) : null}
    </div>
  );
}
