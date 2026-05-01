"use client";

import { useEffect, useState } from "react";
import { api } from "../lib/api";

interface EventOption {
  id: string;
  label: string;
}

interface EventItem {
  id: string;
  title: string;
  description?: string;
  options: EventOption[];
}

const GENERIC_ERROR_MESSAGE =
  "Unable to load events. Please check your connection and refresh.";

export default function EventList() {
  const [events, setEvents] = useState<EventItem[] | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [hasError, setHasError] = useState<boolean>(false);

  useEffect(() => {
    let cancelled = false;

    const loadEvents = async () => {
      const result = await api.get<EventItem[]>("/events");
      if (cancelled) {
        return;
      }
      if (result.success) {
        setEvents(result.data);
        setHasError(false);
      } else {
        setEvents(null);
        setHasError(true);
      }
      setIsLoading(false);
    };

    void loadEvents();

    return () => {
      cancelled = true;
    };
  }, []);

  if (isLoading) {
    return (
      <div
        role="status"
        aria-live="polite"
        style={{
          padding: "1rem",
          border: "1px solid #444",
          borderRadius: "4px",
          margin: "1rem 0",
          fontFamily: "monospace",
        }}
      >
        <span aria-hidden="true">&#9679;</span> Loading events over Tor. This
        may take a moment&hellip;
      </div>
    );
  }

  if (hasError) {
    return (
      <div
        role="alert"
        style={{
          padding: "1rem",
          border: "1px solid #a33",
          borderRadius: "4px",
          margin: "1rem 0",
          color: "#a33",
          fontFamily: "monospace",
        }}
      >
        {GENERIC_ERROR_MESSAGE}
      </div>
    );
  }

  if (!events || events.length === 0) {
    return (
      <div
        style={{
          padding: "1rem",
          margin: "1rem 0",
          fontFamily: "monospace",
        }}
      >
        No active events at this time.
      </div>
    );
  }

  return (
    <ul
      style={{
        listStyle: "none",
        padding: 0,
        margin: 0,
        fontFamily: "monospace",
      }}
    >
      {events.map((event) => (
        <li
          key={event.id}
          style={{
            border: "1px solid #444",
            borderRadius: "4px",
            padding: "1rem",
            marginBottom: "1rem",
          }}
        >
          <h3 style={{ margin: "0 0 0.5rem 0" }}>{event.title}</h3>
          {event.description ? (
            <p style={{ margin: "0 0 0.75rem 0" }}>{event.description}</p>
          ) : null}
          <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
            {event.options.map((option) => (
              <li
                key={option.id}
                style={{
                  padding: "0.25rem 0",
                  borderTop: "1px dashed #333",
                }}
              >
                <span aria-hidden="true">&raquo;</span> {option.label}
              </li>
            ))}
          </ul>
        </li>
      ))}
    </ul>
  );
}
