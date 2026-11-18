export type Tone = "neutral" | "ok" | "warn" | "danger" | "info";

export function statusTone(status: string): Tone {
  switch (status) {
    case "completed":
    case "deployed":
    case "approved":
    case "verified":
      return "ok";
    case "failed":
    case "rejected":
    case "rolled_back":
    case "refused":
      return "danger";
    case "blocked":
    case "awaiting_approval":
    case "starting":
    case "pending":
      return "warn";
    case "running":
      return "info";
    default:
      return "neutral";
  }
}

export function formatMoment(moment: string): string {
  if (moment === "") {
    return "—";
  }
  const parsed = new Date(moment);
  if (Number.isNaN(parsed.getTime())) {
    return moment;
  }
  return parsed.toLocaleString();
}

export function formatPercent(ratio: number): string {
  return `${(ratio * 100).toFixed(1)}%`;
}
