import type { ReactNode } from "react";
import type { Tone } from "./format";

export function Card({
  title,
  children,
  actions,
}: {
  title?: string;
  children: ReactNode;
  actions?: ReactNode;
}): ReactNode {
  return (
    <section className="card">
      {title !== undefined && (
        <header className="card-head">
          <h2>{title}</h2>
          {actions}
        </header>
      )}
      {children}
    </section>
  );
}

export function Badge({ tone, children }: { tone: Tone; children: ReactNode }): ReactNode {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

export function Fields({ items }: { items: { label: string; value: ReactNode }[] }): ReactNode {
  return (
    <dl className="fields">
      {items.map((item) => (
        <div className="field" key={item.label}>
          <dt>{item.label}</dt>
          <dd>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

/** A bar of a value against its maximum. The value is written in the label. */
export function Bar({
  value,
  max,
  label,
}: {
  value: number;
  max: number;
  label: string;
}): ReactNode {
  const width = 200;
  const height = 10;
  const ratio = max > 0 ? Math.min(1, Math.max(0, value / max)) : 0;
  return (
    <svg
      className="bar"
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label={label}
      preserveAspectRatio="none"
    >
      <rect className="bar-track" x={0} y={0} width={width} height={height} />
      <rect
        className="bar-fill"
        x={0}
        y={0}
        width={Math.round(width * ratio)}
        height={height}
      />
    </svg>
  );
}

/** Text of the engine, shown as it is: never as markup. */
export function TextBlock({ text }: { text: string }): ReactNode {
  return <pre className="text-block">{text}</pre>;
}

export function Notice({
  tone,
  children,
}: {
  tone: Tone;
  children: ReactNode;
}): ReactNode {
  return (
    <p className={`notice notice-${tone}`} role="alert">
      {children}
    </p>
  );
}

export function Loading({ label }: { label: string }): ReactNode {
  return (
    <p className="loading" role="status">
      {label}
    </p>
  );
}

export function Empty({ children }: { children: ReactNode }): ReactNode {
  return <p className="empty">{children}</p>;
}

