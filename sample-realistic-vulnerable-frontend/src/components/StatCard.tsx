interface StatCardProps {
  label: string;
  value: string | number;
  tone?: 'green' | 'blue' | 'orange' | 'red';
}

export default function StatCard({ label, value, tone = 'blue' }: StatCardProps) {
  return (
    <article className={`stat-card stat-${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}
