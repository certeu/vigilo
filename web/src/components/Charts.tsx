import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ACCENT, SEVERITY_COLORS, severityData } from "../lib/severity";

const AXIS = { fontSize: 12, fill: "#606A7B" };

export function Kpi({ label, value, tone }: { label: string; value: number | string; tone?: string }) {
  return (
    <div className="card p-5">
      <div className="text-xs font-medium uppercase tracking-wide text-slate">{label}</div>
      <div
        className="mt-2 font-display text-3xl font-semibold"
        style={tone ? { color: tone } : undefined}
      >
        {value}
      </div>
    </div>
  );
}

export function SeverityDonut({ counts }: { counts: Record<string, number> }) {
  const data = severityData(counts);
  if (data.length === 0) return <Empty />;
  return (
    <div className="w-full overflow-hidden">
    <ResponsiveContainer width="100%" height={240}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" innerRadius={55} outerRadius={90} paddingAngle={2}>
          {data.map((d) => (
            <Cell key={d.key} fill={d.color} />
          ))}
        </Pie>
        <Tooltip formatter={(v: number, n: string) => [`${v} findings`, n]} />
        <Legend iconType="circle" wrapperStyle={{ fontSize: 12 }} />
      </PieChart>
    </ResponsiveContainer>
    </div>
  );
}

export function CategoryBar({
  counts,
  displayNames,
}: {
  counts: Record<string, number>;
  displayNames?: Record<string, string>;
}) {
  const data = Object.entries(counts)
    .map(([k, v]) => ({ name: displayNames?.[k] ?? k, value: v }))
    .sort((a, b) => b.value - a.value);
  if (data.length === 0) return <Empty />;
  return (
    <div className="w-full overflow-hidden">
    <ResponsiveContainer width="100%" height={Math.max(200, data.length * 34)}>
      <BarChart data={data} layout="vertical" margin={{ left: 20, right: 16 }}>
        <CartesianGrid horizontal={false} stroke="#E7E9EE" />
        <XAxis type="number" tick={AXIS} allowDecimals={false} />
        <YAxis type="category" dataKey="name" tick={AXIS} width={150} />
        <Tooltip formatter={(v: number) => [`${v} findings`, "Count"]} cursor={{ fill: "#F2F3F6" }} />
        <Bar dataKey="value" fill={ACCENT} radius={[0, 4, 4, 0]} />
      </BarChart>
    </ResponsiveContainer>
    </div>
  );
}

export interface TimelinePoint {
  label: string;
  total: number;
  critical: number;
  high: number;
}

export function TimelineChart({ data }: { data: TimelinePoint[] }) {
  if (data.length === 0) return <Empty label="No past runs yet." />;
  return (
    <div className="w-full overflow-hidden">
    <ResponsiveContainer width="100%" height={280}>
      <LineChart data={data} margin={{ left: 4, right: 16, top: 8 }}>
        <CartesianGrid stroke="#E7E9EE" />
        <XAxis dataKey="label" tick={AXIS} />
        <YAxis tick={AXIS} allowDecimals={false} />
        <Tooltip />
        <Legend wrapperStyle={{ fontSize: 12 }} />
        <Line type="monotone" dataKey="total" name="Total" stroke={ACCENT} strokeWidth={2} dot={{ r: 3 }} />
        <Line type="monotone" dataKey="critical" name="Critical" stroke={SEVERITY_COLORS.critical} strokeWidth={2} dot={{ r: 3 }} />
        <Line type="monotone" dataKey="high" name="High" stroke={SEVERITY_COLORS.high} strokeWidth={2} dot={{ r: 3 }} />
      </LineChart>
    </ResponsiveContainer>
    </div>
  );
}

function Empty({ label = "No data yet." }: { label?: string }) {
  return <div className="flex h-40 items-center justify-center text-sm text-slate">{label}</div>;
}
