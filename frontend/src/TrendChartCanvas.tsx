import {
  CartesianGrid,
  Line,
  LineChart as RechartsLineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

export type TrendPoint = {
  date: string;
  incidents: number;
  alerts: number;
};

function formatTrendTick(value: string) {
  return value.slice(5);
}

export default function TrendChartCanvas({
  points,
  maxValue,
  yTicks,
}: {
  points: TrendPoint[];
  maxValue: number;
  yTicks?: number[];
}) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <RechartsLineChart data={points} margin={{ top: 10, right: 16, bottom: 4, left: 0 }}>
        <CartesianGrid stroke="#e5e7eb" vertical={false} />
        <XAxis
          dataKey="date"
          axisLine={false}
          tickLine={false}
          tickFormatter={formatTrendTick}
          interval="preserveStartEnd"
          minTickGap={18}
        />
        <YAxis
          allowDecimals={false}
          axisLine={false}
          tickLine={false}
          ticks={yTicks}
          width={30}
          domain={[0, maxValue]}
        />
        <Tooltip
          contentStyle={{
            border: '1px solid #e5e7eb',
            borderRadius: '0.45rem',
            boxShadow: '0 14px 30px rgba(16, 24, 40, 0.12)',
          }}
          cursor={{ stroke: '#94a3b8', strokeDasharray: '4 4' }}
          labelFormatter={(label) => `Date ${label}`}
        />
        <Line
          type="monotone"
          dataKey="incidents"
          name="Incidents"
          stroke="#4b7f00"
          strokeWidth={3}
          dot={{ r: 4, strokeWidth: 2, fill: '#4b7f00', stroke: '#ffffff' }}
          activeDot={{ r: 6, strokeWidth: 2, fill: '#4b7f00', stroke: '#ffffff' }}
          isAnimationActive={false}
        />
        <Line
          type="monotone"
          dataKey="alerts"
          name="Alerts"
          stroke="#f59e0b"
          strokeWidth={3}
          dot={{ r: 4, strokeWidth: 2, fill: '#f59e0b', stroke: '#ffffff' }}
          activeDot={{ r: 6, strokeWidth: 2, fill: '#f59e0b', stroke: '#ffffff' }}
          isAnimationActive={false}
        />
      </RechartsLineChart>
    </ResponsiveContainer>
  );
}
