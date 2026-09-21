'use client';

import { useEffect, useState } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ScatterChart, Scatter, RadarChart, Radar, PolarGrid,
  PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer, Cell,
  LineChart, Line, LabelList,
} from 'recharts';

interface ChartData {
  experiment_id: string;
  experiment_name: string;
  dataset_version: string;
  dataset_hash: string;
  total_test_cases: number;
  modes_compared: string[];
  charts: {
    detection_accuracy: Array<{ mode: string; accuracy: number; precision: number; recall: number }>;
    hallucination_precision_recall: Array<{ mode: string; precision: number; recall: number; f1: number }>;
    patch_success_rate: Array<{ mode: string; patch_success_rate: number; total_patches: number; validated: number }>;
    regression_rate: Array<{ mode: string; regression_rate: number; regressions: number }>;
    average_confidence: Array<{ mode: string; avg_confidence: number }>;
    confidence_vs_success: Array<{ test_id: string; confidence: number; success: number; mode: string }>;
    baseline_comparison: Array<{ metric: string; STATIC_SCANNER: number; HALLUCISHIELD: number }>;
    validation_time: Array<{ mode: string; avg_validation_time_ms: number }>;
    security_improvement: Array<{ category: string; before_patch: number; after_patch: number }>;
  };
  data_provenance: {
    source: string;
    experiment_id: string;
    records_used: number;
    note: string;
  };
}

const COLORS = ['#06b6d4', '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'];
const SHORT_MODE: Record<string, string> = {
  LLM_ONLY: 'LLM',
  STATIC_SCANNER: 'Static',
  SINGLE_PATCH_LLM: 'Single',
  MULTI_PATCH_LLM: 'Multi',
  MULTI_PATCH_VALIDATION: 'Validated',
  HALLUCISHIELD: 'HShield',
};

const chartStyles: Record<string, React.CSSProperties> = {
  container: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(520px, 1fr))', gap: '24px' },
  card: {
    background: 'var(--bg-card)',
    borderRadius: '12px',
    padding: '24px',
    border: '1px solid var(--border-color)',
  },
  title: { fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' },
  subtitle: { fontSize: '12px', color: 'var(--text-muted)', marginBottom: '16px' },
  provenance: {
    marginTop: '32px',
    padding: '16px',
    background: 'var(--bg-secondary)',
    borderRadius: '8px',
    fontSize: '12px',
    color: 'var(--text-muted)',
    border: '1px solid var(--border-color)',
  },
  loading: {
    display: 'flex', justifyContent: 'center', alignItems: 'center',
    height: '400px', color: 'var(--text-secondary)', fontSize: '18px',
  },
  empty: {
    textAlign: 'center' as const, padding: '60px 20px', color: 'var(--text-secondary)',
  },
};

const tooltipStyle = {
  contentStyle: {
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '8px',
    fontSize: '12px',
    color: 'var(--text-primary)',
  },
  formatter: (value: unknown) => `${value}%`,
};

function ChartCard({ title, subtitle, children }: {
  title: string;
  subtitle: string;
  children: React.ReactNode;
}) {
  return (
    <div style={chartStyles.card}>
      <div style={chartStyles.title}>{title}</div>
      <div style={chartStyles.subtitle}>{subtitle}</div>
      {children}
    </div>
  );
}

function NoExperimentEmpty() {
  return (
    <div style={chartStyles.empty}>
      <h2 style={{ fontSize: '24px', marginBottom: '12px', color: 'var(--text-primary)' }}>
        No Experiment Data Available
      </h2>
      <p style={{ maxWidth: '500px', margin: '0 auto', lineHeight: 1.6 }}>
        Run an experiment first via <code style={{ color: 'var(--accent-cyan)' }}>POST /api/experiments/run</code>{' '}
        to generate real analytics data. All charts are sourced from stored experiment results — no synthetic or demo data is shown.
      </p>
    </div>
  );
}

export function ExperimentAnalytics() {
  const [data, setData] = useState<ChartData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const aiUrl = process.env.NEXT_PUBLIC_AI_ENGINE_URL || 'http://localhost:8000';

    async function fetchData() {
      try {
        const res = await fetch(`${aiUrl}/api/analytics/latest/charts`);
        if (res.status === 404) {
          setError('no_experiment');
          setLoading(false);
          return;
        }
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        setData(json);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unknown error');
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, []);

  if (loading) return <div style={chartStyles.loading}>Loading experiment analytics...</div>;
  if (error === 'no_experiment') return <NoExperimentEmpty />;
  if (error) return <div style={chartStyles.empty}>Error: {error}</div>;
  if (!data) return <NoExperimentEmpty />;

  const { charts, data_provenance, experiment_name, total_test_cases, modes_compared } = data;

  return (
    <div>
      <div style={{ marginBottom: '24px' }}>
        <h2 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)' }}>
          IEEE Research Analytics Dashboard
        </h2>
        <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '4px' }}>
          Experiment: <strong style={{ color: 'var(--accent-cyan)' }}>{experiment_name}</strong> &middot;
          {total_test_cases} test cases &middot;
          {modes_compared.length} modes compared &middot;
          Dataset {data.dataset_version} (hash: {data.dataset_hash})
        </p>
      </div>

      <div style={chartStyles.container}>

        {/* 1. Vulnerability Detection Accuracy */}
        <ChartCard
          title="1. Vulnerability Detection Accuracy"
          subtitle="Percentage of vulnerabilities correctly detected per analysis mode"
        >
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={charts.detection_accuracy} {...tooltipStyle}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="mode" tickFormatter={(v: string) => SHORT_MODE[v] || v} stroke="#9ca3af" fontSize={11} />
              <YAxis domain={[0, 100]} stroke="#9ca3af" fontSize={11} />
              <Tooltip {...tooltipStyle} />
              <Legend />
              <Bar dataKey="accuracy" fill="#06b6d4" name="Accuracy %" radius={[4, 4, 0, 0]} />
              <Bar dataKey="precision" fill="#3b82f6" name="Precision %" radius={[4, 4, 0, 0]} />
              <Bar dataKey="recall" fill="#10b981" name="Recall %" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* 2. Hallucination Detection Precision/Recall */}
        <ChartCard
          title="2. Hallucination Detection Precision / Recall / F1"
          subtitle="Per-mode breakdown of precision, recall, and F1 score"
        >
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={charts.hallucination_precision_recall} {...tooltipStyle}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="mode" tickFormatter={(v: string) => SHORT_MODE[v] || v} stroke="#9ca3af" fontSize={11} />
              <YAxis domain={[0, 100]} stroke="#9ca3af" fontSize={11} />
              <Tooltip {...tooltipStyle} />
              <Legend />
              <Bar dataKey="precision" fill="#3b82f6" name="Precision %" radius={[4, 4, 0, 0]} />
              <Bar dataKey="recall" fill="#10b981" name="Recall %" radius={[4, 4, 0, 0]} />
              <Bar dataKey="f1" fill="#f59e0b" name="F1 %" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* 3. Patch Success Rate */}
        <ChartCard
          title="3. Patch Success Rate"
          subtitle="Percentage of generated patches that successfully remediated the vulnerability"
        >
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={charts.patch_success_rate} {...tooltipStyle}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="mode" tickFormatter={(v: string) => SHORT_MODE[v] || v} stroke="#9ca3af" fontSize={11} />
              <YAxis domain={[0, 100]} stroke="#9ca3af" fontSize={11} />
              <Tooltip {...tooltipStyle} />
              <Legend />
              <Bar dataKey="patch_success_rate" fill="#10b981" name="Success %" radius={[4, 4, 0, 0]}>
                {charts.patch_success_rate.map((entry, index) => (
                  <Cell key={index} fill={entry.mode === 'HALLUCISHIELD' ? '#10b981' : COLORS[index % COLORS.length]} />
                ))}
                <LabelList dataKey="total_patches" position="top" fill="#9ca3af" fontSize={10} />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* 4. Regression Rate */}
        <ChartCard
          title="4. Regression Rate"
          subtitle="Percentage of patches that introduced new vulnerabilities"
        >
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={charts.regression_rate} {...tooltipStyle}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="mode" tickFormatter={(v: string) => SHORT_MODE[v] || v} stroke="#9ca3af" fontSize={11} />
              <YAxis domain={[0, 'auto']} stroke="#9ca3af" fontSize={11} />
              <Tooltip {...tooltipStyle} />
              <Legend />
              <Bar dataKey="regression_rate" name="Regression %">
                {charts.regression_rate.map((entry, index) => (
                  <Cell key={index} fill={entry.regression_rate > 0 ? '#ef4444' : '#10b981'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* 5. Average Confidence */}
        <ChartCard
          title="5. Average Confidence Score"
          subtitle="Mean confidence calibration across all test cases per mode"
        >
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={charts.average_confidence} {...tooltipStyle}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="mode" tickFormatter={(v: string) => SHORT_MODE[v] || v} stroke="#9ca3af" fontSize={11} />
              <YAxis domain={[0, 100]} stroke="#9ca3af" fontSize={11} />
              <Tooltip {...tooltipStyle} />
              <Legend />
              <Bar dataKey="avg_confidence" fill="#8b5cf6" name="Avg Confidence %" radius={[4, 4, 0, 0]}>
                {charts.average_confidence.map((entry, index) => (
                  <Cell key={index} fill={COLORS[index % COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* 6. Actual Patch Success vs Predicted Confidence */}
        <ChartCard
          title="6. Actual Patch Success vs Predicted Confidence"
          subtitle="Scatter plot: x = confidence score, y = success (100) or failure (0), colored by mode"
        >
          <ResponsiveContainer width="100%" height={300}>
            <ScatterChart {...tooltipStyle}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis
                type="number" dataKey="confidence" name="Confidence"
                domain={[0, 100]} stroke="#9ca3af" fontSize={11}
                label={{ value: 'Confidence %', position: 'insideBottom', offset: -5, fill: '#9ca3af', fontSize: 11 }}
              />
              <YAxis
                type="number" dataKey="success" name="Success"
                domain={[0, 100]} stroke="#9ca3af" fontSize={11}
                tickFormatter={(v: number) => v === 100 ? 'Yes' : v === 0 ? 'No' : String(v)}
              />
              <Tooltip
                {...tooltipStyle}
                formatter={(value: unknown, name: unknown) => {
                  const n = String(name);
                  const v = Number(value);
                  return n === 'Success' ? (v === 100 ? 'Yes' : 'No') : `${v}%`;
                }}
                labelFormatter={(label: unknown) => `Confidence: ${label}%`}
              />
              <Legend />
              {modes_compared.map((mode, i) => (
                <Scatter
                  key={mode}
                  name={SHORT_MODE[mode] || mode}
                  data={charts.confidence_vs_success.filter(d => d.mode === mode)}
                  fill={COLORS[i % COLORS.length]}
                />
              ))}
            </ScatterChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* 7. Comparison Between Baseline Systems */}
        <ChartCard
          title="7. Baseline Comparison: Static Scanner vs HalluciShield"
          subtitle="Head-to-head comparison across key metrics"
        >
          {charts.baseline_comparison.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={charts.baseline_comparison} layout="vertical" {...tooltipStyle}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis type="number" domain={[0, 100]} stroke="#9ca3af" fontSize={11} />
                <YAxis type="category" dataKey="metric" width={120} stroke="#9ca3af" fontSize={11} />
                <Tooltip {...tooltipStyle} />
                <Legend />
                <Bar dataKey="STATIC_SCANNER" fill="#f59e0b" name="Static Scanner" radius={[0, 4, 4, 0]} />
                <Bar dataKey="HALLUCISHIELD" fill="#10b981" name="HalluciShield" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <p style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '40px' }}>
              Baseline comparison requires both STATIC_SCANNER and HALLUCISHIELD modes in the experiment.
            </p>
          )}
        </ChartCard>

        {/* 8. Validation Time */}
        <ChartCard
          title="8. Validation Time"
          subtitle="Average time (ms) spent on patch validation per mode"
        >
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={charts.validation_time} {...tooltipStyle}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="mode" tickFormatter={(v: string) => SHORT_MODE[v] || v} stroke="#9ca3af" fontSize={11} />
              <YAxis stroke="#9ca3af" fontSize={11} />
              <Tooltip {...tooltipStyle} formatter={(v: unknown) => `${v} ms`} />
              <Legend />
              <Bar dataKey="avg_validation_time_ms" fill="#f59e0b" name="Avg Time (ms)" radius={[4, 4, 0, 0]}>
                {charts.validation_time.map((entry, index) => (
                  <Cell key={index} fill={COLORS[index % COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* 9. Security Improvement Before vs After Patch */}
        <ChartCard
          title="9. Security Improvement: Before vs After Patch"
          subtitle="Detection rate vs successful remediation rate per vulnerability category (HalluciShield mode)"
        >
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={charts.security_improvement} {...tooltipStyle}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis
                dataKey="category" stroke="#9ca3af" fontSize={10}
                angle={-25} textAnchor="end" height={80}
                tickFormatter={(v: string) => v.replace('_', ' ')}
              />
              <YAxis domain={[0, 100]} stroke="#9ca3af" fontSize={11} />
              <Tooltip {...tooltipStyle} />
              <Legend />
              <Bar dataKey="before_patch" fill="#f59e0b" name="Before Patch %" radius={[4, 4, 0, 0]} />
              <Bar dataKey="after_patch" fill="#10b981" name="After Patch %" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

      </div>

      {/* Data Provenance */}
      <div style={chartStyles.provenance}>
        <strong style={{ color: 'var(--text-secondary)' }}>Data Provenance:</strong>{' '}
        Source = {data_provenance.source} &middot;
        Experiment = {data_provenance.experiment_id} &middot;
        Records = {data_provenance.records_used} &middot;
        {data_provenance.note}
      </div>
    </div>
  );
}
