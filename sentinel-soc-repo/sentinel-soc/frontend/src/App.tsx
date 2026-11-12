import React, { useEffect, useState } from 'react';
import { socApi } from './services/api';

const NAV_ITEMS = [
  { id: 'overview', label: '1. Overview' },
  { id: 'live', label: '2. Live Monitoring' },
  { id: 'explorer', label: '3. Log Explorer' },
  { id: 'detection', label: '4. Threat Detection' },
  { id: 'alerts', label: '5. Security Alerts' },
  { id: 'incidents', label: '6. Incident Management' },
  { id: 'intel', label: '7. Threat Intelligence' },
  { id: 'reports', label: '8. Reports & Analytics' },
  { id: 'rules', label: '9. Detection Rules' },
  { id: 'settings', label: '10. Settings' },
  { id: 'about', label: '11. About Developer' },
];

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [overview, setOverview] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const refreshOverview = async () => {
    setLoading(true);
    try {
      const data = await socApi.getOverview();
      setOverview(data);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refreshOverview();
  }, []);

  return (
    <div className="min-h-screen flex bg-[#070b14] text-slate-100">
      <aside className="w-64 bg-[#0f172a] border-r border-slate-800 flex flex-col justify-between">
        <div>
          <div className="p-5 border-b border-slate-800">
            <h1 className="text-lg font-bold tracking-wider text-cyan-400">SENTINEL SOC</h1>
            <p className="text-xs text-slate-400">Mini SIEM & Threat Detection</p>
          </div>
          <nav className="p-3 space-y-1">
            {NAV_ITEMS.map((item) => (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full text-left px-3 py-2.5 rounded-lg text-sm font-medium transition ${
                  activeTab === item.id
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                    : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
                }`}
              >
                {item.label}
              </button>
            ))}
          </nav>
        </div>
        <div className="p-4 border-t border-slate-800 text-xs text-slate-400">
          <p className="font-semibold text-slate-200">Wasif Karim</p>
          <p>DU PMICS — 7th Batch</p>
          <p>Daffodil International University</p>
          <div className="mt-2 flex gap-2">
            <a href="mailto:wasifkarim.work@gmail.com" className="text-cyan-400 hover:underline">Email</a>
            <span>•</span>
            <a href="https://wa.me/8801783734911" target="_blank" rel="noreferrer" className="text-emerald-400 hover:underline">WhatsApp</a>
          </div>
        </div>
      </aside>
      <main className="flex-1 flex flex-col">
        <header className="h-16 border-b border-slate-800 bg-[#0f172a]/80 px-6 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-sm text-slate-300">System Healthy • Timezone: Asia/Dhaka (UTC+06:00)</span>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => socApi.loadSampleData().then(refreshOverview)}
              className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white"
            >
              Load Sample Telemetry
            </button>
          </div>
        </header>
        <div className="p-6 flex-1 overflow-y-auto">
          {loading && <p className="text-sm text-cyan-400">Refreshing SOC telemetry...</p>}
          {overview && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              <div className="p-4 rounded-xl bg-[#0f172a] border border-slate-800">
                <p className="text-xs text-slate-400">Total Events</p>
                <p className="text-2xl font-bold text-white">{overview.kpis.total_events}</p>
              </div>
              <div className="p-4 rounded-xl bg-[#0f172a] border border-slate-800">
                <p className="text-xs text-slate-400">Critical Alerts</p>
                <p className="text-2xl font-bold text-rose-400">{overview.kpis.critical_alerts}</p>
              </div>
              <div className="p-4 rounded-xl bg-[#0f172a] border border-slate-800">
                <p className="text-xs text-slate-400">High Severity Alerts</p>
                <p className="text-2xl font-bold text-orange-400">{overview.kpis.high_alerts}</p>
              </div>
              <div className="p-4 rounded-xl bg-[#0f172a] border border-slate-800">
                <p className="text-xs text-slate-400">Active Incidents</p>
                <p className="text-2xl font-bold text-cyan-400">{overview.kpis.active_incidents}</p>
              </div>
            </div>
          )}
        </div>
        <footer className="px-6 py-3 border-t border-slate-800 text-xs text-slate-400 flex justify-between">
          <span>SENTINEL SOC — Mini SOC Log Analyzer & Threat Detection Platform</span>
          <span>Designed and Developed by Wasif Karim (<a href="mailto:wasifkarim.work@gmail.com" className="text-cyan-400">wasifkarim.work@gmail.com</a> | <a href="https://wa.me/8801783734911" className="text-emerald-400">+8801783734911</a>)</span>
        </footer>
      </main>
    </div>
  );
}
