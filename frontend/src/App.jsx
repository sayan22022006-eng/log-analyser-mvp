import { useEffect, useMemo, useRef, useState } from 'react'
import { PieChart,Pie,Cell,Tooltip,ResponsiveContainer,Legend,BarChart,Bar,XAxis,YAxis,CartesianGrid } from 'recharts'
import { Activity, AlertTriangle, ArrowDownToLine, CheckCircle2, ChevronRight, Clock3, FileSearch, FileUp, Filter, History, LoaderCircle, RefreshCw, ShieldCheck, Trash2, UploadCloud, XCircle } from 'lucide-react'
import { deleteScan, exportUrl, getAlerts, getScan, getScans, getDashboard, uploadScan } from './api'

const severityOrder = { High: 0, Medium: 1, Low: 2 }
const fmtDate = (value) => value ? new Date(value).toLocaleString() : '—'
const bytes = (n) => n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1024 / 1024).toFixed(2)} MB`

export default function App() {
  const inputRef = useRef(null)
  const [scans, setScans] = useState([])
  const [dashboard, setDashboard] = useState(null)
  const [active, setActive] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [selectedIp, setSelectedIp] = useState(null)
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [file, setFile] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [filters, setFilters] = useState({ severity: '', rule_id: '', username: '', source_ip: '' })
  const [refreshing, setRefreshing] = useState(false)


async function refreshDashboard() {
  try {
    const data = await getDashboard()
    setDashboard(data)
  } catch (e) {
    setError(e.message)
  }
}


  async function refreshScans(preferredId) {
    setRefreshing(true)
    try {
      const data = await getScans()
      setScans(data)
      const id = preferredId ?? active?.id ?? data[0]?.id
      if (id) await openScan(id)
      else { setActive(null); setAlerts([]); setSelectedAlert(null) }
    } catch (e) { setError(e.message) }
    finally { setRefreshing(false) }
  }

  async function openScan(id) {
    try {
      const [scan, found] = await Promise.all([getScan(id), getAlerts(id, filters)])
      setActive(scan)
      setAlerts(found.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]))
      setSelectedAlert(current => current && found.some(a => a.id === current.id) ? current : (found[0] || null))
      setError('')
    } catch (e) { setError(e.message) }
  }

  
useEffect(() => {
  refreshScans()
  refreshDashboard()
}, [])

  useEffect(() => {
    if (active?.id) getAlerts(active.id, filters).then(data => {
      setAlerts(data.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]))
      setSelectedAlert(current => current && data.some(a => a.id === current.id) ? current : (data[0] || null))
    }).catch(e => setError(e.message))
  }, [filters, active?.id])

  async function runScan(event) {
    event.preventDefault()
    if (!file) { setError('Choose a log file first.'); return }
    setBusy(true); setError(''); setNotice('')
    try {
      const result = await uploadScan(file)
      setFile(null)
      if (inputRef.current) inputRef.current.value = ''
      setNotice(`Analysis completed: ${result.parsed_count} parsed events and ${result.alert_count} alerts.`)
      await refreshScans(result.id)
      await refreshDashboard()
    } catch (e) { setError(e.message) }
    finally { setBusy(false) }
  }

  async function removeScan(id) {
    if (!window.confirm('Delete this scan and all retained alert data? This cannot be undone.')) return
    try {
      await deleteScan(id)
      setNotice(`Scan #${id} deleted.`)
      if (active?.id === id) { setActive(null); setAlerts([]); setSelectedAlert(null) }
      await refreshScans(active?.id === id ? undefined : active?.id)
      await refreshDashboard()
    } catch (e) { setError(e.message) }
  }

  const highCount = active?.severity_counts?.High || 0
  const mediumCount = active?.severity_counts?.Medium || 0
  const lowCount = active?.severity_counts?.Low || 0
  const totalScans = dashboard?.total_scans ?? 0
  const totalEvents = dashboard?.total_events ?? 0
  const totalAlerts = dashboard?.total_alerts ?? 0
  const dashboardHigh = dashboard?.high_alerts ?? 0
  const dashboardMedium = dashboard?.medium_alerts ?? 0
  const dashboardLow = dashboard?.low_alerts ?? 0

  const severityData = [
  { name: 'High', value: dashboardHigh, color: '#ef4444' },
  { name: 'Medium', value: dashboardMedium, color: '#f59e0b' },
  { name: 'Low', value: dashboardLow, color: '#22c55e' },
]

  const ruleCounts = Object.values(
  alerts.reduce((groups, alert) => {
    const key = alert.rule_id

    if (!groups[key]) {
      groups[key] = {
        rule_id: alert.rule_id,
        name: alert.rule_name || alert.rule_id,
        count: 0,
      }
    }

    groups[key].count += 1
    return groups
  }, {})
)
  .sort((a, b) => b.count - a.count)
  .slice(0, 5)


  
  const ipAnalysis = Object.values(
    alerts.reduce((groups, alert) => {
      const rawIp = alert.entities?.source_ip
      const ips = Array.isArray(rawIp) ? rawIp : [rawIp]

      ips.forEach((value) => {
        if (typeof value !== 'string' || !value.trim()) return

        const ip = value.trim()

        if (!groups[ip]) {
          groups[ip] = {
            ip,
            alertCount: 0,
            high: 0,
            medium: 0,
            low: 0,
          }
        }

        groups[ip].alertCount += 1

        const severity = alert.severity?.toLowerCase()
        if (severity === 'high') groups[ip].high += 1
        if (severity === 'medium') groups[ip].medium += 1
        if (severity === 'low') groups[ip].low += 1
      })

      return groups
    }, {})
  ).sort((a, b) => b.alertCount - a.alertCount)


  const parsePercent = active?.total_lines ? Math.round((active.parsed_count / active.total_lines) * 100) : 0
  const currentFilterCount = Object.values(filters).filter(Boolean).length

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-icon"><ShieldCheck size={22}/></div><div><strong>Log Analyser</strong><span>SECURITY WORKSPACE</span></div></div>
      <div className="side-section-label">WORKSPACE</div>
      <button className="nav-item active"><Activity size={17}/> Overview</button>
      <button className="nav-item" onClick={() => document.getElementById('upload-panel')?.scrollIntoView({ behavior: 'smooth' })}><FileUp size={17}/> New analysis</button>
      <button className="nav-item" onClick={() => document.getElementById('history-panel')?.scrollIntoView({ behavior: 'smooth' })}><History size={17}/> Scan history <span className="nav-count">{scans.length}</span></button>
      <div className="sidebar-bottom"><div className="privacy-icon"><ShieldCheck size={17}/></div><strong>Privacy-first MVP</strong><p>Uploads are processed in memory. Raw files are not stored by this application.</p><span className="version">VERSION 1.0.0</span></div>
    </aside>

    <main className="main-content">
      <header className="topbar"><div><div className="eyebrow">APPLICATION SECURITY / LOG REVIEW</div><h1>Analysis overview</h1><p>Investigate suspicious patterns in application logs with evidence-backed rules.</p></div><button className="button button-ghost" onClick={() => {
  refreshScans()
  refreshDashboard()
}} disabled={refreshing}>{refreshing ? <LoaderCircle className="spin" size={16}/> : <RefreshCw size={16}/>} Refresh</button></header>

      {error && <div className="alert-banner error-banner"><XCircle size={18}/><span>{error}</span><button onClick={() => setError('')} aria-label="Dismiss error"><XCircle size={16}/></button></div>}
      {notice && <div className="alert-banner success-banner"><CheckCircle2 size={18}/><span>{notice}</span><button onClick={() => setNotice('')} aria-label="Dismiss message"><XCircle size={16}/></button></div>}

      <section id="upload-panel" className="panel upload-panel">
        <div className="section-heading"><div><div className="eyebrow">START HERE</div><h2>Analyse a log file</h2><p>Upload a supported file to parse events and run detection rules.</p></div><div className="supported-label"><ShieldCheck size={15}/> Server-side validation enabled</div></div>
        <form onSubmit={runScan}>
          <div className={`drop-zone ${file ? 'has-file' : ''}`} onDragOver={e => e.preventDefault()} onDrop={e => { e.preventDefault(); const dropped = e.dataTransfer.files?.[0]; if (dropped) setFile(dropped) }}>
            <input ref={inputRef} type="file" accept=".log,.txt,.json" onChange={e => setFile(e.target.files?.[0] || null)} hidden />
            <div className="upload-icon"><UploadCloud size={25}/></div>
            {file ? <><strong>{file.name}</strong><span>{bytes(file.size)} · Ready to analyse</span><button className="text-button" type="button" onClick={() => { setFile(null); if (inputRef.current) inputRef.current.value = '' }}>Remove file</button></> : <><strong>Drop your log file here</strong><span>or choose a file from your device</span><button className="button button-secondary" type="button" onClick={() => inputRef.current?.click()}><FileUp size={16}/> Choose file</button></>}
            <div className="file-spec">.log · .txt · .json (JSON Lines) <span>•</span> Max 10 MB</div>
          </div>
          <div className="upload-footer"><div className="privacy-note"><ShieldCheck size={16}/><span>Only upload logs you are authorized to analyse. Redaction is applied to common secret patterns.</span></div><button className="button button-primary" type="submit" disabled={busy || !file}>{busy ? <><LoaderCircle size={16} className="spin"/> Analysing…</> : <><FileSearch size={16}/> Run analysis <ChevronRight size={16}/></>}</button></div>
        </form>
      </section>

      <section className="metric-grid">
  <Metric
    icon={<History size={18} />}
    label="Total Scans"
    value={totalScans.toLocaleString()}
    foot="Saved analyses"
  />

  <Metric
    icon={<Activity size={18} />}
    label="Parsed Events"
    value={totalEvents.toLocaleString()}
    foot={`${dashboard?.malformed_events ?? 0} malformed events`}
  />

  <Metric
    icon={<AlertTriangle size={18} />}
    label="Total Alerts"
    value={totalAlerts.toLocaleString()}
    foot={`${dashboardHigh} high-priority alerts`}
  />

  <Metric
    icon={<ShieldCheck size={18} />}
    label="Alert Severity"
    value={`${dashboardHigh} / ${dashboardMedium} / ${dashboardLow}`}
    foot="High / Medium / Low"
  />
</section>

<section className="chart-panel">
  <div className="section-heading">
    <div>
      <div className="eyebrow">SECURITY OVERVIEW</div>
      <h2>Alert Severity Distribution</h2>
    </div>
    <span className="muted">All scans</span>
  </div>

  {totalAlerts === 0 ? (
    <p className="muted">No alerts available to display yet.</p>
  ) : (
    <div style={{ width: '100%', height: 280 }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={severityData}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            outerRadius={90}
            innerRadius={55}
            paddingAngle={3}
          >
            {severityData.map((entry) => (
              <Cell key={entry.name} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </div>
  )}
</section>


<section className="chart-panel">
  <div className="section-heading">
    <div>
      <div className="eyebrow">RULE ANALYTICS</div>
      <h2>Most Frequent Alert Rules</h2>
    </div>
    <span className="muted">Top 5</span>
  </div>

  {ruleCounts.length === 0 ? (
    <p className="muted">
      Select a scan with alerts to view the most frequent rules.
    </p>
  ) : (
    <div style={{ width: '100%', height: 320 }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={ruleCounts}
          layout="vertical"
          margin={{ top: 8, right: 28, left: 16, bottom: 8 }}
        >
          <CartesianGrid
            strokeDasharray="3 3"
            stroke="#263449"
            horizontal={false}
          />
          <XAxis
            type="number"
            allowDecimals={false}
            stroke="#94a3b8"
          />
          <YAxis
            type="category"
            dataKey="name"
            width={190}
            stroke="#94a3b8"
            tick={{ fontSize: 11 }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#101c2e',
              border: '1px solid #334155',
              borderRadius: 8,
            }}
          />
          <Bar
            dataKey="count"
            name="Alert records"
            fill="#60a5fa"
            radius={[0, 5, 5, 0]}
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )}
</section>


<section className="chart-panel">
  <div className="section-heading">
    <div>
      <div className="eyebrow">NETWORK ANALYTICS</div>
      <h2>Suspicious IP Analysis</h2>
    </div>
    <span className="muted">{ipAnalysis.length} IPs</span>
  </div>

  {ipAnalysis.length === 0 ? (
    <p className="muted">
      No source IPs are available in the selected scan's alert entities.
    </p>
  ) : (
    <div style={{ overflowX: 'auto' }}>
      <table className="data-table">
        <thead>
          <tr>
            <th>Source IP</th>
            <th>Total Alerts</th>
            <th>High</th>
            <th>Medium</th>
            <th>Low</th>
          </tr>
        </thead>
        <tbody>
          {ipAnalysis.map((item) => (
            <tr
  key={item.ip}
  onClick={() => setSelectedIp(item.ip)}
  style={{
    cursor: 'pointer',
    backgroundColor: selectedIp === item.ip ? '#1e293b' : 'transparent',
  }}
  title={`Investigate ${item.ip}`}
>
              <td>
  <button
    type="button"
    onClick={() => setSelectedIp(item.ip)}
    style={{
      background: 'none',
      border: 'none',
      color: '#60a5fa',
      cursor: 'pointer',
      padding: 0,
      font: 'inherit',
      textDecoration: 'underline',
    }}
  >
    {item.ip}
  </button>
</td>
              <td>{item.alertCount}</td>
              <td>{item.high}</td>
              <td>{item.medium}</td>
              <td>{item.low}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )}

  {selectedIp && (
    <div style={{ marginTop: 24 }}>
      <div className="section-heading">
        <div>
          <div className="eyebrow">IP INVESTIGATION</div>
          <h3>{selectedIp}</h3>
        </div>
        <button
          type="button"
          onClick={() => setSelectedIp(null)}
        >
          Clear selection
        </button>
      </div>

      {(() => {
        const matchingAlerts = alerts.filter(
          (alert) => alert.entities?.source_ip === selectedIp
        )

const timelineEvents = matchingAlerts
  .flatMap((alert) =>
    (alert.evidence || [])
      .filter((event) => event.source_ip === selectedIp)
      .map((event, index) => ({
        ...event,
        alertId: alert.id,
        alertTitle: alert.title,
        severity: alert.severity,
        timelineKey: `${alert.id}-${event.source_line_number ?? index}`,
      }))
  )
  .filter((event) => {
    if (!event.timestamp) return false
    return !Number.isNaN(Date.parse(event.timestamp))
  })
  .sort(
    (a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp)
  )


        return matchingAlerts.length === 0 ? (
          <p className="muted">
            No matching alerts were found for this IP in the current scan.
          </p>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Rule</th>
                  <th>Alert</th>
                  <th>Event Count</th>
                  <th>Time Range</th>
                </tr>
              </thead>
              <tbody>
                {matchingAlerts.map((alert) => (
                  <tr key={alert.id}>
                    <td>{alert.severity}</td>
                    <td>{alert.rule_name}</td>
                    <td>{alert.title}</td>
                    <td>{alert.event_count}</td>
                    <td>
                      {alert.time_start || alert.time_end
                        ? `${alert.time_start || 'Unknown'} – ${alert.time_end || 'Unknown'}`
                        : 'Unknown'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {matchingAlerts.map((alert) => (
              <div
                key={`evidence-${alert.id}`}
                style={{ marginTop: 16, padding: 16, border: '1px solid #263449', borderRadius: 8 }}
              >
                <h4>{alert.title}</h4>
                <p>{alert.description}</p>
                <p><strong>Reason:</strong> {alert.reason}</p>


<h4>IP Activity Timeline</h4>

{timelineEvents.length === 0 ? (
  <p className="muted">
    No timestamped evidence is available for this IP.
  </p>
) : (
  <div
    style={{
      position: 'relative',
      margin: '16px 0 24px',
      paddingLeft: 24,
      borderLeft: '2px solid #334155',
    }}
  >
    {timelineEvents.map((event) => (
      <div
        key={event.timelineKey}
        style={{
          position: 'relative',
          marginBottom: 20,
          padding: '12px 16px',
          border: '1px solid #263449',
          borderRadius: 8,
          backgroundColor: '#101c2e',
        }}
      >
        <span
          style={{
            position: 'absolute',
            left: -31,
            top: 18,
            width: 12,
            height: 12,
            borderRadius: '50%',
            backgroundColor:
              event.severity === 'High'
                ? '#ef4444'
                : event.severity === 'Medium'
                  ? '#f59e0b'
                  : '#22c55e',
            border: '2px solid #101c2e',
          }}
        />

        <p className="muted">
          {new Date(event.timestamp).toLocaleString()}
        </p>

        <p>
          <strong>{event.event_type || 'Unknown event'}</strong>
          {' · '}
          {event.severity || 'Unknown severity'}
        </p>

        <p><strong>Alert:</strong> {event.alertTitle}</p>
        <p><strong>Username:</strong> {event.username || 'Unknown'}</p>
        <p><strong>Source line:</strong> {event.source_line_number ?? 'Unknown'}</p>
        <p><strong>Message:</strong> {event.message || 'No message provided'}</p>
      </div>
    ))}
  </div>
)}


                <h4>Evidence</h4>
                {alert.evidence?.length ? (
                  alert.evidence
                    .filter((event) => event.source_ip === selectedIp)
                    .map((event, index) => (
                      <div key={`${alert.id}-${index}`} style={{ marginBottom: 12 }}>
                        <p><strong>Timestamp:</strong> {event.timestamp || 'Unknown'}</p>
                        <p><strong>Event type:</strong> {event.event_type || 'Unknown'}</p>
                        <p><strong>Username:</strong> {event.username || 'Unknown'}</p>
                        <p><strong>Source line:</strong> {event.source_line_number ?? 'Unknown'}</p>
                        <p><strong>Message:</strong> {event.message || 'No message provided'}</p>
                      </div>
                    ))
                ) : (
                  <p className="muted">No evidence details available.</p>
                )}

                {alert.recommended_next_steps?.length > 0 && (
                  <>
                    <h4>Recommended Next Steps</h4>
                    <ul>
                      {alert.recommended_next_steps.map((step, index) => (
                        <li key={index}>{step}</li>
                      ))}
                    </ul>
                  </>
                )}
              </div>
            ))}
          </div>
        )
      })()}
    </div>
  )}
</section>



  

      {active ? <>
        <div className="scan-heading"><div><div className="eyebrow">CURRENT SCAN</div><h2>{active.original_filename}</h2><p>Scan #{active.id} <span className="dot">•</span> Completed {fmtDate(active.completed_at)}</p></div><a className="button button-secondary" href={exportUrl(active.id)}><ArrowDownToLine size={16}/> Export CSV</a></div>
        <section className="metric-grid">
          <Metric icon={<FileSearch size={18}/>} label="Parsed events" value={active.parsed_count.toLocaleString()} foot={`${active.total_lines.toLocaleString()} total lines`} />
          <Metric icon={<AlertTriangle size={18}/>} label="Total alerts" value={active.alert_count.toLocaleString()} foot={`${highCount} high priority`} />
          <Metric icon={<CheckCircle2 size={18}/>} label="Parse coverage" value={`${parsePercent}%`} foot={`${active.malformed_count} malformed · ${active.skipped_count} unknown`} />
          <Metric icon={<Clock3 size={18}/>} label="Missing timestamps" value={active.missing_timestamp_count.toLocaleString()} foot="May limit time-window rules" />
        </section>

        <section className="severity-grid">
          <SeverityCard severity="High" count={highCount} description="Prompt human review" />
          <SeverityCard severity="Medium" count={mediumCount} description="Notable pattern detected" />
          <SeverityCard severity="Low" count={lowCount} description="Informational / data quality" />
        </section>

        {active.coverage_notes?.length > 0 && <section className="coverage-panel"><div className="coverage-title"><AlertTriangle size={17}/> Analysis coverage notes</div><ul>{active.coverage_notes.map((note, i) => <li key={i}>{note}</li>)}</ul></section>}

        <section className="panel findings-panel">
          <div className="section-heading"><div><div className="eyebrow">DETECTION RESULTS</div><h2>Findings <span className="inline-count">{alerts.length}</span></h2><p>Each alert includes a rule explanation and representative evidence.</p></div><div className="filter-indicator"><Filter size={15}/> {currentFilterCount ? `${currentFilterCount} filter(s)` : 'All findings'}</div></div>
          <div className="filters">
            <select aria-label="Filter severity" value={filters.severity} onChange={e => setFilters(f => ({ ...f, severity: e.target.value }))}><option value="">All severities</option><option>High</option><option>Medium</option><option>Low</option></select>
            <select aria-label="Filter rule" value={filters.rule_id} onChange={e => setFilters(f => ({ ...f, rule_id: e.target.value }))}><option value="">All rules</option>{['AUTH-001','AUTH-002','AUTH-003','AUTH-004','ACCESS-001','TRAFFIC-001','DATA-001'].map(rule => <option key={rule}>{rule}</option>)}</select>
            <input aria-label="Filter username" placeholder="Username" value={filters.username} onChange={e => setFilters(f => ({ ...f, username: e.target.value }))}/>
            <input aria-label="Filter IP address" placeholder="Source IP" value={filters.source_ip} onChange={e => setFilters(f => ({ ...f, source_ip: e.target.value }))}/>
            {currentFilterCount > 0 && <button className="text-button" onClick={() => setFilters({ severity: '', rule_id: '', username: '', source_ip: '' })}>Clear</button>}
          </div>
          {alerts.length ? <div className="findings-layout">
            <div className="finding-list">{alerts.map(alert => <button className={`finding-row ${selectedAlert?.id === alert.id ? 'selected' : ''}`} key={alert.id} onClick={() => setSelectedAlert(alert)}>
              <span className={`severity-dot ${alert.severity.toLowerCase()}`}></span><span className="finding-main"><strong>{alert.title}</strong><span>{alert.rule_id} <span className="dot">•</span> {alert.event_count} event(s)</span></span><span className={`severity-pill ${alert.severity.toLowerCase()}`}>{alert.severity}</span>
            </button>)}</div>
            {selectedAlert && <AlertDetails alert={selectedAlert}/>}
          </div> : <EmptyState title="No findings match these filters" detail="Try clearing a filter, or analyse a sample log that contains a known detection scenario."/>}
        </section>
      </> : <section className="panel empty-overview"><div className="empty-illustration"><FileSearch size={30}/></div><h2>No scan selected</h2><p>Upload a log file above or select a previous scan from history to inspect its findings.</p></section>}

      <section id="history-panel" className="panel history-panel">
        <div className="section-heading"><div><div className="eyebrow">PAST ANALYSES</div><h2>Scan history</h2><p>Previously analysed files and their retained summaries.</p></div><span className="history-count">{scans.length} scan(s)</span></div>
        {scans.length ? <div className="history-table-wrap"><table><thead><tr><th>FILE</th><th>DATE</th><th>EVENTS</th><th>ALERTS</th><th>STATUS</th><th></th></tr></thead><tbody>{scans.map(scan => <tr key={scan.id} className={active?.id === scan.id ? 'active-history' : ''}><td><button className="filename-button" onClick={() => openScan(scan.id)}><FileSearch size={16}/><span>{scan.original_filename}<small>Scan #{scan.id}</small></span></button></td><td>{fmtDate(scan.created_at)}</td><td>{scan.parsed_count.toLocaleString()}</td><td><span className="table-alert-count">{scan.alert_count}</span></td><td><span className="status-badge"><span></span>{scan.status}</span></td><td><div className="table-actions"><button title="Open scan" aria-label="Open scan" onClick={() => openScan(scan.id)}><ChevronRight size={16}/></button><button title="Delete scan" aria-label="Delete scan" onClick={() => removeScan(scan.id)}><Trash2 size={15}/></button></div></td></tr>)}</tbody></table></div> : <EmptyState title="No scan history yet" detail="Your completed scans will appear here."/>}
      </section>
      <footer className="footer"><span>Log Analyser MVP · Rule engine v1.0.0</span><span>Alerts are signals for investigation, not proof of compromise.</span></footer>
    </main>
  </div>
}

function Metric({ icon, label, value, foot }) {
  return <div className="metric-card"><div className="metric-top"><span>{label}</span><span className="metric-icon">{icon}</span></div><strong>{value}</strong><span className="metric-foot">{foot}</span></div>
}
function SeverityCard({ severity, count, description }) {
  return <div className={`severity-card ${severity.toLowerCase()}-card`}><div><span className={`severity-dot ${severity.toLowerCase()}`}></span><strong>{severity}</strong></div><b>{count}</b><span>{description}</span></div>
}
function AlertDetails({ alert }) {
  return <div className="alert-detail">
    <div className="detail-title-row"><span className={`severity-pill ${alert.severity.toLowerCase()}`}>{alert.severity} severity</span><span className="rule-tag">{alert.rule_id}</span></div>
    <h3>{alert.title}</h3><p className="detail-description">{alert.description}</p>
    <div className="reason-box"><strong>Why this alert triggered</strong><p>{alert.reason}</p></div>
    <div className="detail-stats"><div><span>Matched events</span><strong>{alert.event_count}</strong></div><div><span>Start time</span><strong>{alert.time_start ? new Date(alert.time_start).toLocaleTimeString() : 'Unavailable'}</strong></div><div><span>End time</span><strong>{alert.time_end ? new Date(alert.time_end).toLocaleTimeString() : 'Unavailable'}</strong></div></div>
    <div className="entity-list">{Object.entries(alert.entities || {}).map(([key, value]) => <div key={key}><span>{key.replaceAll('_', ' ')}</span><strong>{String(value)}</strong></div>)}</div>
    <div className="detail-section"><h4>Evidence <span>{alert.evidence?.length || 0} representative record(s)</span></h4>
      {alert.evidence?.length ? <div className="evidence-list">{alert.evidence.map((e, i) => <div className="evidence-item" key={`${e.source_line_number}-${i}`}><span className="line-number">L{e.source_line_number}</span><div><strong>{e.event_type}</strong><p>{e.timestamp || 'No timestamp'}{e.source_ip ? ` · ${e.source_ip}` : ''}{e.username ? ` · ${e.username}` : ''}</p>{e.message && <code>{e.message}</code>}</div></div>)}</div> : <p className="muted">This data-quality alert does not reference a specific event.</p>}
    </div>
    {alert.limitations?.length > 0 && <div className="detail-section"><h4>Limitations</h4><ul>{alert.limitations.map((x, i) => <li key={i}>{x}</li>)}</ul></div>}
    {alert.recommended_next_steps?.length > 0 && <div className="detail-section next-steps"><h4>Recommended investigation</h4><ul>{alert.recommended_next_steps.map((x, i) => <li key={i}>{x}</li>)}</ul></div>}
  </div>
}
function EmptyState({ title, detail }) {
  return <div className="empty-state"><div className="empty-icon"><FileSearch size={22}/></div><strong>{title}</strong><p>{detail}</p></div>
}
