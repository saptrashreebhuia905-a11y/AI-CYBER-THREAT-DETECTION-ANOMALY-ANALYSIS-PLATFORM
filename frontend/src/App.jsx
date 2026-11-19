import { useCallback, useEffect, useState } from 'react'
import './App.css'

const TOKEN_KEY = 'sentinel-access-token'
const NAV_ITEMS = [
  ['overview', 'Overview'],
  ['alerts', 'Alerts'],
  ['events', 'Security events'],
  ['ingest', 'Submit event'],
  ['simulator', 'Simulator'],
]

const makeInitialEvent = () => {
  const timestamp = new Date()
  timestamp.setMinutes(timestamp.getMinutes() - timestamp.getTimezoneOffset())
  return {
    timestamp: timestamp.toISOString().slice(0, 16),
    source_ip: '',
    user_id: '',
    endpoint: '/api/login',
    request_rate: '1',
    login_status: 'SUCCESS',
    failed_attempts: '0',
  }
}

async function apiRequest(path, token, options = {}) {
  const headers = new Headers(options.headers || {})
  if (token) headers.set('Authorization', `Bearer ${token}`)
  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }

  const response = await fetch(path, { ...options, headers })
  const body = await response.json().catch(() => null)
  if (!response.ok) {
    throw new Error(body?.detail || `Request failed (${response.status}).`)
  }
  if (body === null) throw new Error('The server returned an invalid response.')
  return body
}

function formatDate(value) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString()
}

function App() {
  const [token, setToken] = useState(() => sessionStorage.getItem(TOKEN_KEY) || '')
  const [user, setUser] = useState(null)
  const [authMode, setAuthMode] = useState('login')
  const [authForm, setAuthForm] = useState({ username: '', password: '' })
  const [page, setPage] = useState('overview')
  const [apiStatus, setApiStatus] = useState('checking')
  const [dashboard, setDashboard] = useState(null)
  const [logs, setLogs] = useState({ items: [], total: 0 })
  const [logsPage, setLogsPage] = useState(0)
  const [alerts, setAlerts] = useState({ items: [], total: 0 })
  const [filters, setFilters] = useState({ search: '', login_status: '', min_risk: '' })
  const [appliedFilters, setAppliedFilters] = useState({})
  const [eventForm, setEventForm] = useState(makeInitialEvent)
  const [notice, setNotice] = useState('')
  const [noticeType, setNoticeType] = useState('')
  const [authBusy, setAuthBusy] = useState(false)
  const [loading, setLoading] = useState(false)
  const [simulatorBusy, setSimulatorBusy] = useState(false)

  const checkHealth = useCallback(async () => {
    try {
      await apiRequest('/api/v1/health')
      setApiStatus('online')
    } catch {
      setApiStatus('offline')
    }
  }, [])

  const loadWorkspace = useCallback(async () => {
    if (!token) return
    setLoading(true)
    try {
      const query = new URLSearchParams({ limit: '50', skip: String(logsPage * 50) })
      Object.entries(appliedFilters).forEach(([key, value]) => {
        if (value) query.set(key, value)
      })
      const [dashboardData, logsData, alertsData, userData] = await Promise.all([
        apiRequest('/api/v1/dashboard', token),
        apiRequest(`/api/v1/logs?${query}`, token),
        apiRequest('/api/v1/alerts?limit=100', token),
        apiRequest('/api/v1/auth/me', token),
      ])
      setDashboard(dashboardData)
      setLogs(logsData)
      setAlerts(alertsData)
      setUser(userData)
      setNotice('')
    } catch (error) {
      setNotice(error.message)
      setNoticeType('error')
      if (error.message.includes('Sign in')) {
        sessionStorage.removeItem(TOKEN_KEY)
        setToken('')
        setUser(null)
      }
    } finally {
      setLoading(false)
    }
  }, [appliedFilters, logsPage, token])

  useEffect(() => {
    const initialCheck = window.setTimeout(() => { checkHealth() }, 0)
    const timer = window.setInterval(checkHealth, 15000)
    return () => {
      window.clearTimeout(initialCheck)
      window.clearInterval(timer)
    }
  }, [checkHealth])

  useEffect(() => {
    const initialLoad = window.setTimeout(() => { loadWorkspace() }, 0)
    const timer = token ? window.setInterval(loadWorkspace, 15000) : undefined
    return () => {
      window.clearTimeout(initialLoad)
      if (timer !== undefined) window.clearInterval(timer)
    }
  }, [loadWorkspace, token])

  function signOut() {
    sessionStorage.removeItem(TOKEN_KEY)
    setToken('')
    setUser(null)
    setDashboard(null)
    setLogs({ items: [], total: 0 })
    setAlerts({ items: [], total: 0 })
    setPage('overview')
    setNotice('')
  }

  async function submitAuth(event) {
    event.preventDefault()
    setAuthBusy(true)
    setNotice('')
    try {
      const result = await apiRequest(`/api/v1/auth/${authMode}`, '', {
        method: 'POST',
        body: JSON.stringify(authForm),
      })
      sessionStorage.setItem(TOKEN_KEY, result.access_token)
      setToken(result.access_token)
      setUser(result.user)
      setAuthForm({ username: '', password: '' })
    } catch (error) {
      setNotice(error.message)
      setNoticeType('error')
    } finally {
      setAuthBusy(false)
    }
  }

  function updateEventField(event) {
    const { name, value } = event.target
    setEventForm((current) => ({ ...current, [name]: value }))
  }

  async function submitEvent(event) {
    event.preventDefault()
    setNotice('')
    try {
      const result = await apiRequest('/api/v1/logs', token, {
        method: 'POST',
        body: JSON.stringify({
          ...eventForm,
          timestamp: new Date(eventForm.timestamp).toISOString(),
          request_rate: Number(eventForm.request_rate),
          failed_attempts: Number(eventForm.failed_attempts),
        }),
      })
      setNotice(
        `Event stored. Risk ${result.risk_score}/100 (${result.severity}). ${
          result.is_alert ? 'An alert was created.' : 'No alert was raised.'
        }`,
      )
      setNoticeType(result.is_alert ? 'warning' : 'success')
      setEventForm(makeInitialEvent())
      await loadWorkspace()
    } catch (error) {
      setNotice(error.message)
      setNoticeType('error')
    }
  }

  async function runScenario(scenario) {
    setSimulatorBusy(true)
    setNotice('')
    try {
      const result = await apiRequest('/api/v1/simulator/run', token, {
        method: 'POST',
        body: JSON.stringify({ scenario, event_count: scenario === 'normal' ? 1 : 3 }),
      })
      setNotice(`Simulation complete: ${result.events_created} synthetic ${scenario} event(s) stored.`)
      setNoticeType('success')
      await loadWorkspace()
    } catch (error) {
      setNotice(error.message)
      setNoticeType('error')
    } finally {
      setSimulatorBusy(false)
    }
  }

  async function updateAlert(alertId, update) {
    await apiRequest(`/api/v1/alerts/${alertId}`, token, {
      method: 'PATCH',
      body: JSON.stringify(update),
    })
    await loadWorkspace()
  }

  if (!token) {
    return (
      <main className="auth-page">
        <section className="auth-card">
          <Brand />
          <p className="eyebrow">SECURITY OPERATIONS PLATFORM</p>
          <h1>{authMode === 'login' ? 'Welcome back' : 'Create your analyst account'}</h1>
          <p className="auth-description">
            {authMode === 'login'
              ? 'Sign in to review events and manage security alerts.'
              : 'Register to start monitoring your security events.'}
          </p>
          <form onSubmit={submitAuth} className="auth-form">
            <label>
              Username
              <input
                autoComplete="username"
                minLength="3"
                maxLength="64"
                name="username"
                onChange={(event) => setAuthForm({ ...authForm, username: event.target.value })}
                required
                value={authForm.username}
              />
            </label>
            <label>
              Password
              <input
                autoComplete={authMode === 'login' ? 'current-password' : 'new-password'}
                minLength={authMode === 'login' ? 1 : 12}
                maxLength="128"
                name="password"
                onChange={(event) => setAuthForm({ ...authForm, password: event.target.value })}
                required
                type="password"
                value={authForm.password}
              />
            </label>
            {notice && <p className={`notice ${noticeType}`} role="alert">{notice}</p>}
            <button disabled={authBusy || apiStatus !== 'online'} type="submit">
              {authBusy ? 'Please wait…' : authMode === 'login' ? 'Sign in' : 'Create account'}
            </button>
          </form>
          <button
            className="text-button"
            onClick={() => {
              setAuthMode(authMode === 'login' ? 'register' : 'login')
              setNotice('')
            }}
            type="button"
          >
            {authMode === 'login' ? 'New here? Create an account' : 'Already registered? Sign in'}
          </button>
          <p className={`auth-backend ${apiStatus}`}>
            <span className="status-dot" />
            {apiStatus === 'checking' ? 'Checking backend and database…' : `Backend and database ${apiStatus}`}
          </p>
        </section>
      </main>
    )
  }

  return (
    <div className="workspace">
      <aside className="sidebar">
        <Brand />
        <p className="side-label">WORKSPACE</p>
        <nav aria-label="Main navigation">
          {NAV_ITEMS.map(([id, label]) => (
            <button
              aria-current={page === id ? 'page' : undefined}
              className={`nav-item ${page === id ? 'selected' : ''}`}
              key={id}
              onClick={() => {
                setPage(id)
                setNotice('')
              }}
              type="button"
            >
              <span className={`nav-icon ${id}`} aria-hidden="true" />
              {label}
              {id === 'alerts' && alerts.total > 0 && <span className="nav-count">{alerts.total}</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="profile">
            <span className="avatar">{user?.username?.slice(0, 1).toUpperCase() || 'A'}</span>
            <span className="profile-copy">
              <strong>{user?.username || 'Analyst'}</strong>
              <small>{user?.role || 'analyst'}</small>
            </span>
          </div>
          <button className="signout-button" onClick={signOut} type="button">Sign out</button>
        </div>
      </aside>

      <main className="main-content">
        <header className="workspace-header">
          <div>
            <span className={`connection ${apiStatus}`}>
              <span className="status-dot" />
              {apiStatus === 'online' ? 'Systems operational' : 'Backend/database offline'}
            </span>
          </div>
          <button className="refresh-button" disabled={loading} onClick={loadWorkspace} type="button">
            {loading ? 'Refreshing…' : 'Refresh'}
          </button>
        </header>

        {notice && <p className={`notice workspace-notice ${noticeType}`} role="status">{notice}</p>}

        {page === 'overview' && (
          <Overview dashboard={dashboard} onNavigate={setPage} />
        )}
        {page === 'alerts' && (
          <AlertsPage alerts={alerts.items} onUpdate={updateAlert} />
        )}
        {page === 'events' && (
          <EventsPage
            filters={filters}
            logs={logs}
            onApply={() => {
              setLogsPage(0)
              setAppliedFilters(filters)
            }}
            onFilterChange={(event) => setFilters({ ...filters, [event.target.name]: event.target.value })}
            onPageChange={setLogsPage}
            page={logsPage}
          />
        )}
        {page === 'ingest' && (
          <IngestPage eventForm={eventForm} onChange={updateEventField} onSubmit={submitEvent} />
        )}
        {page === 'simulator' && (
          <SimulatorPage busy={simulatorBusy} onRun={runScenario} />
        )}
        <footer className="app-footer">Sentinel AI <span>•</span> Security event monitoring</footer>
      </main>
    </div>
  )
}

function Brand() {
  return (
    <a className="brand" href="/" aria-label="Sentinel AI">
      <span className="brand-mark" aria-hidden="true">S</span>
      <span>Sentinel<span className="brand-light">AI</span></span>
    </a>
  )
}

function PageHeading({ eyebrow, title, description, action }) {
  return (
    <div className="page-heading">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        <p className="page-description">{description}</p>
      </div>
      {action}
    </div>
  )
}

function Overview({ dashboard, onNavigate }) {
  const metrics = [
    ['Events collected', dashboard?.total_logs ?? '—', 'Total ingested'],
    ['Open alerts', dashboard?.open_alerts ?? '—', 'Needs review'],
    ['Investigating', dashboard?.investigating_alerts ?? '—', 'Being triaged'],
    ['High risk · 24h', dashboard?.high_risk_last_24h ?? '—', 'Risk score ≥ 40'],
  ]

  return (
    <>
      <PageHeading
        description="Monitor incoming activity and respond to detected anomalies."
        eyebrow="OVERVIEW"
        title="Security dashboard"
        action={<button className="primary-button" onClick={() => onNavigate('ingest')} type="button">＋ Submit event</button>}
      />
      <section className="metric-grid" aria-label="Security metrics">
        {metrics.map(([label, value, caption]) => (
          <article className="metric-card" key={label}>
            <p>{label}</p>
            <strong>{value}</strong>
            <small>{caption}</small>
          </article>
        ))}
      </section>
      <section className="content-card">
        <div className="section-heading">
          <div>
            <h2>Recent alerts</h2>
            <p>Latest events flagged by detection rules or the anomaly model</p>
          </div>
          <button className="link-button" onClick={() => onNavigate('alerts')} type="button">View all alerts →</button>
        </div>
        <AlertTable alerts={dashboard?.recent_alerts || []} compact />
      </section>
      <section className="content-card quick-actions">
        <div className="section-heading">
          <div><h2>Quick actions</h2><p>Explore the platform tools</p></div>
        </div>
        <div className="quick-action-grid">
          <button onClick={() => onNavigate('events')} type="button"><strong>Search events</strong><span>Filter and inspect recent security logs</span></button>
          <button onClick={() => onNavigate('simulator')} type="button"><strong>Run simulator</strong><span>Generate local synthetic test events</span></button>
        </div>
      </section>
    </>
  )
}

function AlertsPage({ alerts, onUpdate }) {
  const [statusFilter, setStatusFilter] = useState('all')
  const visibleAlerts = statusFilter === 'all'
    ? alerts
    : alerts.filter((alert) => alert.alert_status === statusFilter)

  return (
    <>
      <PageHeading
        description="Review detection findings and track response progress."
        eyebrow="TRIAGE"
        title="Security alerts"
        action={
          <select aria-label="Filter alerts by status" className="toolbar-select" onChange={(event) => setStatusFilter(event.target.value)} value={statusFilter}>
            <option value="all">All statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
          </select>
        }
      />
      <section className="content-card">
        <div className="section-heading">
          <div><h2>{visibleAlerts.length} alert{visibleAlerts.length === 1 ? '' : 's'}</h2><p>Maximum 100 most recent alerts loaded</p></div>
        </div>
        <AlertTable alerts={visibleAlerts} onUpdate={onUpdate} />
      </section>
    </>
  )
}

function AlertTable({ alerts, onUpdate, compact = false }) {
  if (!alerts.length) {
    return <div className="empty-state"><span className="empty-icon">✓</span><strong>No alerts to show</strong><p>New detections will appear here.</p></div>
  }

  return (
    <div className="table-scroll">
      <table className="data-table alert-table">
        <thead>
          <tr>
            <th>Severity</th><th>Source / account</th><th>Detection</th><th>Risk</th><th>Status</th>
            {!compact && <th>Response</th>}
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <AlertRow alert={alert} compact={compact} key={alert._id} onUpdate={onUpdate} />
          ))}
        </tbody>
      </table>
    </div>
  )
}

function AlertRow({ alert, compact, onUpdate }) {
  const [statusValue, setStatusValue] = useState(alert.alert_status || 'open')
  const [notes, setNotes] = useState(alert.alert_notes || '')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  async function save() {
    setSaving(true)
    setError('')
    try {
      await onUpdate(alert._id, { status: statusValue, notes, assigned_to: alert.assigned_to })
    } catch (saveError) {
      setError(saveError.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <tr>
      <td><span className={`severity ${alert.severity}`}>{alert.severity}</span></td>
      <td><strong>{alert.source_ip}</strong><small>{alert.user_id} · {formatDate(alert.timestamp)}</small></td>
      <td className="detection-cell">{alert.reasons?.join(', ') || 'Anomaly detected'}</td>
      <td><span className="risk-score">{alert.risk_score}<small>/100</small></span></td>
      <td><span className={`alert-status ${alert.alert_status}`}>{alert.alert_status}</span></td>
      {!compact && (
        <td className="response-cell">
          <select aria-label={`Status for alert ${alert._id}`} onChange={(event) => setStatusValue(event.target.value)} value={statusValue}>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
          </select>
          <input aria-label={`Notes for alert ${alert._id}`} onChange={(event) => setNotes(event.target.value)} placeholder="Add triage notes" value={notes} />
          <button disabled={saving} onClick={save} type="button">{saving ? 'Saving…' : 'Save'}</button>
          {error && <small className="inline-error">{error}</small>}
        </td>
      )}
    </tr>
  )
}

function EventsPage({ filters, logs, onApply, onFilterChange, onPageChange, page }) {
  const pageCount = Math.max(1, Math.ceil(logs.total / 50))

  return (
    <>
      <PageHeading
        description="Search and inspect all ingested security activity."
        eyebrow="EVENTS"
        title="Security events"
      />
      <section className="content-card">
        <form className="filter-toolbar" onSubmit={(event) => { event.preventDefault(); onApply() }}>
          <input name="search" onChange={onFilterChange} placeholder="Search IP, user, endpoint" value={filters.search} />
          <select name="login_status" onChange={onFilterChange} value={filters.login_status}>
            <option value="">All login statuses</option><option value="SUCCESS">Success</option><option value="FAILED">Failed</option>
          </select>
          <select name="min_risk" onChange={onFilterChange} value={filters.min_risk}>
            <option value="">Any risk score</option><option value="40">40 and above</option><option value="60">60 and above</option><option value="80">80 and above</option>
          </select>
          <button className="secondary-button" type="submit">Apply filters</button>
        </form>
        <p className="table-count">
          {logs.total} matching event{logs.total === 1 ? '' : 's'} · page {page + 1} of {pageCount}
        </p>
        <div className="table-scroll">
          <table className="data-table">
            <thead><tr><th>Time</th><th>Source IP</th><th>User</th><th>Endpoint</th><th>Login</th><th>Rate/min</th><th>Risk</th></tr></thead>
            <tbody>
              {logs.items.map((log) => (
                <tr key={log._id}>
                  <td>{formatDate(log.timestamp)}</td><td><strong>{log.source_ip}</strong></td><td>{log.user_id}</td>
                  <td className="endpoint-cell">{log.endpoint}</td><td><span className={`login-state ${log.login_status.toLowerCase()}`}>{log.login_status}</span></td>
                  <td>{log.request_rate}</td><td><span className={`severity ${log.severity}`}>{log.risk_score} · {log.severity}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
          {!logs.items.length && <div className="empty-state"><strong>No matching events</strong><p>Try changing the filters or submit an event.</p></div>}
        </div>
        {logs.total > 50 && (
          <div className="pagination">
            <button disabled={page === 0} onClick={() => onPageChange(page - 1)} type="button">Previous</button>
            <span>Page {page + 1} of {pageCount}</span>
            <button disabled={page + 1 >= pageCount} onClick={() => onPageChange(page + 1)} type="button">Next</button>
          </div>
        )}
      </section>
    </>
  )
}

function IngestPage({ eventForm, onChange, onSubmit }) {
  return (
    <>
      <PageHeading description="Send a validated event through the detection pipeline." eyebrow="INGESTION" title="Submit a security event" />
      <section className="content-card form-card">
        <div className="section-heading">
          <div><h2>Event details</h2><p>Events are scored before being stored in MongoDB.</p></div>
          <span className="api-label">POST /api/v1/logs</span>
        </div>
        <form onSubmit={onSubmit}>
          <div className="form-grid">
            <label>Timestamp<input name="timestamp" onChange={onChange} required type="datetime-local" value={eventForm.timestamp} /></label>
            <label>Source IP<input name="source_ip" onChange={onChange} placeholder="203.0.113.42" required value={eventForm.source_ip} /></label>
            <label>User ID<input name="user_id" onChange={onChange} placeholder="user-001" required value={eventForm.user_id} /></label>
            <label>Endpoint<input name="endpoint" onChange={onChange} required value={eventForm.endpoint} /></label>
            <label>Requests per minute<input min="0" name="request_rate" onChange={onChange} required type="number" value={eventForm.request_rate} /></label>
            <label>Login status<select name="login_status" onChange={onChange} value={eventForm.login_status}><option value="SUCCESS">Success</option><option value="FAILED">Failed</option></select></label>
            <label>Failed attempts<input min="0" name="failed_attempts" onChange={onChange} type="number" value={eventForm.failed_attempts} /></label>
          </div>
          <div className="form-actions"><span>Rule checks and baseline-anomaly scoring run automatically.</span><button className="primary-button" type="submit">Analyze and submit</button></div>
        </form>
      </section>
    </>
  )
}

function SimulatorPage({ busy, onRun }) {
  const scenarios = [
    { key: 'normal', title: 'Normal activity', detail: 'Create a baseline event with typical values.' },
    { key: 'brute_force', title: 'Repeated login failures', detail: 'Create three synthetic failed-login events with elevated failed-attempt counts.' },
    { key: 'high_request_rate', title: 'High request rate', detail: 'Create three synthetic events with a high request-rate value.' },
  ]

  return (
    <>
      <PageHeading description="Generate synthetic records locally to exercise detection and alert triage." eyebrow="TESTING" title="Event simulator" />
      <div className="simulator-warning">
        <strong>Safe, data-only simulation</strong>
        <span>This writes synthetic event records to your own MongoDB. It does not send network traffic to other systems.</span>
      </div>
      <section className="simulator-grid">
        {scenarios.map((scenario) => (
          <article className="simulator-card" key={scenario.key}>
            <span className={`simulator-symbol ${scenario.key}`} aria-hidden="true">◈</span>
            <h2>{scenario.title}</h2>
            <p>{scenario.detail}</p>
            <button className="secondary-button" disabled={busy} onClick={() => onRun(scenario.key)} type="button">
              {busy ? 'Generating…' : 'Generate sample'}
            </button>
          </article>
        ))}
      </section>
    </>
  )
}

export default App
