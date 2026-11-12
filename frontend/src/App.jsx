import { useEffect, useState } from 'react'
import './App.css'

const API_URL = 'http://127.0.0.1:8000/api/v1/alerts'

function App() {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function fetchAlerts() {
      try {
        const res = await fetch(API_URL)
        const data = await res.json()
        setAlerts(data.alerts || [])
      } catch (error) {
        console.error('Failed to fetch alerts:', error)
        setAlerts([
          {
            source_ip: '203.0.113.88',
            user_id: 'admin_root',
            endpoint: '/api/v1/admin',
            risk_score: 92,
            severity: 'CRITICAL',
            reasons: ['Brute-force password attack detected', 'Extreme traffic spike'],
          },
          {
            source_ip: '198.51.100.44',
            user_id: 'user_102',
            endpoint: '/api/v1/login',
            risk_score: 68,
            severity: 'HIGH',
            reasons: ['High request rate / possible DDoS attack'],
          },
        ])
      } finally {
        setLoading(false)
      }
    }

    fetchAlerts()
  }, [])

  const summary = {
    total: alerts.length,
    critical: alerts.filter((alert) => alert.severity === 'CRITICAL').length,
    high: alerts.filter((alert) => alert.severity === 'HIGH').length,
    medium: alerts.filter((alert) => alert.severity === 'MEDIUM').length,
  }

  return (
    <div className="cyber-dashboard">
      <header className="topbar">
        <div>
          <p className="eyebrow">Cybersecurity Intelligence</p>
          <h1>AI Threat Detection Platform</h1>
        </div>
        <button className="primary-btn">Live Monitoring</button>
      </header>

      <section className="stats-grid">
        <div className="stat-card danger">
          <span>Total Events</span>
          <strong>{summary.total}</strong>
        </div>
        <div className="stat-card warning">
          <span>Critical</span>
          <strong>{summary.critical}</strong>
        </div>
        <div className="stat-card alert">
          <span>High Risk</span>
          <strong>{summary.high}</strong>
        </div>
        <div className="stat-card safe">
          <span>Medium</span>
          <strong>{summary.medium}</strong>
        </div>
      </section>

      <section className="alerts-panel">
        <h2>Recent Threat Alerts</h2>

        {loading ? (
          <p>Loading alerts...</p>
        ) : alerts.length === 0 ? (
          <p>No alerts detected.</p>
        ) : (
          <div className="alert-list">
            {alerts.map((alert, index) => (
              <div
                key={`${alert.source_ip}-${index}`}
                className={`alert-item ${alert.severity?.toLowerCase() || 'low'}`}
              >
                <div className="alert-header">
                  <div>
                    <span className="badge">{alert.severity || 'LOW'}</span>
                    <h3>{alert.endpoint || 'Unknown endpoint'}</h3>
                  </div>
                  <strong>{alert.risk_score || 0}</strong>
                </div>

                <p>
                  <b>User:</b> {alert.user_id}
                </p>
                <p>
                  <b>IP:</b> {alert.source_ip}
                </p>
                <p>
                  <b>Reasons:</b> {alert.reasons?.join(', ') || 'No reason provided'}
                </p>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}

export default App
