import { useState, useEffect, useRef } from 'react'
import axios from 'axios'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, LineChart, Line } from 'recharts'
import { ShieldAlert, Activity, Server, AlertTriangle, CheckCircle, Target, Zap, Eye, Filter, User, UserCog, Flame, Sun, Moon, LogOut } from 'lucide-react'
import Toast from './components/Toast'
import IncidentModal from './components/IncidentModal'
import ThreatMap from './components/ThreatMap'
import AlertBanner from './components/AlertBanner'
import AttackTypeChart from './components/Charts/AttackTypeChart'
import FeatureImportanceChart from './components/Charts/FeatureImportanceChart'
import NetworkTopology from './components/NetworkTopology'
import Login from './components/Login'
import ThemeToggle from './components/ThemeToggle'
import './index.css'

const COLORS = ['#38BDF8', '#F43F5E', '#D29922', '#2EA043']; // Neon Sky, Neon Rose, Gold, Green

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(localStorage.getItem('auth') === 'true')
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark')

  const [threats, setThreats] = useState([])
  const [riskStats, setRiskStats] = useState([])
  const [metrics, setMetrics] = useState(null)
  const [history, setHistory] = useState([])
  const [features, setFeatures] = useState([])
  const [attackTypes, setAttackTypes] = useState([])
  const [criticalAlerts, setCriticalAlerts] = useState([])
  const [highRiskCount, setHighRiskCount] = useState(0)
  const [loading, setLoading] = useState(true)
  const [alert, setAlert] = useState(null)
  const [selectedThreat, setSelectedThreat] = useState(null)
  const [filterType, setFilterType] = useState('All')
  const [filterRisk, setFilterRisk] = useState('All')
  const [userRole, setUserRole] = useState('SOC Analyst') // Mock Role: SOC Analyst, CISO
  const lastThreatTime = useRef(null)

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('theme', theme)
  }, [theme])

  const toggleTheme = () => {
    setTheme(prev => prev === 'dark' ? 'light' : 'dark')
  }

  const handleLogin = () => {
    setIsAuthenticated(true)
    localStorage.setItem('auth', 'true')
  }

  const handleLogout = () => {
    setIsAuthenticated(false)
    localStorage.removeItem('auth')
  }


  const handleResolve = async (id) => {
    try {
      await axios.post(`http://localhost:8000/api/threats/${id}/resolve`)
      // Update local state
      setThreats(prev => prev.map(t => t.id === id ? { ...t, status: 'Resolved' } : t))
      // Also update critical alerts if present
      setCriticalAlerts(prev => prev.filter(t => t.id !== id))
      setSelectedThreat(null)
      setAlert({ type: 'success', message: 'Incident marked as resolved.' })
    } catch (err) {
      console.error("Failed to resolve threat", err)
    }
  }

  const handleBlockIP = async (id, ip) => {
    try {
      await axios.post(`http://localhost:8000/api/threats/${id}/block`);
      setAlert({ type: 'success', message: `IP ${ip} has been blocked at the firewall.` });
    } catch (err) {
      setAlert({ type: 'error', message: 'Failed to block IP' });
    }
  }

  const fetchData = async () => {
    try {
      // 1. Threat Feed
      const threatsRes = await axios.get('http://localhost:8000/api/threats')
      setThreats(threatsRes.data)

      // 2. Risk Summary (Chart)
      const statsRes = await axios.get('http://localhost:8000/api/threats/risk-summary')
      setRiskStats(statsRes.data)

      // Calculate High Risk Count from summary
      const critical = statsRes.data.find(s => s.name === 'Critical')?.value || 0
      const high = statsRes.data.find(s => s.name === 'High')?.value || 0
      setHighRiskCount(critical + high)

      // 3. ML Metrics
      const metricsRes = await axios.get('http://localhost:8000/api/model/metrics')
      setMetrics(metricsRes.data)

      // 4. Traffic History
      const historyRes = await axios.get('http://localhost:8000/api/stats/history')
      setHistory(historyRes.data)

      // 5. Feature Importance
      const featuresRes = await axios.get('http://localhost:8000/api/model/features')
      setFeatures(featuresRes.data)

      // 6. Attack Types
      const attackTypesRes = await axios.get('http://localhost:8000/api/stats/attack-types')
      setAttackTypes(attackTypesRes.data)

      // 7. Critical Alerts
      const criticalRes = await axios.get('http://localhost:8000/api/alerts/critical')
      setCriticalAlerts(criticalRes.data)

      // Alert Logic
      if (threatsRes.data.length > 0) {
        const latest = threatsRes.data[0];
        // Check if it's a new threat (by timestamp) and is critical
        if (latest.timestamp !== lastThreatTime.current) {
          lastThreatTime.current = latest.timestamp;
          if (latest.risk_score >= 80) {
            setAlert({
              type: 'critical',
              message: `High risk detected: ${latest.predicted_label} from ${latest.source_ip}`
            });
            // Optional: Play sound here
          }
        }
      }

      setLoading(false)
    } catch (error) {
      console.error("Error fetching data", error)
    }
  }

  useEffect(() => {
    if (!isAuthenticated) return;
    fetchData()
    const interval = setInterval(fetchData, 5000)
    return () => clearInterval(interval)
  }, [isAuthenticated])

  if (!isAuthenticated) {
    return <Login onLogin={handleLogin} />
  }

  const getRiskColor = (score) => {
    if (score >= 80) return 'text-red-500' // Critical
    if (score >= 60) return 'text-orange-500' // High
    if (score >= 30) return 'text-yellow-500' // Medium
    return 'text-green-500' // Low
  }

  const getRowClass = (score) => {
    if (score >= 80) return 'critical-row'
    return ''
  }

  // Filtering Logic
  const filteredThreats = threats.filter(t => {
    if (filterType !== 'All' && t.predicted_label !== filterType) return false;
    if (filterRisk !== 'All') {
      const risk = t.risk_score;
      if (filterRisk === 'Critical' && risk < 80) return false;
      if (filterRisk === 'High' && (risk < 60 || risk >= 80)) return false;
      if (filterRisk === 'Medium' && (risk < 30 || risk >= 60)) return false;
      if (filterRisk === 'Low' && risk >= 30) return false;
    }
    return true;
  });

  return (
    <div className="app-container">
      <AlertBanner alerts={criticalAlerts} onResolve={handleResolve} />

      <header className="header">
        <div className="logo">
          <ShieldAlert size={32} color={theme === 'dark' ? "#38BDF8" : "#0969DA"} />
          <h1>Sentin<span style={{ color: 'var(--accent)' }}>AI</span> NetGuard</h1>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
          {/* Theme Toggle */}
          <ThemeToggle theme={theme} toggleTheme={toggleTheme} />

          {/* Role Toggle */}
          <div className="role-toggle" onClick={() => setUserRole(prev => prev === 'SOC Analyst' ? 'CISO' : 'SOC Analyst')}>
            {userRole === 'SOC Analyst' ? <User size={18} /> : <UserCog size={18} />}
            <span>{userRole} View</span>
          </div>

          <div className="status-badge">
            <Activity size={16} />
            <span>System Active</span>
          </div>

          <button onClick={handleLogout} className="action-btn" title="Logout" style={{ color: 'var(--critical)', border: '1px solid var(--critical)' }}>
            <LogOut size={16} />
          </button>
        </div>
      </header>

      {/* KPI Widgets */}
      <div className="kpi-grid">
        <div className="kpi-card">
          <div className="kpi-icon"><Server size={24} color="var(--accent)" /></div>
          <div className="kpi-info">
            <h3>Total Threats</h3>
            <p>{threats.length}</p>
          </div>
        </div>
        <div className="kpi-card">
          <div className="kpi-icon"><AlertTriangle size={24} color="var(--critical)" /></div>
          <div className="kpi-info">
            <h3>High Risk</h3>
            <p>{highRiskCount}</p>
          </div>
        </div>
        <div className="kpi-card">
          <div className="kpi-icon"><CheckCircle size={24} color="var(--success)" /></div>
          <div className="kpi-info">
            <h3>System Health</h3>
            <p>98.5%</p>
          </div>
        </div>
        {userRole === 'SOC Analyst' ? (
          <div className="kpi-card">
            <div className="kpi-icon"><Zap size={24} color="var(--warning)" /></div>
            <div className="kpi-info">
              <h3>Response Time</h3>
              <p>1.2s</p>
            </div>
          </div>
        ) : (
          <div className="kpi-card">
            <div className="kpi-icon"><Target size={24} color="var(--success)" /></div>
            <div className="kpi-info">
              <h3>Model Accuracy</h3>
              <p>{metrics?.accuracy ? (metrics.accuracy * 100).toFixed(0) + '%' : 'N/A'}</p>
            </div>
          </div>
        )}
      </div>

      <main className="dashboard-grid">
        {/* ML Performance & Risk Dist */}
        <section className="card chart-card">
          <h2><Activity size={20} /> Analysis Overview</h2>
          <div className="charts-container">
            {/* Risk Distribution */}
            <div className="chart-wrapper">
              <h4 className="chart-title">Risk Levels</h4>
              <ResponsiveContainer>
                <BarChart data={riskStats}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                  <XAxis dataKey="name" stroke="var(--text-secondary)" fontSize={12} tick={{ fill: 'var(--text-secondary)' }} />
                  <YAxis stroke="var(--text-secondary)" fontSize={12} tick={{ fill: 'var(--text-secondary)' }} />
                  <Tooltip cursor={{ fill: 'transparent' }} contentStyle={{ backgroundColor: 'var(--chart-tooltip-bg)', borderColor: 'var(--chart-tooltip-border)', color: 'var(--chart-tooltip-text)' }} itemStyle={{ color: 'var(--chart-tooltip-text)' }} />
                  <Bar dataKey="value" fill="var(--accent)" name="Count" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* Attack Type Distribution (New) */}
            <AttackTypeChart data={attackTypes} />

            {/* Feature Importance (New) */}
            <div className="chart-wrapper risk-factors-wrapper">
              <FeatureImportanceChart data={features} />
            </div>
          </div>
        </section>

        {/* Global Threat Map & Topology (Split View) */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <ThreatMap theme={theme} />
          <NetworkTopology />
        </div>

        {/* Threat Feed Section */}
        <section className="card feed-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
            <h2><ShieldAlert size={20} /> Threat Drill-Down</h2>
            <div style={{ display: 'flex', gap: '10px' }}>
              <select className="filter-select" value={filterType} onChange={e => setFilterType(e.target.value)}>
                <option value="All">All Types</option>
                <option value="DDoS">DDoS</option>
                <option value="Brute Force">Brute Force</option>
                <option value="Port Scan">Port Scan</option>
                <option value="Normal">Normal</option>
              </select>
              <select className="filter-select" value={filterRisk} onChange={e => setFilterRisk(e.target.value)}>
                <option value="All">All Risks</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>
          </div>

          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Target IP</th>
                  <th>Type</th>
                  <th>Confidence</th>
                  <th>Risk Score</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredThreats.map((t, i) => (
                  <tr key={i} className={getRowClass(t.risk_score)}>
                    <td>
                      <span style={{
                        padding: '2px 8px', borderRadius: '10px', fontSize: '0.75rem', fontWeight: 600,
                        background: t.status === 'Resolved' ? 'rgba(46, 160, 67, 0.2)' : 'rgba(244, 63, 94, 0.2)',
                        color: t.status === 'Resolved' ? '#2EA043' : '#F43F5E'
                      }}>
                        {t.status || 'Active'}
                      </span>
                    </td>
                    <td>{new Date(t.timestamp).toLocaleTimeString()}</td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        {t.source_ip}
                        {t.escalation_flag && (
                          <span title="Repeat Offender: Risk Escalated">
                            <Flame size={14} color="#F43F5E" fill="#F43F5E" />
                          </span>
                        )}
                      </div>
                    </td>
                    <td>{t.dest_ip}</td>
                    <td style={{ fontWeight: 'bold', color: t.predicted_label === 'Normal' ? 'var(--success)' : 'var(--text-primary)' }}>{t.predicted_label}</td>
                    <td>{(t.confidence * 100).toFixed(0)}%</td>
                    <td className={`risk-score ${getRiskColor(t.risk_score)}`}>
                      {t.risk_score} <span style={{ fontSize: '0.7em', opacity: 0.7 }}>
                        {t.risk_score >= 80 ? '(CRITICAL)' : t.risk_score >= 60 ? '(HIGH)' : t.risk_score >= 30 ? '(MED)' : '(LOW)'}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        <button onClick={() => setSelectedThreat(t)} className="action-btn" style={{
                          color: '#38BDF8', borderColor: '#38BDF8'
                        }}>
                          <Eye size={12} /> View
                        </button>
                        {userRole === 'SOC Analyst' && t.status !== 'Resolved' && (
                          <button onClick={() => handleBlockIP(t.id, t.source_ip)} className="action-btn" style={{
                            color: '#F43F5E', borderColor: '#F43F5E'
                          }}>
                            <ShieldAlert size={12} /> Block
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
                {filteredThreats.length === 0 && (
                  <tr><td colSpan="8" style={{ textAlign: 'center', padding: '20px' }}>No threats match filters...</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </main>

      {alert && (
        <Toast
          message={alert.message}
          type={alert.type}
          onClose={() => setAlert(null)}
        />
      )}

      {selectedThreat && (
        <IncidentModal
          threat={selectedThreat}
          onClose={() => setSelectedThreat(null)}
          onResolve={handleResolve}
        />
      )}
    </div>
  )
}

export default App
