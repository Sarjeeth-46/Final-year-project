/**
 * Project: SentinAI NetGuard
 * Module: Security Dashboard Hook
 * Description: A custom React Hook that acts as the Presentation Layer Controller.
 *              Manages polling synchronization, state aggregation, and interaction logic
 *              for the Security Operation Center (SOC) Dashboard.
 * License: MIT / Academic Use Only
 */
import { useState, useEffect, useRef } from 'react';
import axios from 'axios';

const API_BASE = 'http://localhost:8000/api';

export const useSecurityDashboard = (isAuthenticated) => {
    // State Containers for Telemetry Data
    const [threats, setThreats] = useState([]);
    const [riskStats, setRiskStats] = useState([]);
    const [metrics, setMetrics] = useState(null);
    const [history, setHistory] = useState([]);
    const [features, setFeatures] = useState([]);
    const [attackTypes, setAttackTypes] = useState([]);
    const [criticalAlerts, setCriticalAlerts] = useState([]);

    // UI Logic State
    const [loading, setLoading] = useState(true);
    const [highRiskCount, setHighRiskCount] = useState(0);
    const [alert, setAlert] = useState(null);

    // Polling Reference to detect new telemetry events
    const lastThreatTimestamp = useRef(null);

    const synchronizeTelemetry = async () => {
        try {
            // Fetch Aggregated Dashboard Summary
            const res = await axios.get(`${API_BASE}/dashboard/summary`);
            const telemetryPayload = res.data;

            // Safe Destructuring with Defaults
            const {
                threats = [],
                risk_summary = [],
                metrics = null,
                history = [],
                features = [],
                attack_types = [],
                critical_alerts = []
            } = telemetryPayload || {};

            setThreats(threats);
            setRiskStats(risk_summary);
            setMetrics(metrics);
            setHistory(history);
            setFeatures(features);
            setAttackTypes(attack_types);
            setCriticalAlerts(critical_alerts);

            // Calculate aggregated risk metric
            const critical = risk_summary.find(s => s.name === 'Critical')?.value || 0;
            const high = risk_summary.find(s => s.name === 'High')?.value || 0;
            setHighRiskCount(critical + high);

            // Real-time Alert Trigger Logic
            if (threats.length > 0) {
                const latestEvent = threats[0];
                if (latestEvent.timestamp !== lastThreatTimestamp.current) {
                    lastThreatTimestamp.current = latestEvent.timestamp;
                    if (latestEvent.risk_score >= 80) {
                        setAlert({
                            type: 'critical',
                            message: `Critical Anomaly Detected: ${latestEvent.predicted_label} from Source ${latestEvent.source_ip}`
                        });
                    }
                }
            }

            setLoading(false);
        } catch (error) {
            console.error("[Dashboard] Telemetry Sync Failure:", error);
            setAlert({ type: 'error', message: "Connection lost. Retrying..." });
        } finally {
            setLoading(false);
        }
    };

    const resolveThreat = async (id) => {
        try {
            await axios.post(`${API_BASE}/threats/${id}/resolve`);
            // Optimistic update
            setThreats(prev => prev.map(t => t.id === id ? { ...t, status: 'Resolved' } : t));
            setCriticalAlerts(prev => prev.filter(t => t.id !== id));
            setAlert({ type: 'success', message: 'Incident marked as resolved.' });
        } catch (err) {
            console.error("Resolution Failed:", err);
            setAlert({ type: 'error', message: 'Failed to resolve threat.' });
        }
    };

    const blockIP = async (id, ip) => {
        try {
            await axios.post(`${API_BASE}/threats/${id}/block`);
            setAlert({ type: 'success', message: `IP ${ip} blocked successfully.` });
        } catch (err) {
            setAlert({ type: 'error', message: 'Block action failed.' });
        }
    };

    useEffect(() => {
        if (!isAuthenticated) return;

        synchronizeTelemetry();

        const interval = setInterval(() => {
            // Optimization: Only poll if the user is proactively looking at the page
            if (document.visibilityState === 'visible') {
                synchronizeTelemetry();
            }
        }, 5000);

        return () => clearInterval(interval);
    }, [isAuthenticated]);

    return {
        threats,
        riskStats,
        metrics,
        history,
        features,
        attackTypes,
        criticalAlerts,
        loading,
        highRiskCount,
        alert,
        setAlert, // Export setter for clearing toasts
        actions: {
            resolveThreat,
            blockIP
        }
    };
};
