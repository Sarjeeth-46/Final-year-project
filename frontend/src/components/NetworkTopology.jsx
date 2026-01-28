import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Server, Shield, Router, Database, Monitor, Smartphone, AlertTriangle } from 'lucide-react';

const NetworkTopology = () => {
    const [topology, setTopology] = useState({ nodes: [], links: [] });
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchTopology = async () => {
            try {
                const res = await axios.get('http://localhost:8000/api/network/topology');
                setTopology(res.data);
                setLoading(false);
            } catch (err) {
                console.error("Failed to load topology", err);
            }
        };
        fetchTopology();
    }, []);

    const getNodeIcon = (type) => {
        switch (type) {
            case 'Firewall': return <Shield size={24} color="#38BDF8" />;
            case 'Router': return <Router size={24} color="#D29922" />;
            case 'Switch': return <Server size={24} color="#8B949E" />;
            case 'Database': return <Database size={24} color="#F43F5E" />;
            case 'Server': return <Server size={24} color="#2EA043" />;
            case 'Client': return <Monitor size={24} color="#F0F6FC" />;
            default: return <Smartphone size={24} />;
        }
    };

    const getStatusColor = (status) => {
        if (status === 'Compromised') return '#F43F5E';
        if (status === 'Warning') return '#D29922';
        return '#2EA043'; // Healthy
    };

    if (loading) return <div className="card">Loading Topology...</div>;

    return (
        <div className="card topology-card" style={{ height: '400px', display: 'flex', flexDirection: 'column' }}>
            <h2><Router size={20} /> Network Topology</h2>
            <div style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
                <svg width="100%" height="100%" viewBox="0 0 500 400">
                    <defs>
                        <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="28" refY="3.5" orient="auto">
                            <polygon points="0 0, 10 3.5, 0 7" fill="#30363D" />
                        </marker>
                    </defs>
                    {/* Links */}
                    {topology.links.map((link, i) => {
                        const source = topology.nodes.find(n => n.id === link.source);
                        const target = topology.nodes.find(n => n.id === link.target);
                        if (!source || !target) return null;
                        return (
                            <line
                                key={i}
                                x1={source.x} y1={source.y}
                                x2={target.x} y2={target.y}
                                stroke="#30363D"
                                strokeWidth="2"
                            />
                        );
                    })}

                    {/* Nodes */}
                    {topology.nodes.map((node) => (
                        <foreignObject x={node.x - 25} y={node.y - 25} width="50" height="50" key={node.id}>
                            <div className="topology-node" style={{
                                width: '50px', height: '50px',
                                background: '#151B23',
                                border: `2px solid ${getStatusColor(node.status)}`,
                                borderRadius: '50%',
                                display: 'flex', justifyContent: 'center', alignItems: 'center',
                                boxShadow: node.status === 'Compromised' ? '0 0 15px rgba(244, 63, 94, 0.5)' : 'none',
                                animation: node.status === 'Compromised' ? 'pulse-border 2s infinite' : 'none'
                            }}>
                                {getNodeIcon(node.type)}
                            </div>
                            <div style={{ textAlign: 'center', fontSize: '10px', marginTop: '5px', color: '#8B949E' }}>
                                {node.type}
                            </div>
                        </foreignObject>
                    ))}
                </svg>
            </div>
            {/* Legend/Info Overlay */}
            <div style={{ display: 'flex', gap: '15px', justifyContent: 'center', marginTop: '10px', fontSize: '0.8rem', color: '#8B949E' }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}><div style={{ width: 8, height: 8, borderRadius: '50%', background: '#2EA043' }}></div> Healthy</span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}><div style={{ width: 8, height: 8, borderRadius: '50%', background: '#D29922' }}></div> Warning</span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}><div style={{ width: 8, height: 8, borderRadius: '50%', background: '#F43F5E' }}></div> Compromised</span>
            </div>
        </div>
    );
};

export default NetworkTopology;
