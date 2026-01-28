"""
Topology Service Layer
----------------------
Manages the generation of network graph structures and dynamicaly updates 
node states based on active threat intelligence.
"""
from typing import Dict, List, Any
from backend.core.database import db

class TopologyService:
    """Service for Network Graph generation."""

    # Static definition of the network layout (simulated asset map)
    # in a real system, this would come from an Asset Inventory DB.
    STATIC_NODES = [
        {"id": "firewall-1", "type": "Firewall", "ip": "192.168.1.1", "status": "Healthy", "x": 100, "y": 50},
        {"id": "router-core", "type": "Router", "ip": "10.0.0.1", "status": "Healthy", "x": 250, "y": 50},
        {"id": "switch-main", "type": "Switch", "ip": "10.0.0.2", "status": "Healthy", "x": 250, "y": 150},
        {"id": "server-db", "type": "Database", "ip": "10.0.0.5", "status": "Healthy", "x": 150, "y": 250},
        {"id": "server-app", "type": "Server", "ip": "10.0.0.10", "status": "Healthy", "x": 350, "y": 250},
        {"id": "workstation-1", "type": "Client", "ip": "10.0.0.15", "status": "Healthy", "x": 100, "y": 350},
        {"id": "workstation-2", "type": "Client", "ip": "10.0.0.16", "status": "Healthy", "x": 250, "y": 350},
        {"id": "workstation-3", "type": "Client", "ip": "10.0.0.17", "status": "Healthy", "x": 400, "y": 350},
    ]

    STATIC_LINKS = [
        {"source": "firewall-1", "target": "router-core"},
        {"source": "router-core", "target": "switch-main"},
        {"source": "switch-main", "target": "server-db"},
        {"source": "switch-main", "target": "server-app"},
        {"source": "switch-main", "target": "workstation-1"},
        {"source": "switch-main", "target": "workstation-2"},
        {"source": "switch-main", "target": "workstation-3"},
    ]

    @classmethod
    def get_topology_status(cls) -> Dict[str, Any]:
        """
        Returns the network topology with dynamic status updates derived from
        active threats targeting specific node IPs.
        """
        # Fetch active threats to map against nodes
        # We fetch a larger batch to ensure we catch recent active attacks
        active_threats = [
            t for t in db.fetch_data(limit=200) 
            if t.get('status') != 'Resolved'
        ]
        
        # Clone nodes to avoid mutating static state
        # (simulated immutable state)
        nodes = [dict(n) for n in cls.STATIC_NODES]
        
        for node in nodes:
            # Find threats targeting this node
            node_threats = [t for t in active_threats if t.get('dest_ip') == node['ip']]
            
            if node_threats:
                # Calculate aggregated risk
                max_risk = max((t.get('risk_score', 0) for t in node_threats), default=0)
                
                if max_risk >= 80:
                    node['status'] = 'Compromised'
                elif max_risk >= 60:
                    node['status'] = 'Warning'
                
                # Enrich node data
                node['threats'] = len(node_threats)
                node['latest_threat'] = node_threats[0].get('predicted_label')
            else:
                node['threats'] = 0
                node['status'] = 'Healthy'

        return {
            "nodes": nodes,
            "links": cls.STATIC_LINKS
        }

topology_service = TopologyService()
