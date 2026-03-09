"""
Attack Graph & Kill Chain Visualization Engine
Uses NetworkX to build directed graphs from security events.
Groups events into kill chains by shared IP/user within a time window.
Exports graph data as JSON for D3.js visualization.
"""
import json
from datetime import datetime, timedelta
from typing import List, Optional
from collections import defaultdict

try:
    import networkx as nx
    NX_AVAILABLE = True
except ImportError:
    NX_AVAILABLE = False
    print("⚠️ NetworkX not installed. Attack graph features will be limited.")


# Risk score → severity label
def _severity(score: float) -> str:
    if score >= 85:
        return "critical"
    elif score >= 61:
        return "high"
    elif score >= 31:
        return "medium"
    return "low"


# Severity → color mapping (for frontend D3 nodes)
SEVERITY_COLORS = {
    "critical": "#FF2D2D",
    "high":     "#FF8C00",
    "medium":   "#FFB800",
    "low":      "#00FFC8",
    "normal":   "#4A9EFF"
}


def build_graph(events: list) -> "nx.DiGraph":
    """
    Build a directed graph from a list of event dicts or ORM objects.
    Nodes: IP addresses and user accounts.
    Edges: Event actions linking user → resource.
    """
    if not NX_AVAILABLE:
        return None

    G = nx.DiGraph()

    for i, event in enumerate(events):
        # Support both dicts and ORM objects
        if hasattr(event, "__dict__"):
            ip = getattr(event, "ip", "unknown")
            user = getattr(event, "user", "unknown")
            action = getattr(event, "action", "")
            resource = getattr(event, "resource", "")
            risk_score = getattr(event, "risk_score", 0) or 0
            timestamp = getattr(event, "timestamp", datetime.utcnow())
        else:
            ip = event.get("ip", "unknown")
            user = event.get("user", "unknown")
            action = event.get("action", "")
            resource = event.get("resource", "")
            risk_score = event.get("risk_score", 0) or 0
            timestamp = event.get("timestamp", datetime.utcnow())

        sev = _severity(risk_score)
        ts_str = timestamp.isoformat() if isinstance(timestamp, datetime) else str(timestamp)

        # Add nodes
        ip_node = f"IP:{ip}"
        user_node = f"USER:{user}"
        resource_node = f"RESOURCE:{resource}"

        if not G.has_node(ip_node):
            G.add_node(ip_node, type="ip", label=ip, severity=sev,
                       color=SEVERITY_COLORS.get(sev, "#888"), risk_score=risk_score)
        else:
            # Update if higher risk
            if risk_score > G.nodes[ip_node].get("risk_score", 0):
                G.nodes[ip_node]["severity"] = sev
                G.nodes[ip_node]["color"] = SEVERITY_COLORS.get(sev, "#888")
                G.nodes[ip_node]["risk_score"] = risk_score

        if not G.has_node(user_node):
            G.add_node(user_node, type="user", label=user, severity=sev,
                       color=SEVERITY_COLORS.get(sev, "#888"), risk_score=risk_score)

        if resource and not G.has_node(resource_node):
            G.add_node(resource_node, type="resource", label=resource,
                       severity="low", color=SEVERITY_COLORS["low"], risk_score=0)

        # Add edges
        # IP → User (attacker link)
        G.add_edge(ip_node, user_node, action=action, timestamp=ts_str,
                   risk_score=risk_score, severity=sev, event_index=i)

        # User → Resource (action target)
        if resource:
            G.add_edge(user_node, resource_node, action=action, timestamp=ts_str,
                       risk_score=risk_score, severity=sev, event_index=i)

    return G


def get_attack_chains(events: list, window_minutes: int = 15) -> list:
    """
    Group high-risk events (score >= 60) into kill chains.
    Events are chained if they share a user or IP and occur within window_minutes.
    Returns list of chains, each chain being a list of event dicts.
    """
    high_risk_events = []
    for event in events:
        if hasattr(event, "__dict__"):
            score = getattr(event, "risk_score", 0) or 0
            ts = getattr(event, "timestamp", None)
            ip = getattr(event, "ip", "")
            user = getattr(event, "user", "")
            action = getattr(event, "action", "")
            resource = getattr(event, "resource", "")
            event_id = getattr(event, "id", 0)
        else:
            score = event.get("risk_score", 0) or 0
            ts = event.get("timestamp", None)
            ip = event.get("ip", "")
            user = event.get("user", "")
            action = event.get("action", "")
            resource = event.get("resource", "")
            event_id = event.get("id", 0)

        if score >= 60:
            high_risk_events.append({
                "id": event_id,
                "ip": ip,
                "user": user,
                "action": action,
                "resource": resource,
                "risk_score": score,
                "severity": _severity(score),
                "timestamp": ts.isoformat() if isinstance(ts, datetime) else str(ts)
            })

    # Sort by timestamp
    high_risk_events.sort(key=lambda x: x["timestamp"])

    chains = []
    used = set()
    window = timedelta(minutes=window_minutes)

    for i, evt in enumerate(high_risk_events):
        if i in used:
            continue

        chain = [evt]
        used.add(i)
        t_start = datetime.fromisoformat(evt["timestamp"]) if isinstance(evt["timestamp"], str) else evt["timestamp"]

        for j, other in enumerate(high_risk_events):
            if j in used or j == i:
                continue
            t_other = datetime.fromisoformat(other["timestamp"]) if isinstance(other["timestamp"], str) else other["timestamp"]

            # Link if same IP or user, and within time window
            if (evt["ip"] == other["ip"] or evt["user"] == other["user"]):
                if abs((t_other - t_start).total_seconds()) <= window.total_seconds():
                    chain.append(other)
                    used.add(j)

        if len(chain) >= 1:  # Include all high-risk events, even solo ones
            chains.append({
                "chain_id": f"CHAIN-{i:04d}",
                "events": chain,
                "max_risk": max(e["risk_score"] for e in chain),
                "severity": _severity(max(e["risk_score"] for e in chain)),
                "start_time": chain[0]["timestamp"],
                "end_time": chain[-1]["timestamp"],
                "involved_ips": list(set(e["ip"] for e in chain if e["ip"])),
                "involved_users": list(set(e["user"] for e in chain if e["user"]))
            })

    # Sort chains by max_risk descending
    chains.sort(key=lambda x: x["max_risk"], reverse=True)
    return chains


def graph_to_json(G) -> dict:
    """
    Convert NetworkX graph to D3-compatible JSON.
    Returns { nodes: [...], links: [...] }
    """
    if G is None or not NX_AVAILABLE:
        return {"nodes": [], "links": []}

    # Create node index mapping
    node_list = list(G.nodes(data=True))
    node_index = {node_id: idx for idx, (node_id, _) in enumerate(node_list)}

    nodes = []
    for node_id, attrs in node_list:
        nodes.append({
            "id": node_id,
            "index": node_index[node_id],
            "label": attrs.get("label", node_id),
            "type": attrs.get("type", "unknown"),
            "color": attrs.get("color", "#888"),
            "severity": attrs.get("severity", "low"),
            "risk_score": attrs.get("risk_score", 0)
        })

    links = []
    for source, target, attrs in G.edges(data=True):
        links.append({
            "source": source,
            "target": target,
            "source_index": node_index.get(source, 0),
            "target_index": node_index.get(target, 0),
            "action": attrs.get("action", ""),
            "timestamp": attrs.get("timestamp", ""),
            "risk_score": attrs.get("risk_score", 0),
            "severity": attrs.get("severity", "low")
        })

    return {
        "nodes": nodes,
        "links": links,
        "node_count": len(nodes),
        "link_count": len(links)
    }
