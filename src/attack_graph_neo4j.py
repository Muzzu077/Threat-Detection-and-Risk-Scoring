"""
TrustFlow — Neo4j Attack-Graph Backend (Phase 4)

Optional graph database for the attack-graph view. Mirrors what the in-process
NetworkX module does, but offloads to Neo4j so the graph scales beyond a single
worker's memory.

Schema:
    (:User {name})
        -[:DID {risk, ts, attack_type}]->
    (:Resource {path})
    (:IP {addr})-[:ATTACKED]->(:User)
    (:Tenant {id})-[:OWNS]->(:User)

Enabled by setting NEO4J_URI=bolt://host:7687, plus NEO4J_USER / NEO4J_PASSWORD.
When unset, every public function returns {ok: False, configured: False} so
the existing NetworkX path keeps serving the API.
"""
import os
from datetime import datetime


def _config():
    return {
        "uri":      os.getenv("NEO4J_URI", "").strip(),
        "user":     os.getenv("NEO4J_USER", "neo4j"),
        "password": os.getenv("NEO4J_PASSWORD", ""),
    }


def is_configured() -> bool:
    cfg = _config()
    return bool(cfg["uri"]) and bool(cfg["password"])


_driver = None


def _get_driver():
    global _driver
    if _driver is not None:
        return _driver
    if not is_configured():
        return None
    try:
        from neo4j import GraphDatabase
        cfg = _config()
        _driver = GraphDatabase.driver(cfg["uri"], auth=(cfg["user"], cfg["password"]))
        # Test connection
        with _driver.session() as s:
            s.run("RETURN 1").consume()
        return _driver
    except Exception as e:
        print(f"⚠️  Neo4j connection failed: {e}")
        return None


def upsert_event(event: dict, tenant_id: int) -> dict:
    """Push one event into the graph as nodes + relationships."""
    driver = _get_driver()
    if driver is None:
        return {"ok": False, "skipped": True}

    user     = event.get("user") or "anonymous"
    ip       = event.get("ip") or "unknown"
    resource = event.get("resource") or "/"
    risk     = float(event.get("risk_score") or 0)
    atype    = event.get("attack_type") or "normal"
    ts       = datetime.utcnow().isoformat()

    cypher = """
    MERGE (t:Tenant {id: $tenant_id})
    MERGE (u:User {name: $user})
    MERGE (t)-[:OWNS]->(u)
    MERGE (r:Resource {path: $resource})
    MERGE (i:IP {addr: $ip})
    CREATE (u)-[:DID {risk: $risk, ts: $ts, attack_type: $atype, tenant_id: $tenant_id}]->(r)
    MERGE (i)-[a:ATTACKED]->(u) ON CREATE SET a.first_seen = $ts SET a.last_seen = $ts
    """
    try:
        with driver.session() as s:
            s.run(cypher, tenant_id=tenant_id, user=user, ip=ip,
                  resource=resource, risk=risk, atype=atype, ts=ts)
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def get_graph(tenant_id: int = None, limit: int = 200) -> dict:
    """Pull the recent risk-bearing subgraph for visualisation."""
    driver = _get_driver()
    if driver is None:
        return {"ok": False, "configured": False, "nodes": [], "links": []}

    where = "WHERE d.risk >= 50"
    params = {"limit": limit}
    if tenant_id is not None:
        where += " AND d.tenant_id = $tenant_id"
        params["tenant_id"] = tenant_id

    cypher = f"""
    MATCH (u:User)-[d:DID]->(r:Resource)
    {where}
    OPTIONAL MATCH (i:IP)-[:ATTACKED]->(u)
    RETURN u.name AS user, r.path AS resource, i.addr AS ip,
           d.risk AS risk, d.attack_type AS attack_type, d.ts AS ts
    ORDER BY d.ts DESC
    LIMIT $limit
    """
    try:
        nodes = {}
        links = []
        with driver.session() as s:
            for rec in s.run(cypher, **params):
                user, resource, ip = rec["user"], rec["resource"], rec["ip"]
                if user:     nodes[f"user:{user}"]      = {"id": f"user:{user}", "type": "user", "label": user}
                if resource: nodes[f"res:{resource}"]   = {"id": f"res:{resource}", "type": "resource", "label": resource[:40]}
                if ip:       nodes[f"ip:{ip}"]          = {"id": f"ip:{ip}", "type": "ip", "label": ip}
                if user and resource:
                    links.append({
                        "source": f"user:{user}", "target": f"res:{resource}",
                        "risk": rec["risk"], "attack_type": rec["attack_type"], "ts": rec["ts"],
                    })
                if ip and user:
                    links.append({
                        "source": f"ip:{ip}", "target": f"user:{user}",
                        "kind": "attacked",
                    })
        return {
            "ok": True,
            "configured": True,
            "node_count": len(nodes),
            "link_count": len(links),
            "nodes": list(nodes.values()),
            "links": links,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "nodes": [], "links": []}


def stats() -> dict:
    """High-level graph health check."""
    driver = _get_driver()
    if driver is None:
        return {"ok": False, "configured": False}
    try:
        with driver.session() as s:
            r = s.run("""
            CALL { MATCH (u:User) RETURN count(u) AS users }
            CALL { MATCH (r:Resource) RETURN count(r) AS resources }
            CALL { MATCH (i:IP) RETURN count(i) AS ips }
            CALL { MATCH ()-[d:DID]->() RETURN count(d) AS edges }
            RETURN users, resources, ips, edges
            """).single()
            return {
                "ok": True,
                "configured": True,
                "users": r["users"],
                "resources": r["resources"],
                "ips": r["ips"],
                "edges": r["edges"],
            }
    except Exception as e:
        return {"ok": False, "error": str(e)}
