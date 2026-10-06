"""
Process Behavior Graph Engine
Reconstructs process ancestry trees using NetworkX, analyzes graph depth and fan-out,
and flags anomalous parent-child edges.
Stage 7 requirement.
"""
from typing import List, Dict, Any, Tuple
import networkx as nx

# List of suspicious parent -> child edges in Windows
SUSPICIOUS_EDGES = [
    ("winword.exe", "powershell.exe"),
    ("winword.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("powerpnt.exe", "powershell.exe"),
    ("powershell.exe", "whoami.exe"),
    ("cmd.exe", "whoami.exe"),
    ("cmd.exe", "vssadmin.exe"),
    ("powershell.exe", "vssadmin.exe"),
    ("wmiprvse.exe", "powershell.exe"),
    ("certutil.exe", "powershell.exe")
]

class ProcessGraphEngine:
    def __init__(self):
        self.graph = nx.DiGraph()

    def build_graph_from_events(self, events: List[Dict[str, Any]]) -> nx.DiGraph:
        """Constructs a directed graph (PPID -> PID) from ProcessCreate events."""
        self.graph.clear()

        for ev in events:
            if ev.get("event_type") == "ProcessCreate":
                pid = ev.get("pid")
                ppid = ev.get("parent_pid")
                proc_name = (ev.get("process_name") or "unknown.exe").lower()
                parent_name = (ev.get("parent_process_name") or "unknown.exe").lower()
                cmd = ev.get("command_line", "")
                user = ev.get("user", "")
                ts = ev.get("timestamp", "")

                if pid:
                    # Add child node
                    self.graph.add_node(pid, name=proc_name, cmd=cmd, user=user, timestamp=ts, is_root=False)
                if ppid:
                    # Add parent node if not present
                    if ppid not in self.graph:
                        self.graph.add_node(ppid, name=parent_name, cmd="", user=user, timestamp=ts, is_root=True)
                    # Add directed edge (Parent -> Child)
                    self.graph.add_edge(ppid, pid, parent_name=parent_name, child_name=proc_name)

        return self.graph

    def analyze_graph(self) -> Dict[str, Any]:
        """
        Calculates graph structural features:
        - Max tree depth
        - Max fan-out (max children from one parent)
        - Anomalous / rare parent-child edges
        - Normalized graph anomaly score (0 to 100)
        """
        if self.graph.number_of_nodes() == 0:
            return {
                "node_count": 0,
                "edge_count": 0,
                "max_depth": 0,
                "max_fan_out": 0,
                "anomalous_edges": [],
                "graph_score": 0.0
            }

        # Calculate max fan-out (out-degree)
        out_degrees = dict(self.graph.out_degree())
        max_fan_out = max(out_degrees.values()) if out_degrees else 0

        # Calculate depth (longest path in DAG)
        try:
            if nx.is_directed_acyclic_graph(self.graph):
                max_depth = nx.dag_longest_path_length(self.graph)
            else:
                max_depth = 2
        except Exception:
            max_depth = 2

        # Check for suspicious edges
        anomalous_edges = []
        for u, v, data in self.graph.edges(data=True):
            p_name = data.get("parent_name", "")
            c_name = data.get("child_name", "")
            if (p_name, c_name) in SUSPICIOUS_EDGES:
                anomalous_edges.append({
                    "parent_pid": u,
                    "child_pid": v,
                    "parent_name": p_name,
                    "child_name": c_name,
                    "description": f"Suspicious execution chain: {p_name} spawned {c_name}"
                })

        # Score formulation
        # High base score if suspicious edges exist; small boost for excessive depth
        edge_penalty = min(85.0, len(anomalous_edges) * 45.0)
        depth_penalty = min(15.0, max_depth * 3.0)
        fanout_penalty = min(10.0, max_fan_out * 2.0)
        
        graph_score = round(min(100.0, edge_penalty + depth_penalty + fanout_penalty), 1)

        return {
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
            "max_depth": max_depth,
            "max_fan_out": max_fan_out,
            "anomalous_edges": anomalous_edges,
            "graph_score": graph_score
        }

    def get_layout_for_ui(self) -> Dict[str, Any]:
        """Generates node coordinates and edge lists for Plotly / Streamlit visualization."""
        if self.graph.number_of_nodes() == 0:
            return {"nodes": [], "edges": []}

        # Spring layout provides pleasing hierarchical spacing
        pos = nx.spring_layout(self.graph, seed=42)

        nodes_data = []
        for node in self.graph.nodes():
            data = self.graph.nodes[node]
            x, y = pos[node]
            nodes_data.append({
                "pid": node,
                "x": float(x),
                "y": float(y),
                "name": data.get("name", "proc"),
                "cmd": data.get("cmd", ""),
                "user": data.get("user", "")
            })

        edges_data = []
        for u, v, data in self.graph.edges(data=True):
            x0, y0 = pos[u]
            x1, y1 = pos[v]
            edges_data.append({
                "u": u,
                "v": v,
                "x0": float(x0),
                "y0": float(y0),
                "x1": float(x1),
                "y1": float(y1),
                "parent_name": data.get("parent_name", ""),
                "child_name": data.get("child_name", ""),
                "is_suspicious": (data.get("parent_name"), data.get("child_name")) in SUSPICIOUS_EDGES
            })

        return {"nodes": nodes_data, "edges": edges_data}
