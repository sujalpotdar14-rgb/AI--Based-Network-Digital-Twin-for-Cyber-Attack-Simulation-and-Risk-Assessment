import networkx as nx
import numpy as np

class DigitalTwinGraph:
    def __init__(self):
        self.graph = nx.Graph()
        self.initialize_default_topology()

    def initialize_default_topology(self):
        """
        Initializes an enterprise multi-zone network digital twin topology.
        Zones: WAN (Internet), DMZ, Corporate Internal, Secure Core, ICS/SCADA.
        """
        self.graph.clear()
        
        nodes_data = [
            # WAN / Perimeter Edge
            {
                "id": "node_wan_gateway",
                "name": "Edge Border Router",
                "type": "router",
                "ip": "198.51.100.1",
                "zone": "WAN",
                "os": "Cisco IOS-XR",
                "open_ports": [80, 443, 179],
                "cve_list": [{"id": "CVE-2023-20198", "cvss": 5.3}],
                "cvss_score": 5.3,
                "asset_criticality": 3.0,
                "status": "healthy",
                "pos": {"x": 100, "y": 260}
            },
            {
                "id": "node_fw_perimeter",
                "name": "Perimeter Next-Gen FW",
                "type": "firewall",
                "ip": "192.168.1.1",
                "zone": "Perimeter",
                "os": "Palo Alto PAN-OS",
                "open_ports": [443, 22],
                "cve_list": [{"id": "CVE-2024-3400", "cvss": 6.8}],
                "cvss_score": 6.8,
                "asset_criticality": 4.5,
                "status": "healthy",
                "pos": {"x": 280, "y": 260}
            },
            # DMZ Zone
            {
                "id": "node_web_dmz",
                "name": "Public Nginx Web Server",
                "type": "server",
                "ip": "10.0.1.50",
                "zone": "DMZ",
                "os": "Ubuntu Linux 22.04",
                "open_ports": [80, 443, 22],
                "cve_list": [
                    {"id": "CVE-2023-44487", "cvss": 7.5},
                    {"id": "CVE-2024-21626", "cvss": 8.6}
                ],
                "cvss_score": 8.6,
                "asset_criticality": 3.8,
                "status": "healthy",
                "pos": {"x": 480, "y": 130}
            },
            {
                "id": "node_api_gateway",
                "name": "API Gateway Cluster",
                "type": "server",
                "ip": "10.0.1.51",
                "zone": "DMZ",
                "os": "Alpine Linux",
                "open_ports": [8080, 443],
                "cve_list": [{"id": "CVE-2023-38545", "cvss": 7.2}],
                "cvss_score": 7.2,
                "asset_criticality": 4.0,
                "status": "healthy",
                "pos": {"x": 480, "y": 260}
            },
            {
                "id": "node_mail_server",
                "name": "Corporate Mail Gateway",
                "type": "server",
                "ip": "10.0.1.52",
                "zone": "DMZ",
                "os": "Debian Linux",
                "open_ports": [25, 587, 993],
                "cve_list": [{"id": "CVE-2024-21670", "cvss": 6.5}],
                "cvss_score": 6.5,
                "asset_criticality": 3.5,
                "status": "healthy",
                "pos": {"x": 480, "y": 390}
            },
            # Internal Core Firewall
            {
                "id": "node_fw_internal",
                "name": "Internal Core Firewall",
                "type": "firewall",
                "ip": "10.0.2.1",
                "zone": "Internal",
                "os": "Fortinet FortiGate",
                "open_ports": [443],
                "cve_list": [{"id": "CVE-2024-21762", "cvss": 4.2}],
                "cvss_score": 4.2,
                "asset_criticality": 4.8,
                "status": "healthy",
                "pos": {"x": 680, "y": 260}
            },
            # Internal Corporate Network & Secure Core
            {
                "id": "node_active_directory",
                "name": "Active Directory Controller",
                "type": "server",
                "ip": "10.0.2.10",
                "zone": "Secure Core",
                "os": "Windows Server 2022",
                "open_ports": [53, 88, 389, 445, 636],
                "cve_list": [
                    {"id": "CVE-2022-26923", "cvss": 8.8},
                    {"id": "CVE-2024-20683", "cvss": 7.4}
                ],
                "cvss_score": 8.8,
                "asset_criticality": 5.0, # Highest value target
                "status": "healthy",
                "pos": {"x": 880, "y": 110}
            },
            {
                "id": "node_db_prod",
                "name": "Production PostgreSQL DB",
                "type": "database",
                "ip": "10.0.2.20",
                "zone": "Secure Core",
                "os": "RHEL 9.2",
                "open_ports": [5432, 22],
                "cve_list": [
                    {"id": "CVE-2023-5869", "cvss": 9.1},
                    {"id": "CVE-2024-10979", "cvss": 8.1}
                ],
                "cvss_score": 9.1,
                "asset_criticality": 5.0, # High value database
                "status": "healthy",
                "pos": {"x": 880, "y": 230}
            },
            {
                "id": "node_workstation_admin",
                "name": "SecOps Admin Workstation",
                "type": "workstation",
                "ip": "10.0.3.105",
                "zone": "Internal",
                "os": "Windows 11 Enterprise",
                "open_ports": [3389, 445],
                "cve_list": [{"id": "CVE-2023-36884", "cvss": 6.8}],
                "cvss_score": 6.8,
                "asset_criticality": 4.2,
                "status": "healthy",
                "pos": {"x": 880, "y": 350}
            },
            {
                "id": "node_workstation_user",
                "name": "Finance Dept Workstation",
                "type": "workstation",
                "ip": "10.0.3.112",
                "zone": "Internal",
                "os": "Windows 10 Pro",
                "open_ports": [139, 445],
                "cve_list": [{"id": "CVE-2024-21338", "cvss": 7.8}],
                "cvss_score": 7.8,
                "asset_criticality": 3.2,
                "status": "healthy",
                "pos": {"x": 880, "y": 470}
            },
            # ICS / SCADA Operational Technology Zone & Cloud
            {
                "id": "node_scada_gateway",
                "name": "OT SCADA IoT Gateway",
                "type": "scada",
                "ip": "172.16.5.1",
                "zone": "ICS/SCADA",
                "os": "VxWorks RTOS",
                "open_ports": [502, 20000, 102], # Modbus TCP, DNP3, Siemens S7
                "cve_list": [{"id": "CVE-2023-3595", "cvss": 9.8}],
                "cvss_score": 9.8,
                "asset_criticality": 4.9,
                "status": "healthy",
                "pos": {"x": 1080, "y": 260}
            },
            {
                "id": "node_cloud_storage",
                "name": "Cloud Backup S3 Vault",
                "type": "cloud",
                "ip": "10.0.4.99",
                "zone": "Cloud",
                "os": "AWS Linux 2023",
                "open_ports": [443],
                "cve_list": [{"id": "CVE-2023-34034", "cvss": 5.4}],
                "cvss_score": 5.4,
                "asset_criticality": 4.3,
                "status": "healthy",
                "pos": {"x": 1080, "y": 130}
            }
        ]

        edges_data = [
            ("node_wan_gateway", "node_fw_perimeter", {"bandwidth": 1000, "latency": 2}),
            ("node_fw_perimeter", "node_web_dmz", {"bandwidth": 500, "latency": 1}),
            ("node_fw_perimeter", "node_api_gateway", {"bandwidth": 500, "latency": 1}),
            ("node_fw_perimeter", "node_mail_server", {"bandwidth": 500, "latency": 1}),
            ("node_web_dmz", "node_fw_internal", {"bandwidth": 200, "latency": 3}),
            ("node_api_gateway", "node_fw_internal", {"bandwidth": 300, "latency": 2}),
            ("node_mail_server", "node_fw_internal", {"bandwidth": 100, "latency": 3}),
            ("node_fw_internal", "node_active_directory", {"bandwidth": 500, "latency": 1}),
            ("node_fw_internal", "node_db_prod", {"bandwidth": 500, "latency": 1}),
            ("node_fw_internal", "node_workstation_admin", {"bandwidth": 100, "latency": 4}),
            ("node_fw_internal", "node_workstation_user", {"bandwidth": 100, "latency": 4}),
            ("node_workstation_admin", "node_active_directory", {"bandwidth": 100, "latency": 2}),
            ("node_workstation_admin", "node_db_prod", {"bandwidth": 100, "latency": 2}),
            ("node_db_prod", "node_cloud_storage", {"bandwidth": 200, "latency": 8}),
            ("node_fw_internal", "node_scada_gateway", {"bandwidth": 50, "latency": 12})
        ]

        for n in nodes_data:
            # Baseline telemetry metrics
            n["telemetry"] = {
                "cpu_utilization": round(float(np.random.uniform(10.0, 30.0)), 1),
                "ram_utilization": round(float(np.random.uniform(20.0, 45.0)), 1),
                "bandwidth_mbps": round(float(np.random.uniform(5.0, 50.0)), 1),
                "failed_logins": 0,
                "error_rate": round(float(np.random.uniform(0.0, 0.01)), 3),
                "syn_ratio": 0.05,
                "anomaly_score": 0.02
            }
            self.graph.add_node(n["id"], **n)

        for u, v, attr in edges_data:
            self.graph.add_edge(u, v, **attr)

        self.update_centrality_metrics()

    def update_centrality_metrics(self):
        """Calculates degree and betweenness centrality for all nodes."""
        betweenness = nx.betweenness_centrality(self.graph)
        degree = nx.degree_centrality(self.graph)
        
        for n in self.graph.nodes:
            self.graph.nodes[n]["betweenness_centrality"] = round(betweenness[n], 4)
            self.graph.nodes[n]["degree_centrality"] = round(degree[n], 4)
            self.graph.nodes[n]["telemetry"]["node_centrality"] = round(betweenness[n], 4)

    def get_node(self, node_id):
        if node_id in self.graph:
            return self.graph.nodes[node_id]
        return None

    def add_custom_node(self, node_dict):
        node_id = node_dict.get("id") or f"node_custom_{len(self.graph.nodes)+1}"
        node_dict["id"] = node_id
        if "status" not in node_dict:
            node_dict["status"] = "healthy"
        if "telemetry" not in node_dict:
            node_dict["telemetry"] = {
                "cpu_utilization": 20.0, "ram_utilization": 30.0,
                "bandwidth_mbps": 10.0, "failed_logins": 0,
                "error_rate": 0.0, "syn_ratio": 0.05, "anomaly_score": 0.01,
                "node_centrality": 0.1
            }

        if "pos" not in node_dict or not node_dict["pos"]:
            zone_x_map = {
                "WAN": 100,
                "Perimeter": 280,
                "DMZ": 480,
                "Internal": 680,
                "Secure Core": 880,
                "ICS/SCADA": 1080,
                "Cloud": 1080
            }
            target_x = zone_x_map.get(node_dict.get("zone"), 680)
            existing_y = [
                d["pos"]["y"] for n, d in self.graph.nodes(data=True)
                if "pos" in d and d["pos"] and abs(d["pos"].get("x", 0) - target_x) < 80
            ]
            new_y = (max(existing_y) + 110) if existing_y else 260
            node_dict["pos"] = {"x": target_x, "y": new_y}

        self.graph.add_node(node_id, **node_dict)
        
        # Connect to internal FW by default if unlinked
        if "node_fw_internal" in self.graph and node_id != "node_fw_internal":
            self.graph.add_edge(node_id, "node_fw_internal", bandwidth=100, latency=5)
            
        self.update_centrality_metrics()
        return self.graph.nodes[node_id]

    def reset_network_states(self):
        """Resets node statuses and telemetry back to normal baseline."""
        for n in self.graph.nodes:
            self.graph.nodes[n]["status"] = "healthy"
            self.graph.nodes[n]["telemetry"]["cpu_utilization"] = round(float(np.random.uniform(10.0, 30.0)), 1)
            self.graph.nodes[n]["telemetry"]["ram_utilization"] = round(float(np.random.uniform(20.0, 45.0)), 1)
            self.graph.nodes[n]["telemetry"]["bandwidth_mbps"] = round(float(np.random.uniform(5.0, 50.0)), 1)
            self.graph.nodes[n]["telemetry"]["failed_logins"] = 0
            self.graph.nodes[n]["telemetry"]["error_rate"] = 0.005
            self.graph.nodes[n]["telemetry"]["syn_ratio"] = 0.05
            self.graph.nodes[n]["telemetry"]["anomaly_score"] = 0.02
        return True

    def find_attack_paths(self, source_id, target_id):
        """Finds all simple attack paths between entry node and critical asset."""
        if source_id not in self.graph or target_id not in self.graph:
            return []
        try:
            paths = list(nx.all_shortest_paths(self.graph, source=source_id, target=target_id))
            return paths
        except nx.NetworkXNoPath:
            return []

    def export_graph_json(self):
        """Returns node list and edge list formatted for graph visualization & API."""
        nodes = []
        for n, data in self.graph.nodes(data=True):
            node_info = dict(data)
            node_info["id"] = n
            nodes.append(node_info)
            
        edges = []
        for u, v, data in self.graph.edges(data=True):
            edge_info = dict(data)
            edge_info["source"] = u
            edge_info["target"] = v
            edges.append(edge_info)
            
        return {"nodes": nodes, "edges": edges}
