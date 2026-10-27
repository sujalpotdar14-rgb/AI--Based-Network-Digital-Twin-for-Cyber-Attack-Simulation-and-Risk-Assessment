import copy

class AutomatedMitigationEngine:
    def __init__(self, digital_twin, risk_assessor):
        self.dt = digital_twin
        self.risk_assessor = risk_assessor

    def generate_recommended_playbooks(self):
        """
        Scans Digital Twin network status and generates actionable AI defense playbooks.
        """
        playbooks = []
        risk_summary = self.risk_assessor.evaluate_network_risk()
        node_risks = risk_summary.get("node_risk_scores", {})
        
        for n, data in self.dt.graph.nodes(data=True):
            status = data.get("status", "healthy")
            cvss = data.get("cvss_score", 5.0)
            r_score = node_risks.get(n, 50.0)
            
            if status in ["compromised", "under_attack"] or r_score > 60.0:
                # 1. Isolation Playbook
                playbooks.append({
                    "id": f"playbook_isolate_{n}",
                    "node_id": n,
                    "node_name": data.get("name"),
                    "action_type": "ISOLATE_NODE",
                    "title": f"Network Micro-Segmentation & Isolation on {data.get('name')}",
                    "description": f"Isolate node {n} from core routing table to stop lateral movement blast radius.",
                    "severity": "CRITICAL" if status == "compromised" else "HIGH",
                    "risk_reduction_estimate": round(r_score * 0.75, 1)
                })
                
                # 2. Firewall Block Playbook
                playbooks.append({
                    "id": f"playbook_fw_{n}",
                    "node_id": n,
                    "node_name": data.get("name"),
                    "action_type": "FIREWALL_BLOCK",
                    "title": f"Inject Firewall ACL & Rate-Limit Rule for {data.get('name')}",
                    "description": f"Enforce next-gen firewall policy blocking unauthorized ingress traffic to open ports {data.get('open_ports')}.",
                    "severity": "HIGH",
                    "risk_reduction_estimate": round(r_score * 0.55, 1)
                })
                
            if cvss >= 7.0:
                # 3. Patching Playbook
                playbooks.append({
                    "id": f"playbook_patch_{n}",
                    "node_id": n,
                    "node_name": data.get("name"),
                    "action_type": "PATCH_VULNERABILITY",
                    "title": f"Emergency Patch Deployment for {data.get('name')} (CVSS {cvss})",
                    "description": f"Apply security patch targeting CVE vulnerabilities on {data.get('name')}.",
                    "severity": "MEDIUM",
                    "risk_reduction_estimate": round(r_score * 0.40, 1)
                })
                
        # Honeypot divert option
        if risk_summary["compromised_nodes"] > 0 or risk_summary["under_attack_nodes"] > 0:
            playbooks.append({
                "id": "playbook_honeypot_global",
                "node_id": "global",
                "node_name": "Network Wide",
                "action_type": "HONEYPOT_REDIRECT",
                "title": "Deploy Dynamic Honeypot Trap & Traffic Diversion",
                "description": "Reroute malicious payload packets to isolated Cowrie/Dionaea deception honeypot.",
                "severity": "HIGH",
                "risk_reduction_estimate": 45.0
            })
            
        return playbooks

    def simulate_what_if_countermeasure(self, action_type, node_id):
        """
        Evaluates risk score drop before applying mitigation to live network.
        """
        current_risk = self.risk_assessor.evaluate_network_risk()["network_risk_score"]
        
        # Deep clone state to simulate countermeasure
        temp_graph = copy.deepcopy(self.dt.graph)
        
        if node_id in temp_graph.nodes:
            node_data = temp_graph.nodes[node_id]
            if action_type == "ISOLATE_NODE":
                node_data["status"] = "isolated"
            elif action_type == "FIREWALL_BLOCK":
                node_data["status"] = "shielded"
                node_data["telemetry"]["syn_ratio"] = 0.05
                node_data["telemetry"]["error_rate"] = 0.01
            elif action_type == "PATCH_VULNERABILITY":
                node_data["status"] = "healthy"
                node_data["cvss_score"] = 1.0
            elif action_type == "HONEYPOT_REDIRECT":
                node_data["status"] = "shielded"

        # Calculate hypothetical new risk
        # Create temporary assessor wrapper
        class TempDT:
            def __init__(self, g): self.graph = g
        temp_assessor = self.risk_assessor.__class__(TempDT(temp_graph))
        simulated_risk = temp_assessor.evaluate_network_risk()["network_risk_score"]
        
        risk_drop = round(max(0.0, current_risk - simulated_risk), 1)
        percentage_reduction = round((risk_drop / max(1.0, current_risk)) * 100.0, 1)
        
        return {
            "initial_risk_score": current_risk,
            "simulated_risk_score": simulated_risk,
            "risk_score_reduction": risk_drop,
            "percentage_reduction": percentage_reduction
        }

    def apply_mitigation(self, action_type, node_id):
        """
        Applies defense countermeasure directly to the Digital Twin network.
        """
        node = self.dt.get_node(node_id)
        if not node and action_type != "HONEYPOT_REDIRECT":
            return {"success": False, "message": f"Node {node_id} not found."}
            
        initial_risk = self.risk_assessor.evaluate_network_risk()["network_risk_score"]

        if action_type == "ISOLATE_NODE":
            node["status"] = "isolated"
            node["telemetry"]["cpu_utilization"] = 10.0
            node["telemetry"]["bandwidth_mbps"] = 0.0
            message = f"Node {node['name']} ({node_id}) has been isolated from internal routing tables."

        elif action_type == "FIREWALL_BLOCK":
            node["status"] = "shielded"
            node["telemetry"]["syn_ratio"] = 0.05
            node["telemetry"]["error_rate"] = 0.005
            node["telemetry"]["failed_logins"] = 0
            message = f"Firewall ACL rule enforced blocking malicious ingress traffic to {node['name']}."

        elif action_type == "PATCH_VULNERABILITY":
            node["status"] = "healthy"
            node["cvss_score"] = 1.2
            node["cve_list"] = [{"id": "CVE-PATCHED-2026", "cvss": 1.2}]
            node["telemetry"]["cpu_utilization"] = 22.0
            node["telemetry"]["error_rate"] = 0.001
            message = f"Security patch successfully applied to {node['name']}. Vulnerability mitigated."

        elif action_type == "HONEYPOT_REDIRECT":
            # Add virtual honeypot node if not present
            if "node_honeypot" not in self.dt.graph:
                self.dt.add_custom_node({
                    "id": "node_honeypot",
                    "name": "Deception Honeypot Trap",
                    "type": "server",
                    "ip": "10.0.99.99",
                    "zone": "DMZ",
                    "status": "shielded",
                    "cvss_score": 1.0,
                    "asset_criticality": 1.0,
                    "pos": {"x": 360, "y": 480}
                })
            message = "Traffic deception active. Attacker packets redirected to Honeypot trap."

        else:
            return {"success": False, "message": f"Unknown action type: {action_type}"}

        post_risk = self.risk_assessor.evaluate_network_risk()["network_risk_score"]
        
        return {
            "success": True,
            "action_type": action_type,
            "node_id": node_id,
            "message": message,
            "initial_risk_score": initial_risk,
            "post_mitigation_risk_score": post_risk,
            "risk_reduction": round(initial_risk - post_risk, 1)
        }
