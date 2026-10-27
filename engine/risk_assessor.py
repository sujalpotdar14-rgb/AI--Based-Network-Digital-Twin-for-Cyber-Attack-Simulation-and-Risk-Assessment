import numpy as np

class DynamicRiskAssessor:
    def __init__(self, digital_twin):
        self.dt = digital_twin

    def calculate_node_risk(self, node_data):
        """
        Calculates individual node risk score (0-100).
        """
        cvss = node_data.get("cvss_score", 5.0)
        criticality = node_data.get("asset_criticality", 3.0)
        centrality = node_data.get("betweenness_centrality", 0.1)
        telemetry = node_data.get("telemetry", {})
        
        failed_logins = telemetry.get("failed_logins", 0)
        error_rate = telemetry.get("error_rate", 0.0)
        syn_ratio = telemetry.get("syn_ratio", 0.05)
        cpu = telemetry.get("cpu_utilization", 20.0)
        
        # Threat anomaly component
        threat_weight = (failed_logins / 10.0) + (error_rate * 5.0) + (syn_ratio * 3.0) + (cpu / 100.0 * 2.0)
        threat_score = min(10.0, threat_weight)
        
        # Risk Formula Weights
        w_cvss = 3.5
        w_crit = 3.0
        w_cent = 1.5
        w_threat = 2.0
        
        raw_risk = (cvss * w_cvss) + (criticality * w_crit) + (centrality * 10.0 * w_cent) + (threat_score * w_threat)
        normalized_risk = min(100.0, round(raw_risk / 1.1, 1))
        
        status = node_data.get("status", "healthy")
        if status == "compromised":
            normalized_risk = min(100.0, normalized_risk * 1.4)
        elif status == "under_attack":
            normalized_risk = min(100.0, normalized_risk * 1.25)
        elif status == "isolated":
            normalized_risk = round(normalized_risk * 0.35, 1)
        elif status == "shielded":
            normalized_risk = round(normalized_risk * 0.5, 1)
            
        return min(100.0, round(float(normalized_risk), 1))

    def evaluate_network_risk(self):
        """
        Evaluates system-wide Digital Twin risk score, threat level, and blast radius.
        """
        node_risks = {}
        total_weighted_risk = 0.0
        total_weights = 0.0
        
        compromised_count = 0
        under_attack_count = 0
        isolated_count = 0
        total_nodes = len(self.dt.graph.nodes)
        
        if total_nodes == 0:
            return {"network_risk_score": 0, "threat_level": "LOW", "blast_radius_percent": 0}
            
        for n, data in self.dt.graph.nodes(data=True):
            r_score = self.calculate_node_risk(data)
            node_risks[n] = r_score
            
            crit = data.get("asset_criticality", 3.0)
            status = data.get("status", "healthy")
            
            status_mult = 1.0
            if status == "compromised":
                status_mult = 2.5
                compromised_count += 1
            elif status == "under_attack":
                status_mult = 1.8
                under_attack_count += 1
            elif status == "isolated":
                status_mult = 0.25
                isolated_count += 1
            elif status == "shielded":
                status_mult = 0.5
                
            weight = crit * status_mult
            total_weighted_risk += (r_score * weight)
            total_weights += weight
            
        network_risk_score = round(total_weighted_risk / max(0.1, total_weights), 1)
        network_risk_score = min(100.0, max(0.0, network_risk_score))
        
        if network_risk_score <= 25.0:
            threat_level = "LOW"
            severity_color = "#00E676"
        elif network_risk_score <= 55.0:
            threat_level = "MEDIUM"
            severity_color = "#FFC107"
        elif network_risk_score <= 80.0:
            threat_level = "HIGH"
            severity_color = "#FF9800"
        else:
            threat_level = "CRITICAL"
            severity_color = "#FF3366"
            
        # Calculate Blast Radius Index
        affected_nodes = compromised_count + under_attack_count
        blast_radius_percent = round((affected_nodes / total_nodes) * 100.0, 1)
        
        return {
            "network_risk_score": network_risk_score,
            "threat_level": threat_level,
            "severity_color": severity_color,
            "blast_radius_percent": blast_radius_percent,
            "compromised_nodes": compromised_count,
            "under_attack_nodes": under_attack_count,
            "isolated_nodes": isolated_count,
            "total_nodes": total_nodes,
            "node_risk_scores": node_risks
        }
