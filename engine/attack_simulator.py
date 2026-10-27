import time
import numpy as np

class CyberAttackSimulator:
    def __init__(self, digital_twin, risk_assessor, ml_classifier=None, scaler=None):
        self.dt = digital_twin
        self.risk_assessor = risk_assessor
        self.classifier = ml_classifier
        self.scaler = scaler

    def run_attack_simulation(self, attack_type, target_node_id=None, intensity="high"):
        """
        Executes a cyber attack scenario on the Digital Twin network.
        Returns simulation trajectory, stage logs, packet flow traces, and updated risk state.
        """
        if not target_node_id or target_node_id not in self.dt.graph:
            # Default target selection based on attack type
            if attack_type == "DDoS SYN Flood":
                target_node_id = "node_web_dmz"
            elif attack_type == "Ransomware Propagation":
                target_node_id = "node_db_prod"
            elif attack_type == "SSH Brute Force":
                target_node_id = "node_workstation_admin"
            elif attack_type in ["SQLi / RCE", "SQL Injection / RCE"]:
                target_node_id = "node_web_dmz"
            else:
                target_node_id = "node_active_directory"

        logs = []
        packet_traces = []
        compromised_nodes = []
        
        target_node = self.dt.get_node(target_node_id)
        
        # 1. Multi-Stage Execution based on MITRE ATT&CK Framework
        stages = [
            {"stage": 1, "name": "Reconnaissance", "description": "Port scanning and service vulnerability enumeration"},
            {"stage": 2, "name": "Initial Access", "description": "Exploiting vulnerability or credentials"},
            {"stage": 3, "name": "Privilege Escalation", "description": "Elevating access to SYSTEM/root level"},
            {"stage": 4, "name": "Lateral Movement", "description": "Pivoting across internal network segments"},
            {"stage": 5, "name": "Impact / Data Exfiltration", "description": "Executing payload, encrypting data or DDoS flood"}
        ]
        
        timestamp_base = time.time()

        if attack_type == "DDoS SYN Flood":
            entry_node = "node_wan_gateway"
            target_node["status"] = "under_attack"
            
            # Telemetry spike
            target_node["telemetry"]["cpu_utilization"] = round(float(np.random.uniform(88.0, 99.9)), 1)
            target_node["telemetry"]["bandwidth_mbps"] = round(float(np.random.uniform(450.0, 980.0)), 1)
            target_node["telemetry"]["syn_ratio"] = round(float(np.random.uniform(0.85, 0.98)), 3)
            target_node["telemetry"]["error_rate"] = round(float(np.random.uniform(0.35, 0.75)), 3)
            
            logs.append(f"[RECON] SYN flood vector detected from WAN Gateway -> {target_node['name']} ({target_node['ip']})")
            logs.append(f"[IMPACT] Network link saturated. Bandwidth: {target_node['telemetry']['bandwidth_mbps']} Mbps. CPU: {target_node['telemetry']['cpu_utilization']}%")
            
            packet_traces.append({"from": entry_node, "to": "node_fw_perimeter", "type": "SYN_FLOOD", "color": "#FF3366"})
            packet_traces.append({"from": "node_fw_perimeter", "to": target_node_id, "type": "SYN_FLOOD", "color": "#FF3366"})
            compromised_nodes.append(target_node_id)

        elif attack_type == "Ransomware Propagation":
            entry_node = "node_workstation_user"
            entry_data = self.dt.get_node(entry_node)
            
            # Stage 1: Compromise user workstation via phishing
            entry_data["status"] = "compromised"
            entry_data["telemetry"]["cpu_utilization"] = 85.0
            logs.append(f"[INITIAL ACCESS] Phishing payload executed on {entry_data['name']} ({entry_data['ip']})")
            
            # Stage 2: Lateral movement to Admin workstation & AD
            ad_data = self.dt.get_node("node_active_directory")
            ad_data["status"] = "under_attack"
            logs.append(f"[LATERAL MOVEMENT] Pivoting from {entry_data['ip']} to Active Directory ({ad_data['ip']}) via Kerberoasting")
            
            # Stage 3: Target Database Encryption
            target_node["status"] = "compromised"
            target_node["telemetry"]["cpu_utilization"] = 96.5
            target_node["telemetry"]["ram_utilization"] = 92.0
            target_node["telemetry"]["error_rate"] = 0.25
            logs.append(f"[IMPACT] Ransomware strain encrypting PostgreSQL DB files on {target_node['name']}. VSS copies deleted.")
            
            packet_traces.append({"from": entry_node, "to": "node_fw_internal", "type": "SMB_EXPL", "color": "#FF3366"})
            packet_traces.append({"from": "node_fw_internal", "to": "node_active_directory", "type": "KERBEROS", "color": "#FF9900"})
            packet_traces.append({"from": "node_active_directory", "to": target_node_id, "type": "RANSOMWARE_ENCRYPT", "color": "#FF3366"})
            
            compromised_nodes.extend([entry_node, "node_active_directory", target_node_id])

        elif attack_type == "SSH Brute Force":
            entry_node = "node_fw_perimeter"
            target_node["status"] = "under_attack"
            target_node["telemetry"]["failed_logins"] = np.random.randint(18, 45)
            target_node["telemetry"]["cpu_utilization"] = 65.0
            
            logs.append(f"[RECON] Automated SSH password dictionary attack targeting {target_node['name']} port 22")
            logs.append(f"[INITIAL ACCESS] Failed auth threshold exceeded: {target_node['telemetry']['failed_logins']} attempts")
            
            if target_node["telemetry"]["failed_logins"] > 25:
                target_node["status"] = "compromised"
                logs.append(f"[PRIV_ESC] Valid root credential cracked! Attacker obtained interactive shell.")
                compromised_nodes.append(target_node_id)
                
            packet_traces.append({"from": entry_node, "to": target_node_id, "type": "SSH_BRUTE_FORCE", "color": "#FF9900"})

        elif attack_type in ["SQLi / RCE", "SQL Injection / RCE"]:
            entry_node = "node_fw_perimeter"
            target_node["status"] = "compromised"
            target_node["telemetry"]["error_rate"] = 0.45
            target_node["telemetry"]["packet_length_mean"] = 1350.0
            
            logs.append(f"[INITIAL ACCESS] Malicious HTTP GET payload with SQLi string sent to {target_node['name']}")
            logs.append(f"[PRIV_ESC] Remote Code Execution achieved via unsafe deserialization (CVE-2023-44487)")
            
            # Pivot to DB
            db_node = self.dt.get_node("node_db_prod")
            db_node["status"] = "under_attack"
            logs.append(f"[EXFILTRATION] Unauthorized SELECT queries extracting customer credentials from {db_node['name']}")
            
            packet_traces.append({"from": entry_node, "to": target_node_id, "type": "HTTP_SQLi", "color": "#FF3366"})
            packet_traces.append({"from": target_node_id, "to": "node_db_prod", "type": "DB_EXFIL", "color": "#FF3366"})
            compromised_nodes.extend([target_node_id, "node_db_prod"])

        else: # Generic / Port Scan / APT
            target_node["status"] = "under_attack"
            target_node["telemetry"]["syn_ratio"] = 0.88
            target_node["telemetry"]["error_rate"] = 0.55
            logs.append(f"[RECON] SYN Port Scan sweep across subnet 10.0.1.0/24 targeting {target_node['name']}")
            packet_traces.append({"from": "node_wan_gateway", "to": target_node_id, "type": "PORT_SCAN", "color": "#00F2FE"})
            compromised_nodes.append(target_node_id)

        # Recalculate digital twin risk score post-attack
        risk_summary = self.risk_assessor.evaluate_network_risk()
        
        return {
            "success": True,
            "attack_type": attack_type,
            "target_node": target_node_id,
            "target_node_name": target_node["name"],
            "stages": stages,
            "logs": logs,
            "packet_traces": packet_traces,
            "compromised_nodes": compromised_nodes,
            "post_attack_risk": risk_summary
        }
