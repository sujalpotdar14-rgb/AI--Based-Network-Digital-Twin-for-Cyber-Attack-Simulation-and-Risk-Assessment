import numpy as np
import pandas as pd
import os

def generate_network_telemetry_dataset(num_samples=6000, random_seed=42):
    """
    Generates a realistic synthetic network telemetry dataset for AI-based 
    cyber threat detection and risk assessment in a Digital Twin environment.
    """
    np.random.seed(random_seed)
    
    classes = [
        "Normal",
        "DDoS SYN Flood",
        "Ransomware Propagation",
        "Man-in-the-Middle (MitM)",
        "SSH Brute Force",
        "SQLi / RCE",
        "Port Scanning"
    ]
    
    # Target class distribution
    class_probs = [0.45, 0.12, 0.08, 0.08, 0.10, 0.07, 0.10]
    labels = np.random.choice(classes, size=num_samples, p=class_probs)
    
    data = []
    
    for label in labels:
        if label == "Normal":
            flow_duration = np.random.uniform(0.1, 15.0)
            total_fwd_packets = np.random.randint(5, 120)
            total_bwd_packets = np.random.randint(5, 120)
            packet_length_mean = np.random.uniform(300, 1200)
            syn_flag_ratio = np.random.uniform(0.01, 0.15)
            error_rate = np.random.uniform(0.0, 0.03)
            failed_logins = np.random.choice([0, 1], p=[0.98, 0.02])
            cvss_score = np.random.uniform(1.0, 5.0)
            asset_criticality = np.random.uniform(1.0, 3.5)
            node_centrality = np.random.uniform(0.1, 0.6)
            port_entropy = np.random.uniform(0.1, 0.8)
            
        elif label == "DDoS SYN Flood":
            flow_duration = np.random.uniform(0.001, 2.0)
            total_fwd_packets = np.random.randint(1000, 8000)
            total_bwd_packets = np.random.randint(0, 10)
            packet_length_mean = np.random.uniform(40, 120)
            syn_flag_ratio = np.random.uniform(0.85, 1.0)
            error_rate = np.random.uniform(0.3, 0.85)
            failed_logins = 0
            cvss_score = np.random.uniform(4.0, 8.5)
            asset_criticality = np.random.uniform(3.0, 5.0)
            node_centrality = np.random.uniform(0.5, 0.95)
            port_entropy = np.random.uniform(0.0, 0.3)
            
        elif label == "Ransomware Propagation":
            flow_duration = np.random.uniform(5.0, 45.0)
            total_fwd_packets = np.random.randint(300, 2500)
            total_bwd_packets = np.random.randint(200, 2000)
            packet_length_mean = np.random.uniform(900, 1450) # Heavy payload transfer / encrypted SMB
            syn_flag_ratio = np.random.uniform(0.05, 0.2)
            error_rate = np.random.uniform(0.05, 0.25)
            failed_logins = np.random.randint(1, 15)
            cvss_score = np.random.uniform(7.5, 10.0)
            asset_criticality = np.random.uniform(4.0, 5.0) # Targeting high value storage/DB
            node_centrality = np.random.uniform(0.6, 0.9)
            port_entropy = np.random.uniform(0.2, 1.2)
            
        elif label == "Man-in-the-Middle (MitM)":
            flow_duration = np.random.uniform(10.0, 60.0)
            total_fwd_packets = np.random.randint(150, 800)
            total_bwd_packets = np.random.randint(150, 800)
            packet_length_mean = np.random.uniform(400, 950)
            syn_flag_ratio = np.random.uniform(0.02, 0.1)
            error_rate = np.random.uniform(0.15, 0.45) # Packet duplication/latency jitter
            failed_logins = 0
            cvss_score = np.random.uniform(5.0, 8.0)
            asset_criticality = np.random.uniform(2.5, 4.5)
            node_centrality = np.random.uniform(0.4, 0.8)
            port_entropy = np.random.uniform(0.1, 0.5)
            
        elif label == "SSH Brute Force":
            flow_duration = np.random.uniform(1.0, 30.0)
            total_fwd_packets = np.random.randint(100, 900)
            total_bwd_packets = np.random.randint(80, 800)
            packet_length_mean = np.random.uniform(120, 350)
            syn_flag_ratio = np.random.uniform(0.2, 0.5)
            error_rate = np.random.uniform(0.1, 0.3)
            failed_logins = np.random.randint(8, 45) # High failed logins
            cvss_score = np.random.uniform(6.0, 9.0)
            asset_criticality = np.random.uniform(2.0, 4.0)
            node_centrality = np.random.uniform(0.3, 0.7)
            port_entropy = np.random.uniform(0.0, 0.2)
            
        elif label == "SQLi / RCE":
            flow_duration = np.random.uniform(0.05, 5.0)
            total_fwd_packets = np.random.randint(15, 120)
            total_bwd_packets = np.random.randint(10, 100)
            packet_length_mean = np.random.uniform(700, 1400) # Malicious HTTP payload
            syn_flag_ratio = np.random.uniform(0.05, 0.25)
            error_rate = np.random.uniform(0.1, 0.5) # 500 server errors
            failed_logins = np.random.randint(0, 5)
            cvss_score = np.random.uniform(8.0, 10.0)
            asset_criticality = np.random.uniform(3.5, 5.0)
            node_centrality = np.random.uniform(0.5, 0.85)
            port_entropy = np.random.uniform(0.1, 0.4)
            
        elif label == "Port Scanning":
            flow_duration = np.random.uniform(0.01, 1.5)
            total_fwd_packets = np.random.randint(50, 400)
            total_bwd_packets = np.random.randint(0, 30)
            packet_length_mean = np.random.uniform(40, 90)
            syn_flag_ratio = np.random.uniform(0.6, 0.95)
            error_rate = np.random.uniform(0.4, 0.9) # RST / unreached ports
            failed_logins = 0
            cvss_score = np.random.uniform(2.0, 6.0)
            asset_criticality = np.random.uniform(1.0, 3.0)
            node_centrality = np.random.uniform(0.1, 0.5)
            port_entropy = np.random.uniform(2.5, 3.9) # High port entropy
            
        data.append({
            "flow_duration": round(float(flow_duration), 4),
            "total_fwd_packets": int(total_fwd_packets),
            "total_bwd_packets": int(total_bwd_packets),
            "packet_length_mean": round(float(packet_length_mean), 2),
            "syn_flag_ratio": round(float(syn_flag_ratio), 4),
            "error_rate": round(float(error_rate), 4),
            "failed_logins": int(failed_logins),
            "cvss_score": round(float(cvss_score), 2),
            "asset_criticality": round(float(asset_criticality), 2),
            "node_centrality": round(float(node_centrality), 4),
            "port_entropy": round(float(port_entropy), 4),
            "label": label
        })

    df = pd.DataFrame(data)
    output_dir = os.path.join(os.path.dirname(__file__), "..", "data")
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, "network_telemetry.csv")
    df.to_csv(filepath, index=False)
    print(f"[+] Dataset successfully generated: {filepath} ({len(df)} samples)")
    return df

if __name__ == "__main__":
    generate_network_telemetry_dataset()
