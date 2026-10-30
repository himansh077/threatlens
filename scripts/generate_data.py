"""ThreatLens AI - Synthetic Network Traffic Generator.

================================================================================
DATASET PROVENANCE NOTICE:
This dataset consists entirely of SYNTHETIC DEMONSTRATION DATA generated for
academic evaluation and demonstration in the ThreatLens AI project. It does NOT
represent live enterprise traffic or proprietary telemetry.
================================================================================

Generator Parameters:
---------------------
- Total Flows: 12,000
- Random Seed: 42 (numpy.random.default_rng(42))
- Class Distribution Target:
    * normal:       75% (9,000 flows)
    * dos:          10% (1,200 flows)
    * port_scan:     7%   (840 flows)
    * brute_force:   5%   (600 flows)
    * probe:         3%   (360 flows)
    * Total Attack: 25% (3,000 flows)
- Realistic Difficulty & Overlap:
    * Stealthy Attacks: 8% of attack flows mimic benign parameter distributions
    * Bursty Benign: 5% of benign flows exhibit elevated transmission rates
    * Label Noise: 2% label perturbation to simulate real-world telemetry noise
- Mean Packet Sizes (src / dst bytes):
    * http:   400 / 900
    * https:  500 / 1000
    * dns:     80 / 150
    * ssh:    150 / 150
    * ftp:    200 / 1100
    * smtp:   600 / 150
    * other:  250 / 250
- Regression Target Relationship:
    * src_bytes = round(src_packets * S_src[service] * lognormal(0, 0.25))
    * dst_bytes = round(dst_packets * S_dst[service] * lognormal(0, 0.35))
    * total_bytes = src_bytes + dst_bytes
"""

import hashlib
import sys
from pathlib import Path
from typing import Dict, Tuple

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd

from src.config import RANDOM_SEED, TRAFFIC_CSV_PATH
from src.preprocessing import assign_split

# Mean packet sizes per service (bytes)
PACKET_SIZE_MEANS: Dict[str, Tuple[float, float]] = {
    "http": (400.0, 900.0),
    "https": (500.0, 1000.0),
    "dns": (80.0, 150.0),
    "ssh": (150.0, 150.0),
    "ftp": (200.0, 1100.0),
    "smtp": (600.0, 150.0),
    "other": (250.0, 250.0),
}


def generate_synthetic_dataset(
    n_flows: int = 12000,
    seed: int = RANDOM_SEED,
) -> pd.DataFrame:
    """Generate reproducible synthetic network traffic dataset with distinct yet overlapping signatures.

    Parameters
    ----------
    n_flows : int
        Total flow records to generate (default 12,000).
    seed : int
        Random seed for reproducibility.

    Returns
    -------
    pd.DataFrame
        Complete DataFrame with all required columns, split assignments, and provenance.
    """
    rng = np.random.default_rng(seed)

    # Calculate exact class flow counts
    n_normal = int(n_flows * 0.75)       # 9,000
    n_dos = int(n_flows * 0.10)          # 1,200
    n_port_scan = int(n_flows * 0.07)    # 840
    n_brute_force = int(n_flows * 0.05)  # 600
    n_probe = n_flows - (n_normal + n_dos + n_port_scan + n_brute_force)  # 360

    records = []

    # Helper function to create normal flow parameters
    def sample_normal_flow(is_bursty: bool = False, is_download: bool = False):
        protocol = rng.choice(["tcp", "udp"], p=[0.78, 0.22])
        if protocol == "udp":
            service = "dns"
            dst_port = 53
            state = "established"
            src_packets = rng.integers(1, 10)
            dst_packets = rng.integers(1, 12)
            duration = round(float(rng.uniform(0.01, 1.2)), 4)
            syn_flag_ratio = round(float(rng.uniform(0.0, 0.08)), 4)
            conn_rate = round(float(rng.uniform(1.0, 15.0)), 2)
        else:
            service = rng.choice(["https", "http", "smtp", "other", "ssh", "ftp"], p=[0.55, 0.25, 0.08, 0.07, 0.03, 0.02])
            port_map = {"https": 443, "http": 80, "smtp": 25, "ssh": 22, "ftp": 21, "other": int(rng.integers(1024, 65535))}
            dst_port = port_map[service]
            state = rng.choice(["established", "reset", "rejected"], p=[0.92, 0.05, 0.03])

            if is_download and service in ["http", "ftp"]:
                duration = round(float(rng.uniform(8.0, 120.0)), 4)
                src_packets = int(rng.integers(50, 400))
                dst_packets = int(rng.integers(2000, 15000))  # Heavy-tailed download
                conn_rate = round(float(rng.uniform(5.0, 30.0)), 2)
                syn_flag_ratio = round(float(rng.uniform(0.005, 0.05)), 4)
            elif is_bursty:
                duration = round(float(rng.uniform(0.5, 5.0)), 4)
                src_packets = int(rng.integers(80, 500))
                dst_packets = int(rng.integers(80, 600))
                conn_rate = round(float(rng.uniform(60.0, 180.0)), 2)  # Bursty benign rate
                syn_flag_ratio = round(float(rng.uniform(0.01, 0.10)), 4)
            else:
                duration = round(float(rng.exponential(scale=3.5) + 0.05), 4)
                src_packets = int(rng.integers(3, 80))
                dst_packets = int(rng.integers(2, 90))
                conn_rate = round(float(rng.uniform(1.0, 25.0)), 2)
                syn_flag_ratio = round(float(rng.uniform(0.01, 0.15)), 4)

        failed_logins = int(rng.choice([0, 1, 2], p=[0.97, 0.025, 0.005]))
        unique_dst_ports = 1 if rng.uniform() > 0.08 else 2
        ttl = int(rng.choice([64, 128, 255], p=[0.60, 0.35, 0.05]))
        return {
            "duration": max(0.001, duration),
            "protocol": protocol,
            "service": service,
            "state": state,
            "src_packets": src_packets,
            "dst_packets": dst_packets,
            "dst_port": dst_port,
            "ttl": ttl,
            "failed_logins": failed_logins,
            "syn_flag_ratio": syn_flag_ratio,
            "unique_dst_ports": unique_dst_ports,
            "conn_rate": conn_rate,
            "label": 0,
            "attack_type": "normal",
        }

    # 1. Generate Normal Flows (75% = 9,000)
    for _ in range(n_normal):
        is_bursty = rng.uniform() < 0.05     # 5% bursty benign flows
        is_download = rng.uniform() < 0.04   # 4% heavy-tailed downloads
        flow = sample_normal_flow(is_bursty=is_bursty, is_download=is_download)
        records.append(flow)

    # 2. Generate DoS Flows (10% = 1,200)
    # Signature: very high src_packets, tiny dst_packets, high conn_rate, high syn_flag_ratio, short duration, state=syn_sent
    for _ in range(n_dos):
        is_stealthy = rng.uniform() < 0.08  # 8% stealthy attacks
        if is_stealthy:
            flow = sample_normal_flow()
            flow["attack_type"] = "dos"
            flow["label"] = 1
        else:
            protocol = rng.choice(["tcp", "udp"], p=[0.90, 0.10])
            service = rng.choice(["http", "https", "dns", "other"], p=[0.40, 0.35, 0.10, 0.15])
            dst_port = 80 if service == "http" else (443 if service == "https" else (53 if service == "dns" else 8080))
            duration = round(float(rng.uniform(0.01, 1.5)), 4)
            src_packets = int(rng.integers(500, 5000))
            dst_packets = int(rng.integers(0, 6))
            conn_rate = round(float(rng.uniform(120.0, 950.0)), 2)
            syn_flag_ratio = round(float(rng.uniform(0.80, 1.00)), 4)
            state = "syn_sent" if protocol == "tcp" else "established"
            failed_logins = 0
            unique_dst_ports = int(rng.choice([1, 2, 3], p=[0.85, 0.10, 0.05]))
            ttl = int(rng.choice([64, 128, 255], p=[0.45, 0.45, 0.10]))
            flow = {
                "duration": duration,
                "protocol": protocol,
                "service": service,
                "state": state,
                "src_packets": src_packets,
                "dst_packets": dst_packets,
                "dst_port": dst_port,
                "ttl": ttl,
                "failed_logins": failed_logins,
                "syn_flag_ratio": syn_flag_ratio,
                "unique_dst_ports": unique_dst_ports,
                "conn_rate": conn_rate,
                "label": 1,
                "attack_type": "dos",
            }
        records.append(flow)

    # 3. Generate Port Scan Flows (7% = 840)
    # Signature: high unique_dst_ports, few packets, state rejected/reset
    for _ in range(n_port_scan):
        is_stealthy = rng.uniform() < 0.08
        if is_stealthy:
            flow = sample_normal_flow()
            flow["attack_type"] = "port_scan"
            flow["label"] = 1
        else:
            protocol = rng.choice(["tcp", "udp"], p=[0.85, 0.15])
            service = "other"
            dst_port = int(rng.integers(1, 65535))
            duration = round(float(rng.uniform(0.1, 4.0)), 4)
            src_packets = int(rng.integers(1, 8))
            dst_packets = int(rng.integers(0, 3))
            unique_dst_ports = int(rng.integers(35, 600))  # High unique dst ports
            conn_rate = round(float(rng.uniform(25.0, 160.0)), 2)
            syn_flag_ratio = round(float(rng.uniform(0.60, 0.95)), 4)
            state = rng.choice(["rejected", "reset"], p=[0.70, 0.30])
            failed_logins = 0
            ttl = int(rng.choice([64, 128, 255], p=[0.50, 0.40, 0.10]))
            flow = {
                "duration": duration,
                "protocol": protocol,
                "service": service,
                "state": state,
                "src_packets": src_packets,
                "dst_packets": dst_packets,
                "dst_port": dst_port,
                "ttl": ttl,
                "failed_logins": failed_logins,
                "syn_flag_ratio": syn_flag_ratio,
                "unique_dst_ports": unique_dst_ports,
                "conn_rate": conn_rate,
                "label": 1,
                "attack_type": "port_scan",
            }
        records.append(flow)

    # 4. Generate Brute Force Flows (5% = 600)
    # Signature: service ssh/ftp, high failed_logins, moderate conn_rate
    for _ in range(n_brute_force):
        is_stealthy = rng.uniform() < 0.08
        if is_stealthy:
            flow = sample_normal_flow()
            flow["attack_type"] = "brute_force"
            flow["label"] = 1
        else:
            protocol = "tcp"
            service = rng.choice(["ssh", "ftp"], p=[0.70, 0.30])
            dst_port = 22 if service == "ssh" else 21
            duration = round(float(rng.uniform(2.0, 45.0)), 4)
            failed_logins = int(rng.integers(5, 45))  # High failed logins
            src_packets = int(failed_logins * rng.integers(3, 7))
            dst_packets = int(failed_logins * rng.integers(2, 6))
            conn_rate = round(float(rng.uniform(8.0, 50.0)), 2)
            syn_flag_ratio = round(float(rng.uniform(0.10, 0.35)), 4)
            state = rng.choice(["reset", "established"], p=[0.65, 0.35])
            unique_dst_ports = 1
            ttl = int(rng.choice([64, 128], p=[0.65, 0.35]))
            flow = {
                "duration": duration,
                "protocol": protocol,
                "service": service,
                "state": state,
                "src_packets": src_packets,
                "dst_packets": dst_packets,
                "dst_port": dst_port,
                "ttl": ttl,
                "failed_logins": failed_logins,
                "syn_flag_ratio": syn_flag_ratio,
                "unique_dst_ports": unique_dst_ports,
                "conn_rate": conn_rate,
                "label": 1,
                "attack_type": "brute_force",
            }
        records.append(flow)

    # 5. Generate Probe Flows (3% = 360)
    # Signature: icmp or low-rate multi-port, moderate unique_dst_ports
    for _ in range(n_probe):
        is_stealthy = rng.uniform() < 0.08
        if is_stealthy:
            flow = sample_normal_flow()
            flow["attack_type"] = "probe"
            flow["label"] = 1
        else:
            protocol = rng.choice(["icmp", "tcp", "udp"], p=[0.50, 0.35, 0.15])
            service = "other" if protocol == "icmp" else rng.choice(["dns", "http", "other"])
            dst_port = 0 if protocol == "icmp" else int(rng.integers(1, 1024))
            duration = round(float(rng.uniform(0.5, 12.0)), 4)
            src_packets = int(rng.integers(2, 20))
            dst_packets = int(rng.integers(1, 15))
            unique_dst_ports = int(rng.integers(4, 30))  # Moderate unique dst ports
            conn_rate = round(float(rng.uniform(0.5, 12.0)), 2)
            syn_flag_ratio = round(float(rng.uniform(0.10, 0.50)), 4)
            state = rng.choice(["established", "reset", "rejected"], p=[0.40, 0.40, 0.20])
            failed_logins = 0
            ttl = int(rng.choice([64, 255], p=[0.70, 0.30]))
            flow = {
                "duration": duration,
                "protocol": protocol,
                "service": service,
                "state": state,
                "src_packets": src_packets,
                "dst_packets": dst_packets,
                "dst_port": dst_port,
                "ttl": ttl,
                "failed_logins": failed_logins,
                "syn_flag_ratio": syn_flag_ratio,
                "unique_dst_ports": unique_dst_ports,
                "conn_rate": conn_rate,
                "label": 1,
                "attack_type": "probe",
            }
        records.append(flow)

    # Shuffle the records deterministically
    rng.shuffle(records)

    df = pd.DataFrame(records)

    # Apply 2% label noise (realistic telemetry noise)
    noise_mask = rng.uniform(size=len(df)) < 0.02
    df.loc[noise_mask, "label"] = 1 - df.loc[noise_mask, "label"]

    # Compute regression targets (bytes) based on specification
    # src_bytes = src_packets * S_src[service] * lognormal(0, 0.25)
    # dst_bytes = dst_packets * S_dst[service] * lognormal(0, 0.35)
    # total_bytes = round(src_bytes + dst_bytes)
    src_bytes_list = []
    dst_bytes_list = []
    total_bytes_list = []

    for _, row in df.iterrows():
        s_src, s_dst = PACKET_SIZE_MEANS.get(row["service"], (250.0, 250.0))
        # lognormal(0, sigma)
        mult_src = float(rng.lognormal(mean=0.0, sigma=0.25))
        mult_dst = float(rng.lognormal(mean=0.0, sigma=0.35))
        sb = int(max(0, round(row["src_packets"] * s_src * mult_src)))
        db = int(max(0, round(row["dst_packets"] * s_dst * mult_dst)))
        tb = sb + db
        src_bytes_list.append(sb)
        dst_bytes_list.append(db)
        total_bytes_list.append(tb)

    df["src_bytes"] = src_bytes_list
    df["dst_bytes"] = dst_bytes_list
    df["total_bytes"] = total_bytes_list

    # Assign unique record_id ("TL-000001" style)
    df["record_id"] = [f"TL-{i+1:06d}" for i in range(len(df))]

    # Provenance source marker
    df["source"] = "synthetic"

    # Deterministic stratified train/test split
    df = assign_split(df, test_size=0.2, random_state=seed)

    # Reorder columns to standard order
    columns_order = [
        "record_id",
        "duration",
        "protocol",
        "service",
        "state",
        "src_packets",
        "dst_packets",
        "dst_port",
        "ttl",
        "failed_logins",
        "syn_flag_ratio",
        "unique_dst_ports",
        "conn_rate",
        "src_bytes",
        "dst_bytes",
        "total_bytes",
        "label",
        "attack_type",
        "split",
        "source",
    ]
    df = df[columns_order]
    return df


def calculate_file_sha256(file_path: Path) -> str:
    """Calculate SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def main() -> None:
    """Generate dataset, validate, output hash and class distribution, and save CSV."""
    print("=" * 70)
    print("THREATLENS AI: Generating Synthetic Demonstration Traffic Dataset")
    print("=" * 70)

    df = generate_synthetic_dataset(n_flows=12000, seed=RANDOM_SEED)

    # Save to data/traffic.csv
    TRAFFIC_CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(TRAFFIC_CSV_PATH, index=False)

    file_hash = calculate_file_sha256(TRAFFIC_CSV_PATH)

    print(f"\nGenerated flows: {len(df):,}")
    print(f"File saved to:   {TRAFFIC_CSV_PATH}")
    print(f"SHA-256 Hash:    {file_hash}")

    print("\n--- ATTACK TYPE DISTRIBUTION ---")
    attack_dist = df["attack_type"].value_counts()
    for atype, count in attack_dist.items():
        pct = (count / len(df)) * 100
        print(f"  {atype:<15}: {count:>5} ({pct:>5.2f}%)")

    print("\n--- BINARY LABEL DISTRIBUTION ---")
    label_dist = df["label"].value_counts()
    for lbl, count in label_dist.items():
        desc = "Benign (0)" if lbl == 0 else "Attack (1)"
        pct = (count / len(df)) * 100
        print(f"  {desc:<15}: {count:>5} ({pct:>5.2f}%)")

    print("\n--- SPLIT DISTRIBUTION ---")
    split_dist = df["split"].value_counts()
    for sp, count in split_dist.items():
        pct = (count / len(df)) * 100
        print(f"  {sp:<15}: {count:>5} ({pct:>5.2f}%)")

    # Generate sample_input.json for predict.py testing
    from src.config import SAMPLE_INPUT_JSON_PATH, CLASSIFIER_FEATURES
    sample_row = df[CLASSIFIER_FEATURES].iloc[0].to_dict()
    import json
    with open(SAMPLE_INPUT_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(sample_row, f, indent=2)
    print(f"Sample input saved to: {SAMPLE_INPUT_JSON_PATH}")

    # Validate generated frame
    from src.data_loader import validate_frame
    validate_frame(df)
    print("\n[ACCEPTANCE CHECK] validate_frame passed successfully.")
    print("=" * 70)


if __name__ == "__main__":
    main()
