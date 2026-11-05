"""
EVSentinel Layer 2: CAN Bus Intrusion Detection System
========================================================
Datasets: Real Physical Vehicle Logs (Opel Astra, Renault Clio, VW Prototype) + HCRL Car-Hacking
Attacks: DoS (0x000), Fuzzy Payload, Fuzzy CAN-ID, RPM Spoofing (0x0316),
         Gear Spoofing (0x043F), Speedometer Spoofing (0x05A0),
         Replay Burst Stream (0x01A1/0x02C6), Diagnostic UDS (0x7DF/0x7E0)
Methodology: 24 Engineered Physical Features -> Regularized Logistic Regression + Isolation Forest
"""

import os
import re
import time
import joblib
import warnings
import numpy as np
import pandas as pd

warnings.filterwarnings('ignore')

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "can_bus_model")
os.makedirs(MODEL_DIR, exist_ok=True)

CAN_COLUMNS = [
    "timestamp", "can_id", "dlc",
    "data0", "data1", "data2", "data3",
    "data4", "data5", "data6", "data7",
    "label"
]


def load_can_csv(filepath, attack_label, sample_n=30000):
    """Load standard CSV CAN dataset file."""
    print(f"  Loading {os.path.basename(filepath)}...", end=" ")
    df = pd.read_csv(filepath, header=None, names=CAN_COLUMNS)
    df["attack_type"] = df["label"].apply(
        lambda x: "normal" if str(x).strip().upper() == "R" else attack_label
    )
    if len(df) > sample_n:
        normal = df[df["attack_type"] == "normal"]
        attack = df[df["attack_type"] != "normal"]
        n_norm = min(len(normal), sample_n // 2)
        n_att = min(len(attack), sample_n // 2)
        df = pd.concat([normal.sample(n=n_norm, random_state=42), attack.sample(n=n_att, random_state=42)], ignore_index=True)
    print(f"({len(df)} rows)")
    return df


load_can_dataset = load_can_csv


def parse_candump_line(line):
    """Parses SocketCAN candump lines."""
    m = re.match(r'\s*\(([\d.]+)\)\s+\w+\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]*)', line.strip())
    if not m:
        return None
    ts = float(m.group(1))
    can_id_hex = m.group(2)
    payload_hex = m.group(3)
    dlc = len(payload_hex) // 2
    data_bytes = []
    for i in range(0, min(16, len(payload_hex)), 2):
        data_bytes.append(payload_hex[i:i+2])
    while len(data_bytes) < 8:
        data_bytes.append("00")
    return [ts, can_id_hex, dlc] + data_bytes[:8] + ["T"]


def load_candump_log(filepath, attack_label, filter_condition=None, sample_n=10000):
    """Parses and loads a candump log file."""
    if not os.path.exists(filepath):
        return None
    print(f"  Loading {os.path.basename(filepath)} ({attack_label})...", end=" ")
    rows = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if filter_condition and not filter_condition(line):
                continue
            parsed = parse_candump_line(line)
            if parsed:
                rows.append(parsed)
                if len(rows) >= sample_n:
                    break
    if not rows:
        print("(0 rows)")
        return None
    df = pd.DataFrame(rows, columns=CAN_COLUMNS)
    df["attack_type"] = attack_label
    print(f"({len(df)} rows)")
    return df


def merge_all_datasets():
    """Merge all CAN bus attack datasets across HCRL + Opel Astra, Renault Clio & VW Prototype."""
    print("\n" + "=" * 65)
    print("  STEP 1: IN-VEHICLE CAN BUS DATASET INGESTION & CONSOLIDATION")
    print("=" * 65)
    
    datasets = []
    
    # 1. HCRL Physical Datasets
    if os.path.exists("DoS_dataset.csv"):
        datasets.append(load_can_csv("DoS_dataset.csv", "dos_flooding", sample_n=25000))
    if os.path.exists("Fuzzy_dataset.csv"):
        datasets.append(load_can_csv("Fuzzy_dataset.csv", "fuzzy_payload", sample_n=25000))
    if os.path.exists("RPM_dataset.csv"):
        datasets.append(load_can_csv("RPM_dataset.csv", "rpm_spoofing", sample_n=25000))
    if os.path.exists("gear_dataset.csv"):
        datasets.append(load_can_csv("gear_dataset.csv", "gear_spoofing", sample_n=25000))
        
    # 2. TU/e Real Physical Vehicle Logs (Opel, Renault, Prototype)
    # Speedometer Spoofing (Prototype)
    p_spoof = os.path.join(BASE_DIR, "Prototype", "spoofing_speedometer.log")
    if os.path.exists(p_spoof):
        df_sp = load_candump_log(p_spoof, "speedometer_spoofing", lambda l: " 5A0#01807E" in l, sample_n=5000)
        if df_sp is not None: datasets.append(df_sp)
        
    # Diagnostic UDS Overrides (Opel & Renault)
    for v in ["OpelAstra", "RenaultClio", "Prototype"]:
        p_diag = os.path.join(BASE_DIR, v, "diagnostic.log")
        if os.path.exists(p_diag):
            df_dg = load_candump_log(p_diag, "diagnostic_uds", lambda l: any(x in l for x in [' 760#', ' 7E0#', ' 726#']), sample_n=3000)
            if df_dg is not None: datasets.append(df_dg)
            
    # Fuzzy CAN-ID Injection
    for v in ["OpelAstra", "RenaultClio", "Prototype"]:
        p_fuzz = os.path.join(BASE_DIR, v, "fuzzing_canid.log")
        if os.path.exists(p_fuzz):
            df_fc = load_candump_log(p_fuzz, "fuzzy_canid", lambda l: any(x in l for x in [' 111#', ' 222#', ' 333#', ' 444#']), sample_n=3000)
            if df_fc is not None: datasets.append(df_fc)
            
    # Replay Bursts (Opel & Renault)
    for v in ["OpelAstra", "RenaultClio"]:
        p_rep = os.path.join(BASE_DIR, v, "replay.log")
        if os.path.exists(p_rep):
            df_rp = load_candump_log(p_rep, "replay_burst", lambda l: " 1A1#000041407D" in l or " 2C6#FFFFFF" in l, sample_n=3000)
            if df_rp is not None: datasets.append(df_rp)
            
    # Baseline Normal Driving (Opel & Renault)
    for v in ["OpelAstra", "RenaultClio"]:
        p_tr = os.path.join(BASE_DIR, v, "training.log")
        if os.path.exists(p_tr):
            df_norm = load_candump_log(p_tr, "normal", sample_n=10000)
            if df_norm is not None: datasets.append(df_norm)

    merged = pd.concat(datasets, ignore_index=True)
    print(f"\n  Total Merged Dataset: {len(merged):,} frames")
    print(f"  Multi-Class Distribution across Physical Vehicles:\n{merged['attack_type'].value_counts().to_string()}")
    return merged


def hex_to_int(val):
    try:
        return int(str(val).strip(), 16)
    except (ValueError, TypeError):
        return 0


def engineer_can_features(df):
    """Engineers 24 physical and statistical signals from CAN frames."""
    print("\n" + "=" * 65)
    print("  STEP 2: 24-FEATURE PHYSICAL SIGNAL EXTRACTION")
    print("=" * 65)
    
    df["can_id_int"] = df["can_id"].apply(hex_to_int)
    for i in range(8):
        df[f"data{i}_int"] = df[f"data{i}"].apply(hex_to_int)
        
    df["dlc"] = pd.to_numeric(df["dlc"], errors="coerce").fillna(8).astype(int)
    df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce").fillna(0.0)
    
    data_cols = [f"data{i}_int" for i in range(8)]
    payload_matrix = df[data_cols].values
    
    df["payload_sum"] = payload_matrix.sum(axis=1)
    df["payload_mean"] = payload_matrix.mean(axis=1)
    df["payload_std"] = payload_matrix.std(axis=1)
    df["payload_min"] = payload_matrix.min(axis=1)
    df["payload_max"] = payload_matrix.max(axis=1)
    df["payload_range"] = df["payload_max"] - df["payload_min"]
    
    df["zero_byte_count"] = (payload_matrix == 0).sum(axis=1)
    df["max_byte_count"] = (payload_matrix == 255).sum(axis=1)
    
    def calc_entropy(row):
        _, counts = np.unique(row, return_counts=True)
        probs = counts / len(row)
        return -np.sum(probs * np.log2(probs + 1e-12))
        
    df["payload_entropy"] = np.apply_along_axis(calc_entropy, 1, payload_matrix)
    df["inter_arrival_time"] = df["timestamp"].diff().fillna(0.001).clip(0.0, 10.0)
    df["can_id_frequency"] = df.groupby("can_id_int")["timestamp"].transform("count") / len(df)
    
    df["hamming_weight"] = np.vectorize(lambda x: bin(x).count('1'))(payload_matrix).sum(axis=1)
    
    delta_payload = df["payload_sum"].diff().fillna(0)
    delta_t = df["inter_arrival_time"].replace(0, 1e-6)
    df["payload_gradient"] = (delta_payload / delta_t).clip(-1e6, 1e6)
    df["is_diagnostic_id"] = ((df["can_id_int"] >= 0x7DF) & (df["can_id_int"] <= 0x7FF)).astype(int)
    
    feature_cols = [
        "can_id_int", "dlc",
        "data0_int", "data1_int", "data2_int", "data3_int",
        "data4_int", "data5_int", "data6_int", "data7_int",
        "payload_sum", "payload_mean", "payload_std",
        "payload_min", "payload_max", "payload_range",
        "zero_byte_count", "max_byte_count",
        "payload_entropy", "inter_arrival_time",
        "can_id_frequency", "hamming_weight",
        "payload_gradient", "is_diagnostic_id"
    ]
    print(f"  Extracted {len(feature_cols)} physical features.")
    return df, feature_cols


def train_can_models(df, feature_cols):
    """Trains and serializes the multi-class CAN IDS model bundle."""
    print("\n" + "=" * 65)
    print("  STEP 3: MULTI-CLASS ML MODEL TRAINING & EVALUATION")
    print("=" * 65)
    
    X = df[feature_cols].values
    y_raw = df["attack_type"].values
    
    le = LabelEncoder()
    y = le.fit_transform(y_raw)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print("[*] Training Regularized Multi-Class Logistic Regression (C=0.5)...")
    t0 = time.time()
    clf = LogisticRegression(C=0.5, max_iter=250, solver="lbfgs", random_state=42)
    clf.fit(X_train_scaled, y_train)
    train_time = time.time() - t0
    
    # Measure Inference Latency
    t1 = time.time()
    y_pred = clf.predict(X_test_scaled)
    total_inf_time = time.time() - t1
    latency_us = (total_inf_time / len(X_test_scaled)) * 1_000_000.0
    
    acc = accuracy_score(y_test, y_pred) * 100.0
    
    print("\n" + "=" * 85)
    print(f"  EVSENTINEL CAN BUS MULTI-CLASS CLASSIFICATION REPORT (ACCURACY: {acc:.2f}%)")
    print(f"  Inference Latency: {latency_us:.2f} microseconds / frame | Training Time: {train_time:.2f}s")
    print("=" * 85)
    print(classification_report(y_test, y_pred, target_names=le.classes_, digits=4))
    print("=" * 85)
    
    # Train Unsupervised Isolation Forest for Zero-Day Anomaly Detection
    print("\n[*] Training Isolation Forest on normal driving baseline...")
    iso = IsolationForest(n_estimators=100, contamination=0.005, random_state=42, n_jobs=-1)
    normal_idx = (y_train == le.transform(["normal"])[0])
    iso.fit(X_train_scaled[normal_idx])
    
    # Save Model Bundle
    bundle = {
        "model": clf,
        "scaler": scaler,
        "label_encoder": le,
        "isolation_forest": iso,
        "feature_cols": feature_cols,
        "feature_columns": feature_cols,
        "anomaly_threshold": -0.1,
        "classes": list(le.classes_),
        "accuracy": acc,
        "latency_us": latency_us
    }
    bundle_path = os.path.join(MODEL_DIR, "can_bus_bundle.joblib")
    joblib.dump(bundle, bundle_path)
    print(f"[+] Multi-class CAN model bundle saved to: {bundle_path}")
    return bundle


def main():
    merged_df = merge_all_datasets()
    feat_df, feature_cols = engineer_can_features(merged_df)
    train_can_models(feat_df, feature_cols)


if __name__ == "__main__":
    main()
