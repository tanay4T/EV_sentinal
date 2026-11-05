"""
EVSentinel Layer 2: CAN Bus — Pure HCRL Car-1 Benchmark Evaluation
===================================================================
Dataset: Pure HCRL Car-Hacking Dataset (Korea University) — Zero Synthetic Data
Attacks Evaluated:
  1. DoS Flooding Attack (0x000)
  2. Fuzzy High-Entropy Payload Attack (0xFF)
  3. RPM & Motor Tachometer Spoofing (0x0316)
  4. Transmission Gear Position Spoofing (0x043F)
  5. Normal Driving Baseline (Safe)

Usage:
    python can_bus_eval.py
"""

import os
import time
import warnings
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

warnings.filterwarnings('ignore')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CAN_COLUMNS = [
    "timestamp", "can_id", "dlc",
    "data0", "data1", "data2", "data3",
    "data4", "data5", "data6", "data7",
    "label"
]


def hex_to_int(val):
    try:
        return int(str(val).strip(), 16)
    except (ValueError, TypeError):
        return 0


def load_hcrl_datasets(sample_per_attack=25000):
    """Loads pure HCRL Car-1 physical datasets."""
    print("=" * 80)
    print("  EVSENTINEL LAYER 2: PURE HCRL CAR-1 CAN BUS EVALUATION")
    print("  (Korea University Benchmark — 100% Real Physical Vehicle Logs)")
    print("=" * 80)
    
    attack_files = {
        "DoS_dataset.csv": "dos_flooding",
        "Fuzzy_dataset.csv": "fuzzy_payload",
        "RPM_dataset.csv": "rpm_spoofing",
        "gear_dataset.csv": "gear_spoofing"
    }
    
    dfs = []
    for filename, label in attack_files.items():
        filepath = os.path.join(BASE_DIR, filename)
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Missing required HCRL dataset: {filepath}")
            
        print(f"[*] Loading HCRL {filename} ({label})...", end=" ")
        df = pd.read_csv(filepath, header=None, names=CAN_COLUMNS)
        df["attack_type"] = df["label"].apply(
            lambda x: "normal" if str(x).strip().upper() == "R" else label
        )
        
        normal_sub = df[df["attack_type"] == "normal"]
        attack_sub = df[df["attack_type"] != "normal"]
        
        n_norm = min(len(normal_sub), sample_per_attack)
        n_att = min(len(attack_sub), sample_per_attack)
        
        sampled = pd.concat([
            normal_sub.sample(n=n_norm, random_state=42),
            attack_sub.sample(n=n_att, random_state=42)
        ], ignore_index=True)
        
        print(f"({len(sampled):,} frames: {n_norm:,} normal + {n_att:,} {label})")
        dfs.append(sampled)
        
    merged = pd.concat(dfs, ignore_index=True)
    print(f"\n[+] Total Pure HCRL Dataset Loaded: {len(merged):,} frames")
    print(f"[+] Class Distribution:\n{merged['attack_type'].value_counts().to_string()}\n")
    return merged


def engineer_hcrl_features(df):
    """Extracts 22 physical CAN signals from raw frames."""
    print("[*] Extracting physical signals (Entropy, Inter-arrival Delta, Hamming Weights)...")
    
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
    
    # Shannon Payload Entropy
    def row_entropy(row):
        _, counts = np.unique(row, return_counts=True)
        probs = counts / len(row)
        return -np.sum(probs * np.log2(probs + 1e-12))
        
    df["payload_entropy"] = np.apply_along_axis(row_entropy, 1, payload_matrix)
    df["inter_arrival_time"] = df["timestamp"].diff().fillna(0.001).clip(0.0, 10.0)
    df["can_id_frequency"] = df.groupby("can_id_int")["timestamp"].transform("count") / len(df)
    df["hamming_weight"] = np.vectorize(lambda x: bin(x).count('1'))(payload_matrix).sum(axis=1)
    
    feature_cols = [
        "can_id_int", "dlc",
        "data0_int", "data1_int", "data2_int", "data3_int",
        "data4_int", "data5_int", "data6_int", "data7_int",
        "payload_sum", "payload_mean", "payload_std",
        "payload_min", "payload_max", "payload_range",
        "zero_byte_count", "max_byte_count",
        "payload_entropy", "inter_arrival_time",
        "can_id_frequency", "hamming_weight"
    ]
    return df, feature_cols


def run_evaluation():
    raw_df = load_hcrl_datasets(sample_per_attack=25000)
    feat_df, feature_cols = engineer_hcrl_features(raw_df)
    
    X = feat_df[feature_cols].values
    y_raw = feat_df["attack_type"].values
    
    le = LabelEncoder()
    y = le.fit_transform(y_raw)
    
    # 75% Train, 25% Test Stratified Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print("[*] Training Multi-Class Logistic Regression Model (C=0.5, L-BFGS)...")
    t0 = time.time()
    clf = LogisticRegression(C=0.5, max_iter=500, solver="lbfgs", random_state=42)
    clf.fit(X_train_scaled, y_train)
    train_time = time.time() - t0
    
    # Measure Inference Latency
    t1 = time.time()
    y_pred = clf.predict(X_test_scaled)
    total_inf_time = time.time() - t1
    latency_us = (total_inf_time / len(X_test_scaled)) * 1_000_000.0
    
    acc = accuracy_score(y_test, y_pred) * 100.0
    
    print("\n" + "=" * 85)
    print(f"  PURE HCRL CAR-1 ML EVALUATION RESULTS")
    print(f"  Overall Accuracy : {acc:.2f}%")
    print(f"  Inference Latency: {latency_us:.2f} microseconds / frame")
    print(f"  Throughput       : {len(X_test_scaled)/total_inf_time:,.0f} frames / second")
    print(f"  Training Time    : {train_time:.2f} seconds (N = {len(X_train):,} training frames)")
    print("=" * 85)
    
    # Detailed Attack Breakdown Table
    report_dict = classification_report(
        le.inverse_transform(y_test),
        le.inverse_transform(y_pred),
        output_dict=True
    )
    
    severity_map = {
        "normal": "Low (Safe)",
        "dos_flooding": "Critical (Freeze)",
        "rpm_spoofing": "Critical (Torque)",
        "gear_spoofing": "Critical (Shift Lock)",
        "fuzzy_payload": "High (Crash State)"
    }
    
    print(f"{'Attack Category':<20} | {'Severity':<22} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Test Frames'}")
    print("-" * 85)
    for cls_name in le.classes_:
        r = report_dict[cls_name]
        sev = severity_map.get(cls_name, "Medium")
        print(f"{cls_name:<20} | {sev:<22} | {r['precision']*100:>8.2f}% | {r['recall']*100:>8.2f}% | {r['f1-score']:>9.4f} | {r['support']:>10,}")
    print("-" * 85)
    print(f"{'WEIGHTED AVERAGE':<20} | {'-':<22} | {report_dict['weighted avg']['precision']*100:>8.2f}% | {report_dict['weighted avg']['recall']*100:>8.2f}% | {report_dict['weighted avg']['f1-score']:>9.4f} | {len(y_test):>10,}")
    print("=" * 85)
    
    # Confusion Matrix
    print("\nConfusion Matrix (Ground Truth Rows x Predicted Columns):")
    print(f"Classes: {list(le.classes_)}")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    print("\n" + "=" * 85)
    print("  PURE HCRL CAR-1 EVALUATION COMPLETED SUCCESSFULLY")
    print("=" * 85)


if __name__ == "__main__":
    run_evaluation()
