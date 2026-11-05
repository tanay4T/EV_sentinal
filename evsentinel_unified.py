"""
EVSentinel Unified Detection Engine
=====================================
Integrates Layer 1 (Charging Station Telematics) + Layer 2 (Vehicle CAN Bus)
into a single generalized security interface.

Usage:
    python evsentinel_unified.py
"""

import joblib
import numpy as np
import pandas as pd
import json
import os
import warnings
warnings.filterwarnings('ignore')


# ─── Model Paths ─────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TELEMATICS_MODEL = os.path.join(BASE_DIR, "generalized_telematics_model", "generalized_bundle.joblib")
CAN_BUS_MODEL = os.path.join(BASE_DIR, "can_bus_model", "can_bus_bundle.joblib")

# ─── In-Memory Model Cache ────────────────────────────────────────────
_MODEL_CACHE = {
    "telematics": None,
    "can_bus": None
}


def load_telematics_bundle(path=TELEMATICS_MODEL, reload=False):
    """Load and cache the Layer 1 telematics model bundle in memory."""
    global _MODEL_CACHE
    if _MODEL_CACHE["telematics"] is None or reload:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Telematics model bundle not found at: {path}")
        bundle = joblib.load(path)
        _MODEL_CACHE["telematics"] = bundle
    return _MODEL_CACHE["telematics"]


def load_can_bus_bundle(path=CAN_BUS_MODEL, reload=False):
    """Load and cache the Layer 2 CAN bus model bundle in memory."""
    global _MODEL_CACHE
    if _MODEL_CACHE["can_bus"] is None or reload:
        if not os.path.exists(path):
            raise FileNotFoundError(f"CAN bus model bundle not found at: {path}")
        bundle = joblib.load(path)
        if "model" in bundle and not hasattr(bundle["model"], "multi_class"):
            bundle["model"].multi_class = "auto"
        _MODEL_CACHE["can_bus"] = bundle
    return _MODEL_CACHE["can_bus"]


def preload_models():
    """Preload both Layer 1 and Layer 2 model bundles to eliminate cold-start latency."""
    load_telematics_bundle()
    load_can_bus_bundle()


# ─── Severity Engine (Unified) ────────────────────────────────────────
def compute_unified_severity(label, confidence, is_anomalous, layer):
    """Unified severity scoring across both layers."""
    
    if label in ["normal", "benign"] and not is_anomalous:
        return "Low"
    
    # Critical threats
    critical_attacks = {
        # Telematics layer
        "backdoor", "cryptojacking",
        # CAN bus layer (original)
        "dos", "rpm_spoofing", "gear_spoofing",
        # CAN bus layer (expanded)
        "replay", "bms_spoofing", "uds_exploit"
    }
    
    if label in critical_attacks and (confidence >= 0.70 or is_anomalous):
        return "Critical"
    
    # High threats
    high_attacks = {"flood-attack", "fuzzy", "scan-probe"}
    if label in high_attacks and (confidence >= 0.65 or is_anomalous):
        return "High"
    
    # Novel threat
    if is_anomalous and confidence < 0.50:
        return "Critical"
    
    return "Medium"


# ─── Layer 1: Telematics Prediction ──────────────────────────────────
def predict_telematics(event, bundle):
    """Run telematics (charging station) prediction."""
    clf_pipeline = bundle["classifier_pipeline"]
    anomaly_preprocessor = bundle["anomaly_preprocessor"]
    anomaly_model = bundle["anomaly_model"]
    anomaly_threshold = bundle["anomaly_threshold"]
    feature_cols = bundle["feature_columns"]
    label_encoder = bundle["label_encoder"]

    sample_df = pd.DataFrame([event])
    for col in feature_cols:
        if col not in sample_df.columns:
            sample_df[col] = np.nan
    sample_df = sample_df[feature_cols]

    prob_array = clf_pipeline.predict_proba(sample_df)[0]
    pred_encoded = int(np.argmax(prob_array))
    pred_label = label_encoder.inverse_transform([pred_encoded])[0]
    confidence = float(np.max(prob_array))

    processed = anomaly_preprocessor.transform(sample_df)
    anomaly_score = float(anomaly_model.decision_function(processed)[0])
    is_anomalous = anomaly_score < anomaly_threshold

    if is_anomalous and confidence < 0.50:
        final_decision = "Novel Threat / Suspicious Anomaly"
    else:
        final_decision = pred_label

    severity = compute_unified_severity(pred_label, confidence, is_anomalous, "telematics")

    return {
        "layer": "Layer 1 - Charging Station (Telematics)",
        "predicted_label": pred_label,
        "confidence": round(confidence, 4),
        "anomaly_score": round(anomaly_score, 4),
        "is_anomalous": is_anomalous,
        "final_decision": final_decision,
        "severity": severity,
        "status": "MALICIOUS" if pred_label != "benign" else "SAFE"
    }


# ─── Layer 2: CAN Bus Prediction ─────────────────────────────────────
def hex_to_int(val):
    try:
        return int(str(val).strip(), 16)
    except:
        return 0


def predict_can_bus(event, bundle):
    """Run CAN bus (vehicle internal) prediction with 24-feature vector."""
    model = bundle["model"]
    scaler = bundle["scaler"]
    le = bundle["label_encoder"]
    iso_forest = bundle["isolation_forest"]
    anomaly_threshold = bundle.get("anomaly_threshold", -0.1)
    default_feature_cols = [
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
    feature_cols = bundle.get("feature_cols", bundle.get("feature_columns", default_feature_cols))

    # Build features from raw CAN frame
    can_id_int = hex_to_int(event.get("can_id", "0000"))
    dlc = int(event.get("dlc", 8))
    
    data_ints = []
    for i in range(8):
        data_ints.append(hex_to_int(event.get(f"data{i}", "00")))

    payload_sum = sum(data_ints)
    payload_mean = payload_sum / 8.0
    payload_std = float(np.std(data_ints))
    payload_min = min(data_ints)
    payload_max = max(data_ints)
    payload_range = payload_max - payload_min
    zero_count = sum(1 for d in data_ints if d == 0)
    max_count = sum(1 for d in data_ints if d == 255)
    hamming = sum(bin(v).count('1') for v in data_ints)
    
    # Entropy
    if payload_sum == 0:
        entropy = 0.0
    else:
        probs = np.array(data_ints, dtype=float)
        probs = probs / (probs.sum() + 1e-10)
        probs = probs[probs > 0]
        entropy = -float(np.sum(probs * np.log2(probs + 1e-10)))

    # New Feature 14: Payload Gradient (delta payload_sum / delta time)
    inter_arrival_time = float(event.get("inter_arrival_time", 0.0))
    prev_payload_sum = float(event.get("prev_payload_sum", payload_sum))
    delta_t = inter_arrival_time if inter_arrival_time > 0 else 1e-6
    payload_gradient = (payload_sum - prev_payload_sum) / delta_t
    payload_gradient = max(-1e6, min(1e6, payload_gradient))  # clip extremes

    # New Feature 15: Diagnostic ID Mask (0x7DF-0x7FF)
    is_diagnostic_id = 1 if (0x7DF <= can_id_int <= 0x7FF) else 0

    features = {
        "can_id_int": can_id_int, "dlc": dlc,
        "data0_int": data_ints[0], "data1_int": data_ints[1],
        "data2_int": data_ints[2], "data3_int": data_ints[3],
        "data4_int": data_ints[4], "data5_int": data_ints[5],
        "data6_int": data_ints[6], "data7_int": data_ints[7],
        "payload_sum": payload_sum, "payload_mean": payload_mean,
        "payload_std": payload_std, "payload_min": payload_min,
        "payload_max": payload_max, "payload_range": payload_range,
        "zero_byte_count": zero_count, "max_byte_count": max_count,
        "payload_entropy": entropy,
        "inter_arrival_time": inter_arrival_time,
        "can_id_frequency": float(event.get("can_id_frequency", 0.001)),
        "hamming_weight": hamming,
        "payload_gradient": payload_gradient,
        "is_diagnostic_id": is_diagnostic_id
    }

    X = pd.DataFrame([features])[feature_cols]
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    X_scaled = scaler.transform(X)

    # Supervised prediction
    probs = model.predict_proba(X_scaled)[0]
    pred_idx = int(np.argmax(probs))
    pred_label = le.inverse_transform([pred_idx])[0]
    confidence = float(np.max(probs))

    # Anomaly detection
    anomaly_score = float(iso_forest.decision_function(X_scaled)[0])
    is_anomalous = anomaly_score < anomaly_threshold

    # Bus-Off / Message Drop heuristic: if anomalous AND large timing gap,
    # the ECU has likely been silenced (Bus-Off or Suspension attack).
    if is_anomalous and inter_arrival_time > 0.5:
        final_decision = "Suspected Bus-Off / Message Drop"
        severity = "Critical"
        return {
            "layer": "Layer 2 - Vehicle CAN Bus",
            "predicted_label": pred_label,
            "confidence": round(confidence, 4),
            "anomaly_score": round(anomaly_score, 4),
            "is_anomalous": is_anomalous,
            "final_decision": final_decision,
            "severity": severity,
            "status": "MALICIOUS",
            "alert": "Timing gap (" + f"{inter_arrival_time:.3f}" + "s) suggests ECU silencing attack"
        }

    if is_anomalous and confidence < 0.50:
        final_decision = "Novel Threat / Suspicious Anomaly"
    else:
        final_decision = pred_label

    severity = compute_unified_severity(pred_label, confidence, is_anomalous, "can_bus")

    return {
        "layer": "Layer 2 - Vehicle CAN Bus",
        "predicted_label": pred_label,
        "confidence": round(confidence, 4),
        "anomaly_score": round(anomaly_score, 4),
        "is_anomalous": is_anomalous,
        "final_decision": final_decision,
        "severity": severity,
        "status": "MALICIOUS" if pred_label != "normal" else "SAFE"
    }


# ─── Unified Detection ───────────────────────────────────────────────
def detect(event):
    """
    Auto-detect input type and run through appropriate model.
    Utilizes in-memory model cache to avoid repeated disk reads.
    Returns unified threat assessment.
    """
    # Auto-detect: CAN bus data has 'can_id', telematics has 'bidirectional_packets'
    is_can = "can_id" in event
    is_telematics = "bidirectional_packets" in event or "bidirectional_duration_ms" in event

    results = []

    if is_can:
        can_bundle = load_can_bus_bundle()
        results.append(predict_can_bus(event, can_bundle))
    
    if is_telematics:
        tel_bundle = load_telematics_bundle()
        results.append(predict_telematics(event, tel_bundle))

    if not results:
        return {"error": "Could not identify input type. Include 'can_id' for CAN bus or 'bidirectional_packets' for telematics."}

    # If both layers triggered, combine into unified assessment
    if len(results) == 2:
        worst = max(results, key=lambda r: ["Low","Medium","High","Critical"].index(r["severity"]))
        return {
            "unified_assessment": True,
            "overall_status": "MALICIOUS" if any(r["status"]=="MALICIOUS" for r in results) else "SAFE",
            "overall_severity": worst["severity"],
            "layer_1_result": results[1],
            "layer_2_result": results[0]
        }
    
    return results[0]


# ─── Stream Processor Integration (ISO/SAE 21434 & AUTOSAR IDS) ──────
def create_stream_processor(k=3, n=5, valid_id_set=None):
    """
    Factory function to initialize a 3-Stage Automotive Stream Processor
    (DBC Whitelist + μ±3σ Timing Tracker + K-out-of-N Debounce Filter).
    """
    from stream_processor import AutomotiveStreamProcessor
    bundle = load_can_bus_bundle()
    return AutomotiveStreamProcessor(bundle, k=k, n=n, valid_id_set=valid_id_set)


def detect_stream(frame_event, processor=None):
    """
    Processes a single streaming frame through the 3-stage debounced filter pipeline.
    """
    if processor is None:
        processor = create_stream_processor()
    return processor.process_frame(frame_event, predict_can_bus)


# ─── Demo ─────────────────────────────────────────────────────────────
if __name__ == "__main__":

    print("=" * 60)
    print("  EVSentinel Unified Detection Engine")
    print("  Layer 1: Charging Station | Layer 2: Vehicle CAN Bus")
    print("=" * 60)

    # Preload models into memory for zero-latency inference
    preload_models()

    # ── Test 1: Telematics Event (Charging Station) ──
    print("\n--- TEST 1: Charging Station Telematics ---")
    telematics_event = {
        "bidirectional_duration_ms": 0.19,
        "bidirectional_packets": 0.0065,
        "bidirectional_bytes": 0.012,
        "src2dst_packets": 0.0051,
        "src2dst_bytes": 0.0098,
        "dst2src_packets": 0.0014,
        "dst2src_bytes": 0.007,
        "bidirectional_mean_ps": 0.55,
        "bidirectional_stddev_ps": 0.42,
        "protocol": 1.0,
        "packet_rate_pps": 3.5e-05,
        "byte_rate_bps": 0.00013,
        "src2dst_packet_ratio": 0.78,
        "src2dst_byte_ratio": 0.73,
        "bytes_per_packet": 0.55,
        "flow_duration_sec": 0.19,
        "frequency_category": "medium"
    }
    result1 = detect(telematics_event)
    print(json.dumps(result1, indent=4))

    # ── Test 2: Normal CAN Bus Frame ──
    print("\n--- TEST 2: Normal CAN Bus Frame ---")
    can_normal = {
        "can_id": "0316",
        "dlc": 8,
        "data0": "05", "data1": "21", "data2": "68", "data3": "09",
        "data4": "21", "data5": "21", "data6": "00", "data7": "6f"
    }
    result2 = detect(can_normal)
    print(json.dumps(result2, indent=4))

    # ── Test 3: Suspicious CAN Bus Frame (DoS-like: all zeros, rapid) ──
    print("\n--- TEST 3: Suspicious CAN Bus Frame (DoS Pattern) ---")
    can_dos = {
        "can_id": "0000",
        "dlc": 8,
        "data0": "00", "data1": "00", "data2": "00", "data3": "00",
        "data4": "00", "data5": "00", "data6": "00", "data7": "00",
        "inter_arrival_time": 0.00001
    }
    result3 = detect(can_dos)
    print(json.dumps(result3, indent=4))

    # ── Test 4: Fuzzy Attack CAN Frame (random bytes) ──
    print("\n--- TEST 4: Fuzzy Attack CAN Frame ---")
    can_fuzzy = {
        "can_id": "FFFF",
        "dlc": 8,
        "data0": "A3", "data1": "7B", "data2": "F1", "data3": "0C",
        "data4": "E9", "data5": "44", "data6": "BB", "data7": "12"
    }
    result4 = detect(can_fuzzy)
    print(json.dumps(result4, indent=4))

    # ── Test 5: CAN Replay Attack (replayed frame with timing anomaly) ──
    print("\n--- TEST 5: CAN Replay Attack ---")
    can_replay = {
        "can_id": "0316",
        "dlc": 8,
        "data0": "05", "data1": "21", "data2": "68", "data3": "09",
        "data4": "21", "data5": "21", "data6": "00", "data7": "6f",
        "inter_arrival_time": 0.00008,   # Abnormally fast (replay injection)
        "can_id_frequency": 0.05         # Doubled frequency from baseline
    }
    result5 = detect(can_replay)
    print(json.dumps(result5, indent=4))

    # ── Test 6: BMS Thermal Spoofing (fake cool temp on battery CAN ID) ──
    print("\n--- TEST 6: BMS Thermal Spoofing ---")
    can_bms = {
        "can_id": "0356",
        "dlc": 8,
        "data0": "19", "data1": "2A", "data2": "0F", "data3": "B2",
        "data4": "03", "data5": "8C", "data6": "00", "data7": "4E",
        "inter_arrival_time": 0.015,
        "prev_payload_sum": 800          # Large payload jump -> impossible gradient
    }
    result6 = detect(can_bms)
    print(json.dumps(result6, indent=4))

    # ── Test 7: UDS Diagnostic Exploit (ECU Reset on 0x7DF) ──
    print("\n--- TEST 7: UDS Diagnostic Exploit ---")
    can_uds = {
        "can_id": "07DF",
        "dlc": 8,
        "data0": "02", "data1": "11", "data2": "01", "data3": "00",
        "data4": "00", "data5": "00", "data6": "00", "data7": "00",
        "inter_arrival_time": 0.003
    }
    result7 = detect(can_uds)
    print(json.dumps(result7, indent=4))

    # ── Test 8: Bus-Off / ECU Silence (large timing gap) ──
    print("\n--- TEST 8: Suspected Bus-Off / ECU Silence ---")
    can_busoff = {
        "can_id": "0316",
        "dlc": 8,
        "data0": "05", "data1": "21", "data2": "68", "data3": "09",
        "data4": "21", "data5": "21", "data6": "00", "data7": "6f",
        "inter_arrival_time": 2.5        # 2.5s gap — ECU was silenced
    }
    result8 = detect(can_busoff)
    print(json.dumps(result8, indent=4))

    # ── Summary ──
    print("\n" + "=" * 60)
    print("  UNIFIED DETECTION SUMMARY (8-CLASS + BUS-OFF)")
    print("=" * 60)
    tests = [
        ("Telematics Event", result1),
        ("Normal CAN Frame", result2),
        ("DoS CAN Frame", result3),
        ("Fuzzy CAN Frame", result4),
        ("Replay Attack", result5),
        ("BMS Spoofing", result6),
        ("UDS Diagnostic Exploit", result7),
        ("Bus-Off / ECU Silence", result8),
    ]
    for name, r in tests:
        status = r.get("status", r.get("overall_status", "?"))
        severity = r.get("severity", r.get("overall_severity", "?"))
        label = r.get("final_decision", r.get("predicted_label", "?"))
        layer = r.get("layer", "Unified")
        print(f"  {name:25s} | {status:9s} | {severity:8s} | {label}")
    
    print("\n" + "=" * 60)
    print("  EVSentinel: Both layers operational (8-class expanded)")
    print("=" * 60)
