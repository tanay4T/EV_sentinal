"""
EVSentinel EDR - Folder Ingestion & Log Scanner
===============================================
Discovers and parses CAN bus logs (candump format, .log, .txt, .csv) and
telematics network flow CSVs from any local folder or preset path.
"""

import os
import re
import glob
import pandas as pd
import numpy as np


PRESET_DIRECTORIES = {
    "Tata_Nexon_EV": os.path.join("real_ev_datasets", "Tata_Nexon_EV"),
    "MG_ZS_EV": os.path.join("real_ev_datasets", "MG_ZS_EV"),
    "BYD_Atto3": os.path.join("real_ev_datasets", "BYD_Atto3"),
    "OpelAstra": os.path.join("tue_dataset_extracted", "OpelAstra"),
    "RenaultClio": os.path.join("tue_dataset_extracted", "RenaultClio"),
    "Prototype": os.path.join("tue_dataset_extracted", "Prototype"),
    "Telematics_EVSE": "cic_evse_2024_merged.csv"
}


def parse_candump_line(line, filename="unknown"):
    """
    Parses SocketCAN candump formats:
      - Standard: (1536574931.814734) slcan0 12A#00F0707200003090
      - Text format: Timestamp: 1478198376.389486   ID: 0316    DLC: 8    05 28 68 ...
    """
    line = line.strip()
    if not line:
        return None
        
    # Standard candump regex: (timestamp) interface CAN_ID#PAYLOAD
    m = re.match(r'\(([\d.]+)\)\s+[\w-]+\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]*)', line)
    if m:
        ts = float(m.group(1))
        can_id = m.group(2).upper().zfill(4)
        payload_hex = m.group(3)
        data_bytes = []
        for i in range(0, len(payload_hex), 2):
            data_bytes.append(payload_hex[i:i+2].upper())
        dlc = len(data_bytes)
        while len(data_bytes) < 8:
            data_bytes.append('00')
        return [ts, can_id, dlc] + data_bytes[:8] + [filename, "CAN_BUS"]
        
    # Alternate text format: Timestamp: ... ID: ... DLC: ...
    m2 = re.match(r'Timestamp:\s+([\d.]+)\s+ID:\s+([0-9A-Fa-f]+)\s+\w*\s*DLC:\s+(\d+)\s+(.*)', line)
    if m2:
        ts = float(m2.group(1))
        can_id = m2.group(2).upper().zfill(4)
        dlc = int(m2.group(3))
        parts = m2.group(4).strip().split()
        while len(parts) < 8:
            parts.append('00')
        return [ts, can_id, dlc] + [p.upper() for p in parts[:8]] + [filename, "CAN_BUS"]

    # Vector .asc format: 0.000000 1 242 Rx d 8 00 00 00 00 00 00 00 00
    parts = line.split()
    if len(parts) >= 7 and parts[3] in ('Rx', 'Tx'):
        try:
            ts = float(parts[0])
            can_id = parts[2].upper().zfill(4)
            dlc = int(parts[5]) if parts[4] == 'd' else 8
            data_bytes = [p.upper() for p in parts[6:6+dlc]]
            while len(data_bytes) < 8:
                data_bytes.append('00')
            return [ts, can_id, dlc] + data_bytes[:8] + [filename, "CAN_BUS"]
        except Exception:
            pass

    return None


def scan_and_load_folder(folder_path, max_frames_per_file=20000):
    """
    Scans an entire directory for CAN bus logs and telematics CSVs.
    Returns:
      can_df: DataFrame of CAN frames
      telematics_df: DataFrame of Telematics flows (if any)
      file_manifest: List of parsed files and frame counts
    """
    # Check if preset name passed
    if folder_path in PRESET_DIRECTORIES:
        resolved_path = PRESET_DIRECTORIES[folder_path]
    else:
        resolved_path = folder_path

    if not os.path.exists(resolved_path):
        raise FileNotFoundError(f"Folder path does not exist: {resolved_path}")

    can_records = []
    telematics_dfs = []
    file_manifest = []

    # If single file passed directly
    if os.path.isfile(resolved_path):
        files_to_process = [resolved_path]
    else:
        # Search for .log, .txt, .csv, .asc files
        files_to_process = []
        for ext in ["*.log", "*.txt", "*.csv", "*.asc"]:
            files_to_process.extend(glob.glob(os.path.join(resolved_path, ext)))
            files_to_process.extend(glob.glob(os.path.join(resolved_path, "**", ext), recursive=True))
        files_to_process = sorted(list(set(files_to_process)))

    for fpath in files_to_process:
        fname = os.path.basename(fpath)
        
        # Check if Telematics flow CSV (e.g. CIC-EVSE)
        if fname.endswith(".csv"):
            try:
                sample_df = pd.read_csv(fpath, nrows=5)
                if "bidirectional_duration_ms" in sample_df.columns or "protocol" in sample_df.columns:
                    full_telematics = pd.read_csv(fpath)
                    telematics_dfs.append(full_telematics)
                    file_manifest.append({
                        "file_name": fname,
                        "type": "EVSE Telematics Flow CSV",
                        "records": len(full_telematics),
                        "status": "LOADED"
                    })
                    continue
            except Exception:
                pass

        # Parse as CAN bus log
        file_count = 0
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parsed = parse_candump_line(line, filename=fname)
                if parsed:
                    can_records.append(parsed)
                    file_count += 1
                    if max_frames_per_file and file_count >= max_frames_per_file:
                        break
                        
        if file_count > 0:
            file_manifest.append({
                "file_name": fname,
                "type": "CAN Bus SocketCAN Log",
                "records": file_count,
                "status": "LOADED"
            })

    cols = ["timestamp", "can_id", "dlc", "data0", "data1", "data2", "data3", "data4", "data5", "data6", "data7", "source_file", "data_type"]
    can_df = pd.DataFrame(can_records, columns=cols) if can_records else pd.DataFrame(columns=cols)
    telematics_df = pd.concat(telematics_dfs, ignore_index=True) if telematics_dfs else pd.DataFrame()

    return can_df, telematics_df, file_manifest
