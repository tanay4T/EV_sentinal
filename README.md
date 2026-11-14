# EVSentinel: Automotive EDR & Intrusion Detection System

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-FastAPI-green.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**EVSentinel** is an AI-driven Endpoint Detection and Response (EDR) and Intrusion Detection System (IDS) engineered specifically for Connected Electric Vehicles (EVs), In-Vehicle CAN Networks, and EV Charging Infrastructure (EVSE).

Developed at **Somaiya Vidyavihar University** (K. J. Somaiya School of Engineering).

---

## 🚗 Key Features

- **Microsecond-Latency In-Vehicle CAN IDS**: Real-time detection of CAN bus anomalies, DoS attacks, fuzzy injection, and gear/RPM spoofing with sub-10 microsecond inference latency.
- **Telematics & EVSE Infrastructure Protection**: Anomaly detection for telematics streams and EV charging sessions based on the CIC-EVSE dataset.
- **Interactive EDR Web Dashboard**:
  - Live CAN bus and telemetry visualizer.
  - Subsystem health and anomaly heatmaps.
  - Embedded AI-assisted Incident Response chatbot.
- **Digital Twin & Forensic Evidence**:
  - Cryptographically verifiable incident logs.
  - CERT-In compliance report generation.
- **Multi-Vehicle Support**: Verified across diverse vehicle datasets including BYD Atto 3, MG ZS EV, Opel Astra, and Renault Clio.

---

## 📁 Repository Structure

```text
├── edr_engine/                     # Core EDR processing & classification engines
│   ├── folder_scanner.py          # Log ingestion and directory scanning
│   ├── threat_classifier.py       # ML-driven CAN & telematics threat evaluation
│   ├── health_evaluator.py        # Subsystem health scoring & telemetry decoding
│   └── ai_incident_assistant.py   # AI response assistant & attack explanations
├── can_bus_model/                 # Pretrained CAN bus ML models & scalers
├── generalized_telematics_model/  # Telematics ML classification bundles
├── real_ev_datasets/              # Real-world EV logs (BYD Atto 3, MG ZS EV)
├── templates/                     # Dashboard HTML templates
├── static/                        # Dashboard assets (CSS, JS, icons)
├── edr_server.py                  # FastAPI backend server
├── run_edr_dashboard.py           # Dashboard launcher script
├── evsentinel_unified.py          # Unified detection and reporting pipeline
├── requirements.txt               # Python package dependencies
└── README.md                      # Project documentation
```

---

## 🚀 Quick Start

### 1. Prerequisites
Ensure you have **Python 3.9+** installed on your system.

### 2. Clone the Repository
```bash
git clone https://github.com/tanay4T/EVsentinal.git
cd EVsentinal
```

### 3. Create a Virtual Environment
```bash
# On Windows
python -m venv venv
venv\Scripts\activate

# On Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

### 5. Launch the Dashboard
```bash
python run_edr_dashboard.py
```
Open your browser and navigate to: `http://localhost:8000`

---

## 🛡️ Attack Types Detected

- **CAN DoS (Denial of Service)**: High-frequency dominant message flooding targeting bus arbitration.
- **Fuzzy Injections**: Randomized CAN IDs and payload corruptions.
- **Spoofing / Manipulation**: Gear and RPM telemetry tampering.
- **EVSE Protocol Anomalies**: Abnormal charging currents, unauthenticated charge aborts, and telematics disruptions.

---

## 👥 Authors

- **Tanay Sawant**
- **Swarna Makwana**
- **Charu Malpani**
- **Riya Amin**

*Department of Information Technology, K. J. Somaiya School of Engineering, Somaiya Vidyavihar University, Mumbai.*
