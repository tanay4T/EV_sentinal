"""
EVSentinel EDR - AI Incident Response Assistant & 14-Attack Knowledge Base
==========================================================================
Provides contextual, intelligent incident response playbooks, 
ISO/SAE 21434 compliance guidance, and both:
  1. Plain-English, human-friendly steps for non-technical drivers/operators.
  2. Deep-dive technical cybersecurity playbooks for automotive engineers.
"""

# Complete 14-Attack Technical Encyclopedia with Plain-English + Deep-Dive Sections
ATTACK_KNOWLEDGE_BASE = {
    "dos_flooding": {
        "id": "ATK-01",
        "name": "CAN Bus Denial of Service (DoS) Flooding",
        "layer": "Layer 2: In-Vehicle Powertrain Network",
        "severity": "Critical",
        "target_ecus": ["BMS (Battery Management)", "Inverter", "ESC (Braking)"],
        "target_id": "0x0000",
        "description": "Adversary injects high-priority dominant-bit frames (0x0000) at maximum bus saturation, starving all legitimate electronic control units of communication.",
        "physical_risk": "Freezes communication between the Battery Management System and Motor Inverter, preventing emergency shut-offs and driver braking assistance.",
        "detection_signals": "Inter-arrival time collapses (Δt < 0.2 ms), 8 zero bytes, Hamming weight WH = 0, and payload variance σ² = 0.",
        "simple_driver_steps": [
            "🟢 1. Safely pull over to the road shoulder and come to a smooth stop.",
            "🟢 2. The car will automatically switch to 'Limp-Home Mode' (speed limited to 30 km/h) to allow safe steering and braking.",
            "🟢 3. Turn off the ignition for 60 seconds and restart the vehicle.",
            "🟢 4. If warning persists, call road assistance to inspect the OBD-II port."
        ],
        "mitigation_playbook": [
            "🔧 1. Trigger Emergency Safe Limp-Home Mode.",
            "🔧 2. Decouple high-speed powertrain control loops to prevent uncommanded acceleration.",
            "🔧 3. Isolate the compromised physical OBD-II / Gateway port via electronic bus transceiver disablement.",
            "🔧 4. Log full CAN trace for forensic extraction and firmware integrity audit."
        ],
        "iso_21434_ref": "ISO/SAE 21434 Section 9: Vulnerability Analysis & Road Vehicle Cybersecurity"
    },
    "speedometer_spoofing": {
        "id": "ATK-02",
        "name": "Speedometer & Instrument Cluster Spoofing",
        "layer": "Layer 2: In-Vehicle Instrumentation",
        "severity": "Critical",
        "target_ecus": ["Instrument Cluster", "ADAS Domain Controller"],
        "target_id": "0x05A0",
        "description": "Counterfeit instrument cluster frames are injected forcing the speedometer needle and digital dash to display a false velocity (e.g. 220 km/h).",
        "physical_risk": "Deprives the driver of situational speed awareness and disrupts active cruise control and automatic emergency braking.",
        "detection_signals": "Persistent fixed byte override in data2 (0x7E) alongside collapsed byte variance across telemetry registers.",
        "simple_driver_steps": [
            "🟢 1. Do not panic if the speedometer needle suddenly jumps to max speed.",
            "🟢 2. Turn OFF Adaptive Cruise Control and Autopilot immediately.",
            "🟢 3. Trust your physical road feel and manual brake pedal.",
            "🟢 4. Drive at a cautious, steady speed to the nearest authorized EV service center."
        ],
        "mitigation_playbook": [
            "🔧 1. Isolate arbitration ID 0x05A0 at the Central Gateway firewall.",
            "🔧 2. Revert instrument cluster display to backup wheel-speed sensor telemetry (0x018A).",
            "🔧 3. Disengage ADAS / Adaptive Cruise Control until ECU authenticity is re-verified.",
            "🔧 4. Alert the driver via high-priority audio-visual warning."
        ],
        "iso_21434_ref": "ISO/SAE 21434 Section 10: Cybersecurity Verification & Validation"
    },
    "rpm_spoofing": {
        "id": "ATK-03",
        "name": "RPM & Motor Tachometer Spoofing",
        "layer": "Layer 2: In-Vehicle Powertrain Network",
        "severity": "Critical",
        "target_ecus": ["Motor Control Unit (MCU)", "Inverter"],
        "target_id": "0x0316",
        "description": "Adversary injects falsified motor speed frames claiming 0 RPM or 8,000 RPM while vehicle is cruising.",
        "physical_risk": "Triggers uncommanded motor shut-off, sudden loss of propulsion, or harsh regenerative braking torque spikes.",
        "detection_signals": "CAN ID 0x0316 frequency surges 3x above nominal with distinct bit shifts in payload bytes 3 and 4.",
        "simple_driver_steps": [
            "🟢 1. Keep a firm, steady grip on the steering wheel.",
            "🟢 2. If motor power momentarily cuts out, do not pump the gas pedal; coast safely to the side.",
            "🟢 3. Turn the vehicle off and restart to reset the motor sensor communication."
        ],
        "mitigation_playbook": [
            "🔧 1. Cross-verify motor RPM against four-wheel speed ABS sensors.",
            "🔧 2. Override forged CAN telemetry with hardwired resolver sensor inputs.",
            "🔧 3. Limit inverter maximum torque output to prevent physical drivetrain shock.",
            "🔧 4. Trigger an immediate diagnostic trouble code (DTC U0100)."
        ],
        "iso_21434_ref": "ISO 26262 ASIL-D & ISO 21434 Automotive Functional Safety"
    },
    "gear_spoofing": {
        "id": "ATK-04",
        "name": "Transmission Gear Position Spoofing",
        "layer": "Layer 2: In-Vehicle Powertrain Network",
        "severity": "Critical",
        "target_ecus": ["Transmission Control Unit (TCU)", "Drive Selector"],
        "target_id": "0x043F",
        "description": "Adversary broadcasts fake transmission frames commanding Park (P) or Reverse (R) while the vehicle is driving forward.",
        "physical_risk": "Attempts mechanical parking pawl engagement at speed or abruptly disconnects high-voltage DC contactors.",
        "detection_signals": "Bitwise Hamming weight jumps (WH > 24) in byte 0 combined with illegal state transition sequences.",
        "simple_driver_steps": [
            "🟢 1. Stay calm—modern EV safety locks prevent the physical gears from shifting while moving forward.",
            "🟢 2. Bring the car to a complete stop before attempting to touch the gear selector.",
            "🟢 3. Once fully stopped, manually select Park (P), turn off, and restart the car."
        ],
        "mitigation_playbook": [
            "🔧 1. Enforce physical gear state validation based on vehicle road speed (> 5 km/h locks out P/R).",
            "🔧 2. Reject unauthenticated CAN ID 0x043F state transition requests.",
            "🔧 3. Maintain high-voltage contactor closure to preserve power steering and brake boost."
        ],
        "iso_21434_ref": "AUTOSAR SecOC Specification & ISO 21434 Cybersecurity"
    },
    "diagnostic_uds": {
        "id": "ATK-05",
        "name": "Diagnostic UDS Protocol Exploit (0x7DF/0x7E0)",
        "layer": "Layer 2: OBD-II / Central Gateway",
        "severity": "High",
        "target_ecus": ["Central Gateway", "All On-Bus ECUs"],
        "target_id": "0x07DF – 0x07FF",
        "description": "Adversary injects Unified Diagnostic Services request commands (e.g. Service 0x11 ECU Reset or Service 0x28 Communication Control Disable) during active driving.",
        "physical_risk": "Can force critical ECUs to reset or stop broadcasting status messages while navigating highway traffic.",
        "detection_signals": "Arbitration IDs in reserved diagnostic range (0x7DF - 0x7FF) observed outside stationary workshop mode.",
        "simple_driver_steps": [
            "🟢 1. Check under the steering wheel dashboard for any unauthorized third-party dongles plugged into the OBD-II port.",
            "🟢 2. If found, unplug the unknown device immediately.",
            "🟢 3. Continue driving cautiously to an authorized mechanic to clear diagnostic flags."
        ],
        "mitigation_playbook": [
            "🔧 1. Block all UDS Diagnostic Request arbitration IDs when vehicle speed > 0 km/h.",
            "🔧 2. Terminate active diagnostic session (0x28) immediately.",
            "🔧 3. Enforce cryptographic SecurityAccess (Service 0x27) challenge-response."
        ],
        "iso_21434_ref": "ISO 14229 (UDS) & ISO 21434 Diagnostic Security"
    },
    "fuzzy_attack": {
        "id": "ATK-06",
        "name": "Fuzzy Random Payload & CAN ID Storm",
        "layer": "Layer 2: In-Vehicle Broadcast Bus",
        "severity": "High",
        "target_ecus": ["All Connected ECUs", "CAN Transceivers"],
        "target_id": "Random / Unseen IDs",
        "description": "Adversary injects non-existent arbitration IDs or random 0xFF byte payloads at high rates to induce ECU crash states.",
        "physical_risk": "Triggers random dashboard warning lights, wiper activations, and ECU memory mailbox buffer overflows.",
        "detection_signals": "Shannon Payload Entropy spikes (H(X) > 2.7 bits), max byte count >= 6, and unseen arbitration IDs.",
        "simple_driver_steps": [
            "🟢 1. If dashboard indicator lights flicker or wipers turn on by themselves, pull over safely.",
            "🟢 2. Turn off the car for 60 seconds to allow the computers to clear temporary memory buffers.",
            "🟢 3. Restart the car. If errors persist, request a diagnostic scan at the service center."
        ],
        "mitigation_playbook": [
            "🔧 1. Enable strict CAN ID whitelisting at the Central Gateway.",
            "🔧 2. Purge pending receive mailboxes on affected microcontrollers.",
            "🔧 3. Rate-limit unauthenticated CAN broadcasts."
        ],
        "iso_21434_ref": "ISO/SAE 21434 Threat Scenario Identification"
    },
    "replay_burst": {
        "id": "ATK-07",
        "name": "CAN Frame Replay Burst Attack",
        "layer": "Layer 2: In-Vehicle Telemetry",
        "severity": "Medium",
        "target_ecus": ["Drivetrain & Telematics Gateways"],
        "target_id": "0x01A1 / 0x02C6",
        "description": "Adversary captures legitimate valid frames and retransmits them at a 10x accelerated burst frequency (Δt = 2.5 ms).",
        "physical_risk": "Subverts authentication and introduces stale sensor states without violating static payload boundaries.",
        "detection_signals": "Per-ID inter-arrival time collapses below normal periodicity with sudden frequency expansion.",
        "simple_driver_steps": [
            "🟢 1. If buttons, infotainment, or climate controls feel slightly laggy, drive normally.",
            "🟢 2. Schedule a regular software update at your dealership to refresh vehicle security keys."
        ],
        "mitigation_playbook": [
            "🔧 1. Enforce AUTOSAR SecOC freshness values (Rolling Message Counters).",
            "🔧 2. Discard frames arriving outside the nominal ±20% timing window.",
            "🔧 3. Invalidate current cryptographic session key."
        ],
        "iso_21434_ref": "AUTOSAR Secure Onboard Communication (SecOC)"
    },
    "evse_flood": {
        "id": "ATK-08",
        "name": "EVSE Charging Station DoS / Flood Attack",
        "layer": "Layer 1: External Charging Infrastructure",
        "severity": "High",
        "target_ecus": ["EVSE Controller", "OCPP Central System"],
        "target_id": "Port 9000 (OCPP-J / WebSocket)",
        "description": "High-volume network flood overwhelming the EVSE charging pole controller or cloud management server.",
        "physical_risk": "Disables charging sessions, crashes billing verification, and disrupts grid load management.",
        "detection_signals": "Surge in packet_rate_pps, extreme directional imbalance (src2dst / dst2src > 0.95), and tiny bytes_per_packet.",
        "simple_driver_steps": [
            "🟢 1. If the charging station screen freezes or refuses your payment card, unplug your vehicle.",
            "🟢 2. Move to an alternative charging stall or nearby charging station.",
            "🟢 3. Report the unresponsive charging stall on the charging app."
        ],
        "mitigation_playbook": [
            "🔧 1. Enable edge rate-limiting and DDoS mitigation on the EVSE gateway.",
            "🔧 2. Shift charging controller to local offline fallback authorization.",
            "🔧 3. Isolate offending IP subnet at the station firewall."
        ],
        "iso_21434_ref": "OCPP 2.0.1 Security Profile 3 & ISO 15118"
    },
    "telematics_backdoor": {
        "id": "ATK-09",
        "name": "EVSE / Telematics Remote Backdoor (C2)",
        "layer": "Layer 1: Charging Controller / Telematics Unit",
        "severity": "Critical",
        "target_ecus": ["Charging Controller Linux Gateway", "TCU"],
        "target_id": "Port 22 (SSH) / Reverse Shell",
        "description": "Adversary establishes a persistent command-and-control connection allowing remote root execution.",
        "physical_risk": "Enables unauthorized firmware modification, disabling high-voltage safety shut-offs, and stealing customer tokens.",
        "detection_signals": "High bidirectional packet size stddev (σ_ps), long flow durations, and elevated Isolation Forest scores.",
        "simple_driver_steps": [
            "🟢 1. Immediately unplug your vehicle from the public charging pole.",
            "🟢 2. Do not use open unverified public Wi-Fi networks in your car until a security update is performed."
        ],
        "mitigation_playbook": [
            "🔧 1. Sever all active WebSocket and SSH connections immediately.",
            "🔧 2. Force high-voltage contactor disengagement if charging is active.",
            "🔧 3. Trigger full cryptographic certificate revocation and flash memory re-verification."
        ],
        "iso_21434_ref": "NIST SP 800-61 Incident Handling & ISO 21434"
    },
    "cryptojacking": {
        "id": "ATK-10",
        "name": "Charging Station Resource Hijacking (Cryptojacking)",
        "layer": "Layer 1: Charging Station Edge Computer",
        "severity": "Critical",
        "target_ecus": ["EVSE Quad-Core Embedded Processor"],
        "target_id": "Mining Stratum Protocol",
        "description": "Malicious crypto-mining payload executing on charging hub controllers, stealing CPU and network bandwidth.",
        "physical_risk": "Induces CPU thermal throttling on charging electronics, delaying safety-critical telemetry reporting.",
        "detection_signals": "Continuous periodic flows with uniform byte rates and rigid packet length distributions.",
        "simple_driver_steps": [
            "🟢 1. If a charging pole's cooling fan is making extremely loud noise while delivering slow power, stop the session.",
            "🟢 2. Switch to another fast charger to prevent thermal strain on your battery."
        ],
        "mitigation_playbook": [
            "🔧 1. Kill rogue background mining processes via system watchdog.",
            "🔧 2. Verify charging station firmware hash against OEM golden image.",
            "🔧 3. Restrict outgoing outbound traffic to authorized OCPP endpoints only."
        ],
        "iso_21434_ref": "CIS Controls for IoT / Embedded Systems"
    },
    "scan_probe": {
        "id": "ATK-11",
        "name": "EVSE Network Reconnaissance & Port Scanning",
        "layer": "Layer 1: Charging Station Network",
        "severity": "High",
        "target_ecus": ["EVSE Network Interface"],
        "target_id": "Ports 80, 443, 9000, 22",
        "description": "Automated network scanner probing open ports and services across charging infrastructure.",
        "physical_risk": "Precursor reconnaissance to identify unpatched services for targeted exploit delivery.",
        "detection_signals": "Asymmetric flow ratios and rapid sequential connection attempts across multiple ports.",
        "simple_driver_steps": [
            "🟢 1. Normal charging continues safely. The charging hub firewall will automatically block the scanner in the background."
        ],
        "mitigation_playbook": [
            "🔧 1. Dynamically block scanning source IP at edge firewall.",
            "🔧 2. Close unneeded management ports (SSH, Telnet, HTTP).",
            "🔧 3. Enforce TLS mutual authentication (mTLS) on all OCPP endpoints."
        ],
        "iso_21434_ref": "ISO 15118-20 Public Key Infrastructure"
    },
    "brokenwire_plc": {
        "id": "ATK-12",
        "name": "Brokenwire / Power Line Communication Tampering",
        "layer": "Layer 1: Charging Cable & Physical Interface",
        "severity": "Critical",
        "target_ecus": ["CCS Control Pilot / HomePlug GreenPHY"],
        "target_id": "ISO 15118 PLC Line",
        "description": "Electromagnetic interference injected on the Combined Charging System power line causing sudden charge disruption.",
        "physical_risk": "Abruptly aborts high-voltage charging sessions across multiple stalls simultaneously.",
        "detection_signals": "Sudden drop in bidirectional flow rate during active high-power current flow.",
        "simple_driver_steps": [
            "🟢 1. If charging disconnects every few seconds, check the charging connector plug for dirt or damaged pins.",
            "🟢 2. Use a standard AC Level 2 charger or move to a different DC fast charging stall."
        ],
        "mitigation_playbook": [
            "🔧 1. Shield and inspect physical charging cable coupling.",
            "🔧 2. Fall back to PWM Control Pilot signaling if PLC link degrades.",
            "🔧 3. Log signal-to-noise ratio (SNR) telemetry for forensic verification."
        ],
        "iso_21434_ref": "ISO 15118-3 Physical Layer Specifications"
    },
    "ocpp_mitm": {
        "id": "ATK-13",
        "name": "OCPP Man-in-the-Middle Meter Ledger Tampering",
        "layer": "Layer 1: EVSE Cloud Billing Channel",
        "severity": "High",
        "target_ecus": ["Billing Gateway", "Energy Meter"],
        "target_id": "OCPP MeterValues Payloads",
        "description": "Interception and manipulation of unencrypted OCPP energy metering packets.",
        "physical_risk": "Falsifies billed kilowatt-hour (kWh) readings, manipulating grid settlement ledgers.",
        "detection_signals": "Uncorrelated byte variance against physical charging duration curves.",
        "simple_driver_steps": [
            "🟢 1. Review your charging receipt and billed kWh units in your smartphone app.",
            "🟢 2. If the billed energy is noticeably higher than your battery capacity, contact customer support with your timestamp."
        ],
        "mitigation_playbook": [
            "🔧 1. Enforce OCPP Security Profile 3 (mTLS + signed MeterValues).",
            "🔧 2. Cross-verify digital meter readings against hardware shunt sensors.",
            "🔧 3. Invalidate compromised transaction IDs."
        ],
        "iso_21434_ref": "OCPP Security Profile 3 (Open Charge Alliance)"
    },
    "firmware_tampering": {
        "id": "ATK-14",
        "name": "ECU / EVSE Firmware Tampering & Flash Injection",
        "layer": "Layer 2 & Layer 1: Embedded Hardware",
        "severity": "Critical",
        "target_ecus": ["Microcontroller Flash Memory", "BMS ROM"],
        "target_id": "Memory Flash Registers",
        "description": "Adversary flashes unauthorized binary code into ECU microcontrollers via local diagnostic or remote OTA paths.",
        "physical_risk": "Overrides safety current limits, disabling battery thermal runaway safeguards.",
        "detection_signals": "High-entropy burst payloads over diagnostic channels accompanied by abnormal timing signatures.",
        "simple_driver_steps": [
            "🟢 1. If a 'Tamper / Secure Boot Error' appears on the driver display, DO NOT drive or fast charge.",
            "🟢 2. Request authorized dealer towing for certified factory firmware re-flashing."
        ],
        "mitigation_playbook": [
            "🔧 1. Force Hardware Security Module (HSM) Secure Boot validation.",
            "🔧 2. If signature verification fails, lock ECU into Recovery Mode.",
            "🔧 3. Restore factory firmware from immutable write-protected flash partition."
        ],
        "iso_21434_ref": "UN R155 & ISO 21434 Software Update Management"
    }
}


def get_all_attack_details():
    """Returns full catalog of all 14 attacks."""
    return list(ATTACK_KNOWLEDGE_BASE.values())


def get_attack_info(attack_type):
    """Retrieves specific details for an attack type with normalized property aliases."""
    found = None
    for key, data in ATTACK_KNOWLEDGE_BASE.items():
        if key in attack_type.lower() or data["name"].lower() in attack_type.lower():
            found = data
            break
            
    if not found:
        found = {
            "id": "ATK-GEN",
            "name": attack_type.replace("_", " ").title(),
            "layer": "Dual-Layer EV Ecosystem",
            "severity": "High",
            "target_ecus": ["In-Vehicle / Charging Network"],
            "target_id": "CAN / Telematics",
            "description": f"Anomalous cyber-physical event detected: {attack_type}.",
            "physical_risk": "Potential operational degradation or unauthorized telemetry tampering.",
            "detection_signals": "Statistical feature deviation detected by ML Dual-Engine.",
            "simple_driver_steps": [
                "🟢 1. Pull over safely if vehicle behavior feels abnormal.",
                "🟢 2. Check for unauthorized devices in the OBD-II port.",
                "🟢 3. Restart the vehicle and schedule a diagnostic check."
            ],
            "mitigation_playbook": [
                "🔧 1. Inspect real-time CAN bus telemetry and error frames.",
                "🔧 2. Isolate suspicious arbitration ID or IP address.",
                "🔧 3. Perform cryptographic freshness verification."
            ],
            "iso_21434_ref": "ISO/SAE 21434 Automotive Cybersecurity Standards"
        }

    # Enrich with normalized frontend aliases
    res = dict(found)
    res["mechanism"] = found.get("description", "")
    res["driver_actions"] = found.get("simple_driver_steps", [])
    res["technical_playbook"] = found.get("mitigation_playbook", [])
    res["iso_reference"] = found.get("iso_21434_ref", "ISO/SAE 21434")
    ecus = found.get("target_ecus", [])
    res["subsystem_impact"] = ", ".join(ecus) if isinstance(ecus, list) else str(ecus)
    res["tara_cal_level"] = "CAL-4" if found.get("severity") == "Critical" else ("CAL-3" if found.get("severity") == "High" else "CAL-2")
    return res


def generate_ai_chat_response(query, scan_context=None):
    """
    Generates intelligent, contextual incident response recommendations
    with both plain-English driver steps and technical engineering steps.
    """
    q_lower = query.lower()
    
    # 1. Direct Attack Queries
    for key, data in ATTACK_KNOWLEDGE_BASE.items():
        if key in q_lower or data["name"].lower() in q_lower:
            simple_steps_formatted = "\n".join([f"  {s}" for s in data["simple_driver_steps"]])
            tech_steps_formatted = "\n".join([f"  {s}" for s in data["mitigation_playbook"]])
            return f"""### 🛡️ Incident Response: **{data['name']}** ({data['severity']} Severity)

#### 🚗 Simple Plain-English Steps (For Drivers & Operators):
{simple_steps_formatted}

#### 🔧 Deep-Dive Technical Mitigation (For Automotive Engineers & SOCs):
{tech_steps_formatted}

**Target Subsystems:** `{', '.join(data['target_ecus'])}` | **Identifier:** `{data['target_id']}`
**Compliance Reference:** *{data['iso_21434_ref']}*"""

    # 2. General Health Query
    if any(w in q_lower for w in ["health", "status", "battery", "car", "subsystem"]):
        if scan_context and "health" in scan_context:
            h = scan_context["health"]
            overall = h.get("overall_health_score", 100)
            subs = h.get("subsystems", {})
            return f"""### 🚗 Vehicle Cyber-Physical Health Evaluation

**Overall Health Score:** **{overall}%** ({h.get('status', 'HEALTHY')})

* **Battery Pack (BMS):** {subs.get('bms', {}).get('score', 100)}% ({subs.get('bms', {}).get('details', 'N/A')})
* **Powertrain & Motor:** {subs.get('powertrain', {}).get('score', 100)}% ({subs.get('powertrain', {}).get('details', 'N/A')})
* **Transmission:** {subs.get('drivetrain', {}).get('score', 100)}% ({subs.get('drivetrain', {}).get('details', 'N/A')})
* **CAN Network:** {subs.get('network', {}).get('score', 100)}% ({subs.get('network', {}).get('details', 'N/A')})

**Driver Advisory:** {'⚠️ Critical security degradation detected! Please slow down and pull over safely.' if overall < 70 else '✅ Vehicle is operating normally within safe parameters.'}"""

    # 3. What attacks were detected in current scan
    if any(w in q_lower for w in ["what attack", "detected", "summary", "happened", "incident"]):
        if scan_context and "incidents" in scan_context and scan_context["incidents"]:
            inc_list = "\n".join([f"  • **{inc['display_name']}** ({inc['severity']}) at {inc['start_timestamp']}" for inc in scan_context["incidents"][:5]])
            return f"""### 🚨 Active Incident Summary for Current Vehicle

The scan identified **{len(scan_context['incidents'])} security incidents**:

{inc_list}

**Simple Driver Advice:** Click **[Explain]** next to any incident to see simple plain-English instructions on what to do."""
        else:
            return "✅ **No active cyber threats detected** in the current scan data. All systems are clean and safe."

    # 4. Default Conversational Fallback
    return f"""### 🤖 EVSentinel AI Incident Assistant

I provide both **simple plain-English instructions for drivers** and **technical engineering playbooks for cybersecurity experts**.

**Try Asking Me:**
* *"What should a driver do during a DoS attack?"*
* *"How do I fix Speedometer Spoofing in plain English?"*
* *"What is the Battery Management System health?"*"""
