/**
 * EVSentinel Automotive EDR - Frontend Application Logic (v5.0 - Production 3-Tab Edition)
 * Supports 3 Unshakeable Core Tabs:
 *   - Tab 1: Fleet EDR & Threat Operations (Multi-Vehicle Scanner, 5.2 µs ML, Health Radar, AI Chatbot)
 *   - Tab 2: Vehicle Digital Twin & High-Speed CAN Topology (Interactive SVG + Red Team Sandbox + Active Quarantine)
 *   - Tab 3: AIS-189 & CERT-In Mandatory 6-Hour Incident Reporting & AIS-156 Extreme Battery Safety
 */

let CURRENT_SCAN_DATA = null;
let CURRENT_FILTER = 'ALL';
let ATTACK_CATALOG = [];
let ACTIVE_ECU_NODE = 'bms';
let CERTIN_COUNTDOWN_SECONDS = 5 * 3600 + 38 * 60 + 14;

// ─── ECU REGISTRY FOR DIGITAL TWIN INSPECTOR ────────────────────────────
const ECU_REGISTRY = {
    'bms': {
        title: 'Battery Management System (BMS)',
        desc: 'High-Voltage LFP Battery Pack Master & Slave Monitors. Controls thermal runaway mitigation and cell equalization.',
        canIds: '0x1C7, 0x218, 0x380',
        interval: '10.0 ms (100 Hz)',
        transceiver: 'NXP TJA1051 Isolated High-Speed CAN',
        firewall: 'ACTIVE FILTER (V_cell & T_pack bounds)',
        schema: [
            'D0-D1: Pack Terminal Voltage (mV)',
            'D2-D3: State of Charge (0.1% resolution)',
            'D4-D5: Max Cell Temperature (°C)',
            'D6-D7: High-Voltage Contactor Interlock State'
        ]
    },
    'mcu': {
        title: 'Traction Motor Control Unit (MCU)',
        desc: 'PMSM Inverter driving electric traction motor. Governs regenerative braking and torque vectoring.',
        canIds: '0x316, 0x180',
        interval: '5.0 ms (200 Hz)',
        transceiver: 'Infineon TLE9251V High-Speed',
        firewall: 'ACTIVE FILTER (Torque & RPM Bounds)',
        schema: [
            'D0-D1: Demanded Torque (0.1 Nm)',
            'D2-D3: Actual Motor RPM (0.25 rpm)',
            'D4: Inverter IGBT Temperature (°C)',
            'D5-D7: Fault Flags & Slip Ratio'
        ]
    },
    'vcu': {
        title: 'Vehicle Control Unit (VCU Master)',
        desc: 'Supervisory vehicle state coordinator. Manages drive modes, limp-home limits, and keyless ignition.',
        canIds: '0x418, 0x280',
        interval: '20.0 ms (50 Hz)',
        transceiver: 'NXP TJA1044 Fault-Tolerant',
        firewall: 'GATEWAY SUPERVISED',
        schema: [
            'D0: Power Mode & Ignition State',
            'D1: Accelerator Pedal Position (%)',
            'D2: Brake Switch & Regen Level',
            'D3-D7: Safe Limp-Home Mode Flags'
        ]
    },
    'gateway': {
        title: 'Central Domain Gateway (EDR Core)',
        desc: 'Secure central routing gateway linking Powertrain, Chassis, Infotainment, and Telematics buses. Runs EVSentinel 5.2 µs IDS.',
        canIds: '0x7DF (Diagnostic Routing)',
        interval: 'Sub-Microsecond Latency',
        transceiver: 'Multi-Channel CAN-FD Gateway',
        firewall: 'FIREWALL ENGINE: EVSENTINEL EDR',
        schema: [
            'Mailbox 0-15: Static ID Whitelist',
            'Mailbox 16-31: Dynamic Anomaly Quarantine',
            'Payload Hash: SHA-256 Signature Audit',
            'EDR Mitigations: Limp-Home / Contactor Trip'
        ]
    },
    'ccs2': {
        title: 'CCS2 / IS 17017 Charging Inlet',
        desc: 'Combined Charging System Type 2 inlet handling AC 3-phase and high-power DC fast charging (IS 17017 / IEC 61851).',
        canIds: '0x580, 0x418',
        interval: '100.0 ms (10 Hz)',
        transceiver: 'HomePlug GreenPHY PLC / CAN',
        firewall: 'HARDWARE PILOT INTERLOCK',
        schema: [
            'CP: Control Pilot Duty Cycle (PWM)',
            'PP: Proximity Pilot Resistance (Amps)',
            'DC Contactors: +HV / -HV Relays',
            'IS 17017: Protective Earth Monitoring'
        ]
    },
    'tcu': {
        title: 'Telematics Control Unit (TCU / 4G)',
        desc: 'Cellular 4G/5G modem and OTA gateway communicating with Cloud Fleet CSMS over MQTT and OCPP.',
        canIds: '0x620, 0x680',
        interval: '500.0 ms (2 Hz)',
        transceiver: 'Telit / Quectel Automotive 4G',
        firewall: 'TLS 1.3 / CERT-In Dispatch Tunnel',
        schema: [
            'D0-D3: GPS Latitude / Longitude',
            'D4-D5: Cellular Signal Strength (RSSI)',
            'D6: CSMS Remote Lock / Unlock',
            'D7: OTA Checksum Verification Flag'
        ]
    },
    'cluster': {
        title: 'Digital Instrument Cluster & IVI',
        desc: 'Cockpit driver display receiving speed, warnings, and gear status from powertrain bus.',
        canIds: '0x5A0, 0x43F, 0x480',
        interval: '50.0 ms (20 Hz)',
        transceiver: 'Microchip ATA6560 CAN-FD',
        firewall: 'DRIVER WARNING DISPLAY ONLY',
        schema: [
            'D0-D1: Vehicle Speed (0.8 km/h unit)',
            'D2: Selected Gear (P/R/N/D)',
            'D3: Odometer & Trip Meter',
            'D4-D7: Check Engine & Warning Lamps'
        ]
    },
    'obd': {
        title: 'OBD-II Diagnostic Port',
        desc: 'Physical 16-pin maintenance connector located under steering column for UDS (ISO 14229) diagnostic tools.',
        canIds: '0x7E0, 0x7E8, 0x000',
        interval: 'Aperiodic / Diagnostic Request',
        transceiver: 'Standard OBD-II Pin 6 & 14 CAN',
        firewall: 'DYNAMIC AIR-GAP FILTER ACTIVE',
        schema: [
            'Pin 6: CAN-High (500 kbps)',
            'Pin 14: CAN-Low (500 kbps)',
            'Service 0x10: DiagnosticSessionControl',
            'Service 0x27: SecurityAccess Seed-Key'
        ]
    }
};

document.addEventListener('DOMContentLoaded', async () => {
    // 1. Load Attack Catalog
    await loadAttackCatalog();

    // 2. Setup Event Listeners
    document.getElementById('btnScanFolder').addEventListener('click', handleScanClick);
    document.getElementById('btnExport').addEventListener('click', handleExportReport);

    // 3. Start CERT-In SLA Countdown Timer
    startCertInTimer();

    // 4. Run default scan on India's #1 EV: Tata Nexon EV
    selectPreset('Tata_Nexon_EV');

    // 5. Initialize Digital Twin Inspector with BMS
    inspectECU('bms');
});

// ─── TAB NAVIGATION ─────────────────────────────────────────────────────
function switchTab(tabId) {
    document.querySelectorAll('.tab-pane').forEach(el => el.classList.add('hidden'));
    const target = document.getElementById(tabId);
    if (target) target.classList.remove('hidden');

    // Reset button states
    const btnIds = ['edr', 'digital-twin', 'compliance'];
    btnIds.forEach(id => {
        const btn = document.getElementById(`btnTab-${id}`);
        if (btn) {
            btn.className = 'tab-btn px-4 py-1.5 text-xs font-semibold rounded-xl transition flex items-center space-x-2 bg-slate-800/80 hover:bg-slate-700 text-slate-300 border border-slate-700';
        }
    });

    const activeSuffix = tabId.replace('tab-', '');
    const activeBtn = document.getElementById(`btnTab-${activeSuffix}`);
    if (activeBtn) {
        activeBtn.className = 'tab-btn px-4 py-1.5 text-xs font-semibold rounded-xl transition flex items-center space-x-2 bg-gradient-to-r from-brand-600 to-red-600 text-white shadow-md shadow-red-950/40';
    }

    if (tabId === 'tab-compliance') {
        loadComplianceData();
    }
}

// ─── 1. Attack Catalog & 14-Attack Grid ─────────────────────────────────
async function loadAttackCatalog() {
    try {
        const res = await fetch('/api/attack-catalog');
        const data = await res.json();
        ATTACK_CATALOG = data.catalog || [];
        renderAttackGrid();
    } catch (err) {
        console.error('Error loading attack catalog:', err);
    }
}

function renderAttackGrid() {
    const grid = document.getElementById('attackGrid');
    if (!grid) return;
    grid.innerHTML = '';

    ATTACK_CATALOG.forEach(atk => {
        const card = document.createElement('div');
        card.className = 'bg-darkbg/80 hover:bg-slate-800/60 border border-darkborder hover:border-slate-600 rounded-xl p-2 cursor-pointer transition flex flex-col justify-between';
        card.onclick = () => openAttackModal(atk.id.toLowerCase().replace('-', '_'));

        const sevColor = atk.severity === 'Critical' ? 'text-red-400' : (atk.severity === 'High' ? 'text-amber-400' : 'text-blue-400');

        card.innerHTML = `
            <div>
                <div class="flex items-center justify-between mb-0.5">
                    <span class="text-[9px] font-mono text-slate-500">${atk.id}</span>
                    <span class="text-[9px] font-bold ${sevColor}">${atk.severity}</span>
                </div>
                <h4 class="text-[10.5px] font-semibold text-slate-200 line-clamp-2 leading-tight">${atk.name}</h4>
            </div>
            <span class="text-[9px] text-slate-500 mt-1.5 block font-mono">${atk.target_id}</span>
        `;
        grid.appendChild(card);
    });
}

// ─── 2. Folder Presets & Scanning ───────────────────────────────────────
function selectPreset(presetId) {
    document.querySelectorAll('.preset-btn').forEach(btn => {
        btn.classList.remove('bg-brand-600', 'text-white', 'border-red-500');
        btn.classList.add('bg-slate-800/80', 'text-slate-200', 'border-slate-700');
    });

    const btn = document.getElementById(`btnPreset-${presetId}`);
    if (btn) {
        btn.classList.remove('bg-slate-800/80', 'text-slate-200', 'border-slate-700');
        btn.classList.add('bg-brand-600', 'text-white', 'border-red-500');
    }

    document.getElementById('inputFolderPath').value = presetId;
    triggerScan(presetId);
}

async function handleScanClick() {
    const path = document.getElementById('inputFolderPath').value.trim();
    if (!path) {
        showToast('Please enter a valid folder path or select a preset.', 'warning');
        return;
    }
    triggerScan(path);
}

async function triggerScan(folderPath) {
    const scanBtn = document.getElementById('btnScanFolder');
    const scanIcon = document.getElementById('scanIcon');
    const scanBtnText = document.getElementById('scanBtnText');

    scanBtn.disabled = true;
    scanIcon.className = 'fa-solid fa-circle-notch fa-spin';
    scanBtnText.textContent = 'Analyzing...';

    try {
        const res = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ folder_path: folderPath, max_frames_per_file: 20000 })
        });

        if (!res.ok) {
            const errData = await res.json();
            throw new Error(errData.detail || 'Scan failed.');
        }

        const data = await res.json();
        CURRENT_SCAN_DATA = data;
        updateDashboardUI(data);
        showToast(`Scan complete: ${data.total_frames_analyzed.toLocaleString()} frames evaluated in ${data.processing_time_ms} ms.`, 'success');
    } catch (err) {
        console.error('Scan error:', err);
        showToast(err.message, 'error');
    } finally {
        scanBtn.disabled = false;
        scanIcon.className = 'fa-solid fa-magnifying-glass-chart';
        scanBtnText.textContent = 'Run EDR Scan';
    }
}

// ─── 3. UI Dashboard Updates ────────────────────────────────────────────
function updateDashboardUI(data) {
    // A. Manifest Bar
    const manifestBar = document.getElementById('manifestBar');
    manifestBar.classList.remove('hidden');
    document.getElementById('manifestFiles').textContent = `Target: ${data.folder_path} (${data.manifest.length} logs)`;
    document.getElementById('manifestFrames').textContent = `Analyzed: ${data.total_frames_analyzed.toLocaleString()} frames`;
    document.getElementById('manifestSpeed').textContent = `Processing Time: ${data.processing_time_ms} ms (${data.inference_latency_ms} ms ML latency)`;

    // B. Health Score & Subsystems
    const health = data.health || {};
    const telemetry = data.telemetry || {};
    const overallScore = health.overall_health_score || 100;

    document.getElementById('valOverallHealth').textContent = `${overallScore}%`;
    const healthCircle = document.getElementById('healthCircle');
    const offset = 213.6 - (213.6 * overallScore) / 100;
    healthCircle.style.strokeDashoffset = offset;

    const overallBadge = document.getElementById('badgeOverallStatus');
    if (overallScore < 60) {
        healthCircle.setAttribute('class', 'text-red-500 transition-all duration-1000');
        overallBadge.className = 'px-2 py-0.5 text-[10px] font-bold rounded-full bg-red-950 text-red-400 border border-red-800';
        overallBadge.textContent = 'CRITICAL RISK';
        document.getElementById('healthDesc').textContent = 'Severe cyber-physical anomaly detected across CAN control loops.';
    } else if (overallScore < 85) {
        healthCircle.setAttribute('class', 'text-amber-500 transition-all duration-1000');
        overallBadge.className = 'px-2 py-0.5 text-[10px] font-bold rounded-full bg-amber-950 text-amber-400 border border-amber-800';
        overallBadge.textContent = 'WARNING';
        document.getElementById('healthDesc').textContent = 'Subsystem degradation or intermittent injection attacks observed.';
    } else {
        healthCircle.setAttribute('class', 'text-emerald-500 transition-all duration-1000');
        overallBadge.className = 'px-2 py-0.5 text-[10px] font-bold rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800';
        overallBadge.textContent = 'HEALTHY';
        document.getElementById('healthDesc').textContent = 'All critical powertrain and CAN control loops operating normally.';
    }

    // Subsystem Cards
    document.getElementById('valBmsSoc').textContent = `${telemetry.battery_soc_pct}%`;
    document.getElementById('valBmsTemp').textContent = `${telemetry.battery_temp_c}°C`;
    document.getElementById('barBmsHealth').style.width = `${health.subsystems?.bms?.score || 95}%`;
    document.getElementById('txtBmsStatus').textContent = health.subsystems?.bms?.status || 'OPTIMAL';

    document.getElementById('valMotorRpm').innerHTML = `${telemetry.motor_rpm?.toLocaleString()} <span class="text-xs font-sans text-slate-400">RPM</span>`;
    document.getElementById('valVehicleSpeed').textContent = `${telemetry.vehicle_speed_kmh} km/h`;
    document.getElementById('barPowertrainHealth').style.width = `${health.subsystems?.powertrain?.score || 90}%`;
    document.getElementById('txtGearState').textContent = telemetry.gear_state || 'D';

    document.getElementById('valBusFps').innerHTML = `${telemetry.bus_load_fps?.toLocaleString()} <span class="text-xs font-sans text-slate-400">FPS</span>`;
    document.getElementById('valUniqueIds').textContent = `${telemetry.unique_can_ids} IDs`;
    document.getElementById('barNetworkHealth').style.width = `${health.subsystems?.network?.score || 95}%`;
    document.getElementById('txtActiveThreats').textContent = `${data.total_incidents} Incidents (${data.severity_breakdown?.Critical || 0} Critical)`;

    // Update Active Vehicle Metadata across all Tabs
    const vInfo = data.vehicle_info;
    if (vInfo) {
        // Tab 2: Digital Twin Badge & CAN Registry
        const dtBadge = document.getElementById('digitalTwinPlatformBadge');
        if (dtBadge) dtBadge.textContent = `ACTIVE PLATFORM: ${vInfo.name} (${vInfo.model}) • ${vInfo.bus_type}`;

        const chTag = document.getElementById('svgActiveChassisTag');
        if (chTag) chTag.textContent = `PLATFORM: ${vInfo.name} (${vInfo.model})`;
        const busHeader = document.getElementById('svgBusTopologyHeader');
        if (busHeader) busHeader.textContent = `${vInfo.bus_type} Backbone`;

        const bmsLbl = document.getElementById('svgBmsLabel');
        const bmsIds = document.getElementById('svgBmsCanIds');
        const mcuLbl = document.getElementById('svgMcuLabel');
        const mcuSub = document.getElementById('svgMcuSub');
        const vcuLbl = document.getElementById('svgVcuLabel');
        const tcuLbl = document.getElementById('svgTcuLabel');
        const tcuIds = document.getElementById('svgTcuIds');
        const clsIds = document.getElementById('svgClusterIds');

        if (vInfo.key === 'Tata_Nexon_EV') {
            if (bmsLbl) bmsLbl.textContent = 'Ziptron 320V LFP';
            if (bmsIds) bmsIds.textContent = '0x380 / 0x480';
            if (mcuLbl) mcuLbl.textContent = 'MCU 0x180';
            if (mcuSub) mcuSub.textContent = 'PMSM Inverter';
            if (vcuLbl) vcuLbl.textContent = 'VCU 0x280';
            if (tcuLbl) tcuLbl.textContent = 'iRA 4G TCU';
            if (tcuIds) tcuIds.textContent = '0x5A0';
            if (clsIds) clsIds.textContent = '0x610 Speed';
        } else if (vInfo.key === 'BYD_Atto3') {
            if (bmsLbl) bmsLbl.textContent = 'Blade Battery 400V';
            if (bmsIds) bmsIds.textContent = '0x208 / 0x218';
            if (mcuLbl) mcuLbl.textContent = 'MCU 0x328';
            if (mcuSub) mcuSub.textContent = '8-in-1 E-Drive';
            if (vcuLbl) vcuLbl.textContent = 'VCU 0x438';
            if (tcuLbl) tcuLbl.textContent = 'DiLink 5G TCU';
            if (tcuIds) tcuIds.textContent = '0x5E0';
            if (clsIds) clsIds.textContent = '0x6A8 Cockpit';
        } else if (vInfo.key === 'MG_ZS_EV') {
            if (bmsLbl) bmsLbl.textContent = 'CATL 50.3kWh Pack';
            if (bmsIds) bmsIds.textContent = '0x1B6 / 0x2C4';
            if (mcuLbl) mcuLbl.textContent = 'MCU 0x3D8';
            if (mcuSub) mcuSub.textContent = 'Sync Motor';
            if (vcuLbl) vcuLbl.textContent = 'VCU 0x4D0';
            if (tcuLbl) tcuLbl.textContent = 'i-SMART TCU';
            if (tcuIds) tcuIds.textContent = '0x560';
            if (clsIds) clsIds.textContent = '0x620 Cluster';
        }

        if (vInfo.can_ids) {
            if (ECU_REGISTRY['bms']) ECU_REGISTRY['bms'].canIds = vInfo.can_ids.bms;
            if (ECU_REGISTRY['mcu']) ECU_REGISTRY['mcu'].canIds = vInfo.can_ids.mcu;
            if (ECU_REGISTRY['vcu']) ECU_REGISTRY['vcu'].canIds = vInfo.can_ids.vcu;
            if (ECU_REGISTRY['tcu']) ECU_REGISTRY['tcu'].canIds = vInfo.can_ids.tcu;
            if (ECU_REGISTRY['cluster']) ECU_REGISTRY['cluster'].canIds = vInfo.can_ids.cluster;
            if (ECU_REGISTRY['ccs2']) ECU_REGISTRY['ccs2'].canIds = vInfo.can_ids.ccs2;
            inspectECU(ACTIVE_ECU_NODE || 'bms');
        }

        // Tab 3: CERT-In Compliance Docket
        const certInName = document.getElementById('certInVehicleName');
        if (certInName) certInName.textContent = `${vInfo.name} (${vInfo.oem})`;
        const certInVin = document.getElementById('certInVin');
        if (certInVin) certInVin.textContent = vInfo.vin;
        const certInDocket = document.getElementById('certInDocketId');
        if (certInDocket) certInDocket.textContent = `DOCKET: CERTIN-EVS-${vInfo.key}`;

        // Tab 3: On-screen preview fields
        const dispPlatform = document.getElementById('dispAssetPlatform');
        if (dispPlatform) dispPlatform.textContent = vInfo.name;
        const dispVin = document.getElementById('dispAssetVin');
        if (dispVin) dispVin.textContent = vInfo.vin;
        const dispOem = document.getElementById('dispAssetOem');
        if (dispOem) dispOem.textContent = vInfo.oem;
        const dispBattery = document.getElementById('dispAssetBattery');
        if (dispBattery) dispBattery.textContent = `${vInfo.voltage} (${vInfo.battery_capacity})`;
        const dispBus = document.getElementById('dispAssetBus');
        if (dispBus) dispBus.textContent = vInfo.bus_type;
    }

    // C. Render Compact Incident Table
    renderIncidentTable(data.incidents || []);
}

// ─── 4. Incident Table Rendering & Filtering ────────────────────────────
function filterIncidents(sev) {
    CURRENT_FILTER = sev;
    document.querySelectorAll('.filter-tab').forEach(tab => tab.classList.remove('active-tab'));
    const activeBtn = document.getElementById(`tab-${sev}`);
    if (activeBtn) activeBtn.classList.add('active-tab');

    if (CURRENT_SCAN_DATA) {
        let filtered = CURRENT_SCAN_DATA.incidents || [];
        if (sev !== 'ALL') {
            filtered = filtered.filter(i => i.severity === sev);
        }
        renderIncidentTable(filtered);
    }
}

function renderIncidentTable(incidents) {
    const tbody = document.getElementById('incidentTableBody');
    const lblCount = document.getElementById('lblIncidentCount');
    const txtShowing = document.getElementById('txtShowingRows');
    if (!tbody) return;
    tbody.innerHTML = '';

    const totalCount = incidents.length;
    lblCount.textContent = totalCount > 0 ? `(${totalCount} Total)` : '';

    if (totalCount === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="py-6 text-center text-slate-500 font-sans text-xs">
                    <i class="fa-solid fa-shield-check text-xl text-emerald-500 mb-1.5 block"></i>
                    No attack incidents found for the selected filter (${CURRENT_FILTER}).
                </td>
            </tr>
        `;
        txtShowing.textContent = 'Showing 0 incidents';
        return;
    }

    const compactList = incidents.slice(0, 5);
    txtShowing.textContent = `Showing latest ${compactList.length} of ${totalCount} incidents`;

    compactList.forEach(inc => {
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-darkbg/60 transition';

        const sevClass = inc.severity === 'Critical' ? 'badge-critical' : (inc.severity === 'High' ? 'badge-high' : 'badge-medium');

        tr.innerHTML = `
            <td class="py-2 px-2.5">
                <span class="font-bold text-white block text-[11px]">${inc.incident_id}</span>
                <span class="text-[9px] text-slate-500">${inc.start_timestamp}</span>
            </td>
            <td class="py-2 px-2.5">
                <span class="font-semibold text-slate-200 block font-sans text-[11px]">${inc.display_name}</span>
                <span class="text-[9px] text-slate-500 font-mono">${inc.target_identifier}</span>
            </td>
            <td class="py-2 px-2.5 font-sans text-slate-400 text-[10.5px]">
                ${inc.target_subsystem}
            </td>
            <td class="py-2 px-2.5 text-[11px]">
                <span class="text-white">${inc.frame_count.toLocaleString()}</span>
                <span class="text-[9px] text-slate-500 block">${inc.duration_seconds}s</span>
            </td>
            <td class="py-2 px-2.5">
                <span class="px-1.5 py-0.2 rounded-full text-[9px] font-bold ${sevClass}">${inc.severity}</span>
            </td>
            <td class="py-2 px-2.5 text-right space-x-1.5 font-sans whitespace-nowrap">
                <button onclick="openAttackModal('${inc.attack_type}')" title="Click to view full plain-English & engineering threat explanation" class="inline-flex items-center px-2 py-0.5 bg-indigo-950/90 hover:bg-indigo-900 text-indigo-200 border border-indigo-700/80 hover:border-indigo-400 text-[10px] font-semibold rounded-md shadow-sm transition hover:scale-105 active:scale-95">
                    <i class="fa-solid fa-circle-info mr-1 text-cyan-400"></i>Explain
                </button>
                <button onclick="triggerMitigation('isolate_node', '${inc.incident_id}', '${inc.target_identifier}')" title="Trigger autonomous transceiver quarantine" class="inline-flex items-center px-2 py-0.5 bg-red-950/90 hover:bg-red-900 text-red-200 border border-red-800/80 hover:border-red-500 text-[10px] font-semibold rounded-md shadow-sm transition hover:scale-105 active:scale-95">
                    <i class="fa-solid fa-shield mr-1 text-red-400"></i>Mitigate
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

// ─── 5. Full Incidents Modal Table ──────────────────────────────────────
function openAllIncidentsModal() {
    if (!CURRENT_SCAN_DATA || !CURRENT_SCAN_DATA.incidents) {
        showToast('No scan data available. Please run an EDR scan first.', 'warning');
        return;
    }
    document.getElementById('allIncidentsModal').classList.remove('hidden');
    renderModalIncidentTable(CURRENT_SCAN_DATA.incidents);
}

function closeAllIncidentsModal() {
    document.getElementById('allIncidentsModal').classList.add('hidden');
}

function handleModalSearch() {
    const query = document.getElementById('inputModalSearch').value.toLowerCase().trim();
    if (!CURRENT_SCAN_DATA || !CURRENT_SCAN_DATA.incidents) return;

    const filtered = CURRENT_SCAN_DATA.incidents.filter(inc => {
        return (inc.display_name && inc.display_name.toLowerCase().includes(query)) ||
               (inc.target_identifier && inc.target_identifier.toLowerCase().includes(query)) ||
               (inc.target_subsystem && inc.target_subsystem.toLowerCase().includes(query)) ||
               (inc.severity && inc.severity.toLowerCase().includes(query));
    });
    renderModalIncidentTable(filtered);
}

function renderModalIncidentTable(incidents) {
    const tbody = document.getElementById('modalIncidentTableBody');
    const txtCount = document.getElementById('txtModalFilteredCount');
    if (!tbody) return;
    tbody.innerHTML = '';

    txtCount.textContent = `Showing ${incidents.length} incident records`;

    if (incidents.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="py-8 text-center text-slate-500 font-sans text-xs">No incidents match search criteria.</td></tr>`;
        return;
    }

    incidents.forEach(inc => {
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-darkbg/60 transition';
        const sevClass = inc.severity === 'Critical' ? 'badge-critical' : (inc.severity === 'High' ? 'badge-high' : 'badge-medium');

        tr.innerHTML = `
            <td class="py-2 px-3">
                <span class="font-bold text-white block text-[11px]">${inc.incident_id}</span>
                <span class="text-[9px] text-slate-500">${inc.start_timestamp}</span>
            </td>
            <td class="py-2 px-3 font-semibold text-slate-200 font-sans text-[11.5px]">${inc.display_name}</td>
            <td class="py-2 px-3 font-sans text-slate-400 text-[11px]">${inc.target_subsystem}</td>
            <td class="py-2 px-3 font-mono text-[11px] text-slate-300">${inc.target_identifier}</td>
            <td class="py-2 px-3 text-[11px] text-white">${inc.frame_count.toLocaleString()}</td>
            <td class="py-2 px-3"><span class="px-2 py-0.5 rounded-full text-[9.5px] font-bold ${sevClass}">${inc.severity}</span></td>
            <td class="py-2 px-3 text-right space-x-1.5 font-sans whitespace-nowrap">
                <button onclick="openAttackModal('${inc.attack_type}')" title="Click to view deep plain-English & technical explanation" class="inline-flex items-center px-2.5 py-0.5 bg-indigo-950/90 hover:bg-indigo-900 text-indigo-200 border border-indigo-700/80 hover:border-indigo-400 text-[10.5px] font-semibold rounded-md shadow-sm transition hover:scale-105 active:scale-95">
                    <i class="fa-solid fa-circle-info mr-1 text-cyan-400"></i>Explain
                </button>
                <button onclick="triggerMitigation('isolate_node', '${inc.incident_id}', '${inc.target_identifier}')" title="Trigger autonomous transceiver quarantine" class="inline-flex items-center px-2.5 py-0.5 bg-red-950/90 hover:bg-red-900 text-red-200 border border-red-800/80 hover:border-red-500 text-[10.5px] font-semibold rounded-md shadow-sm transition hover:scale-105 active:scale-95">
                    <i class="fa-solid fa-shield mr-1 text-red-400"></i>Quarantine
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

// ─── 6. Attack Explainability Modal (14 Attacks) ────────────────────────
async function openAttackModal(attackType) {
    try {
        const res = await fetch(`/api/attack-details/${attackType}`);
        const data = await res.json();

        const attackId = data.id || 'ATK';
        const attackName = data.name || attackType.replace('_', ' ').toUpperCase();
        document.getElementById('modalAttackId').textContent = attackId;
        document.getElementById('modalAttackName').textContent = attackName;

        const targetDesc = data.target_id || (data.target_ecus ? data.target_ecus.join(', ') : 'CAN Bus');
        const impactDesc = (data.target_ecus && data.target_ecus.length) ? data.target_ecus.join(', ') : (data.subsystem_impact || data.layer || 'Vehicle Subsystem');
        document.getElementById('modalAttackLayer').textContent = `Target: ${targetDesc} | Subsystem: ${impactDesc}`;

        // Threat Mechanism & Description
        const descText = data.description || data.mechanism || "Anomalous cyber-physical frame patterns detected on in-vehicle network.";
        document.getElementById('modalAttackDesc').textContent = descText;

        // Physical Risk
        const riskText = data.physical_risk || "Potential loss of steering/braking situational awareness or battery pack degradation.";
        document.getElementById('modalAttackRisk').textContent = riskText;

        // Mathematical / Detection Signals
        const signalsText = data.detection_signals || "Inter-arrival Δt collapse (< 0.2ms) and Shannon entropy boundary breach.";
        document.getElementById('modalAttackSignals').textContent = signalsText;

        // ISO Reference
        const isoText = data.iso_21434_ref || data.iso_reference || "ISO/SAE 21434 Road Vehicles Cybersecurity";
        const calLevel = data.tara_cal_level || (data.severity === 'Critical' ? 'CAL-4' : (data.severity === 'High' ? 'CAL-3' : 'CAL-2'));
        document.getElementById('modalIsoRef').textContent = `${isoText} | Security Level: ${calLevel}`;

        // Plain English Driver Steps
        const driverUl = document.getElementById('modalDriverSteps');
        driverUl.innerHTML = '';
        const driverSteps = data.simple_driver_steps || data.driver_actions || [
            "🟢 1. Safely pull over to the road shoulder and come to a smooth stop.",
            "🟢 2. Allow vehicle to engage automated Limp-Home Mode.",
            "🟢 3. Restart vehicle after 60 seconds and schedule an authorized diagnostic check."
        ];
        driverSteps.forEach(step => {
            const li = document.createElement('li');
            li.className = 'flex items-start space-x-1.5';
            li.innerHTML = `<span class="text-emerald-400 font-bold">•</span><span>${step}</span>`;
            driverUl.appendChild(li);
        });

        // Technical Mitigation Playbook
        const playbookUl = document.getElementById('modalAttackPlaybook');
        playbookUl.innerHTML = '';
        const playbookSteps = data.mitigation_playbook || data.technical_playbook || [
            "🔧 1. Activate CAN transceiver mailbox rate-limiter.",
            "🔧 2. Isolate compromised arbitration ID at central domain gateway.",
            "🔧 3. Enforce cryptographic freshness counter verification."
        ];
        playbookSteps.forEach(action => {
            const li = document.createElement('li');
            li.className = 'flex items-start space-x-1.5';
            li.innerHTML = `<span class="text-blue-400 font-bold">›</span><span>${action}</span>`;
            playbookUl.appendChild(li);
        });

        const modal = document.getElementById('attackModal');
        if (modal) {
            modal.classList.remove('hidden');
        }
    } catch (err) {
        console.error('Error fetching attack details:', err);
        showToast('Failed to load attack details. Please try again.', 'error');
    }
}

function closeAttackModal() {
    document.getElementById('attackModal').classList.add('hidden');
}

function askAiAboutCurrentAttack() {
    const attackName = document.getElementById('modalAttackName').textContent;
    closeAttackModal();
    const chatInput = document.getElementById('chatInput');
    if (chatInput) {
        chatInput.value = `Explain the cyber-physical risk and mitigation for ${attackName} in simple terms.`;
        const form = document.getElementById('chatForm');
        if (form) {
            form.dispatchEvent(new Event('submit'));
        }
    }
}

// ─── 7. AI Incident Response Chatbot ────────────────────────────────────
async function handleChatSubmit(e) {
    e.preventDefault();
    const input = document.getElementById('chatInput');
    const query = input.value.trim();
    if (!query) return;

    appendChatMessage('user', query);
    input.value = '';

    const typingId = appendChatMessage('ai', '...', true);

    try {
        const res = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query: query, scan_context: CURRENT_SCAN_DATA })
        });
        const data = await res.json();
        removeTypingIndicator(typingId);
        appendChatMessage('ai', data.reply);
    } catch (err) {
        removeTypingIndicator(typingId);
        appendChatMessage('ai', 'Sorry, I encountered an error answering your query.');
    }
}

function askPrompt(text) {
    document.getElementById('chatInput').value = text;
    document.getElementById('chatForm').dispatchEvent(new Event('submit'));
}

function appendChatMessage(sender, text, isTyping = false) {
    const container = document.getElementById('chatMessages');
    const msgId = 'msg-' + Date.now();
    const div = document.createElement('div');
    div.id = msgId;

    if (sender === 'user') {
        div.className = 'bg-slate-800/90 text-white rounded-xl p-2 ml-4 border border-slate-700 text-[11px]';
        div.textContent = text;
    } else {
        div.className = 'bg-darkbg/90 border border-darkborder rounded-xl p-2.5 mr-2 text-slate-300 text-[11px]';
        let formatted = text
            .replace(/### (.*?)\n/g, '<h4 class="font-bold text-white text-xs mb-1">$1</h4>')
            .replace(/#### (.*?)\n/g, '<h5 class="font-bold text-slate-200 text-[10.5px] mt-1.5 mb-0.5">$1</h5>')
            .replace(/\*\*(.*?)\*\*/g, '<strong class="text-white">$1</strong>')
            .replace(/• (.*?)\n/g, '<div class="flex items-start space-x-1 my-0.5"><span class="text-red-400">•</span><span>$1</span></div>')
            .replace(/\n/g, '<br>');

        div.innerHTML = formatted;
    }

    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
    return msgId;
}

function removeTypingIndicator(id) {
    const el = document.getElementById(id);
    if (el) el.remove();
}

// ─── 8. Active Mitigation Action & Toast ────────────────────────────────
async function triggerMitigation(actionType, incidentId, targetId) {
    try {
        const res = await fetch('/api/trigger-action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action_type: actionType, incident_id: incidentId, target_identifier: targetId })
        });
        const data = await res.json();
        showToast(data.message, 'success');
    } catch (err) {
        showToast('Mitigation action failed to execute.', 'error');
    }
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    const bg = type === 'success' ? 'bg-emerald-950 text-emerald-200 border-emerald-800' : (type === 'warning' ? 'bg-amber-950 text-amber-200 border-amber-800' : 'bg-red-950 text-red-200 border-red-800');

    toast.className = `p-2.5 rounded-xl border text-xs shadow-2xl transition-all duration-300 flex items-center space-x-2 ${bg}`;
    toast.innerHTML = `
        <i class="fa-solid ${type === 'success' ? 'fa-circle-check text-emerald-400' : 'fa-circle-exclamation text-red-400'}"></i>
        <span>${message}</span>
    `;

    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

function handleExportReport() {
    window.location.href = '/api/export-report';
}

// ─── 9. DIGITAL TWIN SIMULATOR & ECU INSPECTOR (TAB 2) ──────────────────
function inspectECU(nodeKey) {
    ACTIVE_ECU_NODE = nodeKey;
    const info = ECU_REGISTRY[nodeKey];
    if (!info) return;

    document.getElementById('inspectorTitle').textContent = info.title;
    document.getElementById('inspectorDesc').textContent = info.desc;
    document.getElementById('inspectorCanIds').textContent = info.canIds;
    document.getElementById('inspectorInterval').textContent = info.interval;
    document.getElementById('inspectorTransceiver').textContent = info.transceiver;
    document.getElementById('inspectorFirewall').textContent = info.firewall;

    const schemaDiv = document.getElementById('inspectorSchema');
    schemaDiv.innerHTML = '';
    info.schema.forEach(s => {
        const d = document.createElement('div');
        d.textContent = s;
        schemaDiv.appendChild(d);
    });

    // Highlight node in SVG
    document.querySelectorAll('.node-group circle, .node-group rect').forEach(shape => {
        shape.style.filter = 'none';
    });
    const activeGroup = document.getElementById(`node-${nodeKey}`);
    if (activeGroup) {
        const shape = activeGroup.querySelector('circle') || activeGroup.querySelector('rect');
        if (shape) shape.style.filter = 'drop-shadow(0 0 8px rgba(99, 102, 241, 0.8))';
    }
}

async function injectSimulatedAttack(attackType) {
    try {
        const res = await fetch('/api/simulate-attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ attack_type: attackType })
        });
        const data = await res.json();
        const d = data.details;

        const simDot = document.getElementById('simDot');
        const simTitle = document.getElementById('simTitle');
        const simMitigation = document.getElementById('simMitigation');
        const backbone = document.getElementById('canBackbone');
        const qShield = document.getElementById('svgQuarantineShield');
        const p1 = document.getElementById('pipelineStep1');
        const p2 = document.getElementById('pipelineStep2');
        const p3 = document.getElementById('pipelineStep3');

        // Reset all droplines to normal
        resetDroplines();

        if (attackType === 'clean') {
            simDot.className = 'w-2.5 h-2.5 rounded-full bg-emerald-500';
            simTitle.textContent = `State: ${d.attack_name}`;
            simMitigation.textContent = d.mitigation;
            simMitigation.className = 'font-mono text-[11px] text-emerald-400';
            backbone.setAttribute('stroke', '#d97706');
            if (qShield) qShield.classList.add('hidden');
            resetSvgNodeColors();
            if (p1) p1.textContent = 'None (Nominal Bus Traffic)';
            if (p2) p2.textContent = '5.2 µs Hybrid ML Active';
            if (p3) p3.textContent = 'All Transceivers Healthy';
            showToast('Digital Twin restored to clean nominal state.', 'success');
        } else {
            simDot.className = 'w-2.5 h-2.5 rounded-full bg-red-500 animate-ping';
            simTitle.textContent = `CRITICAL ATTACK: ${d.attack_name}`;
            simMitigation.textContent = `EDR Mitigating: ${d.mitigation}`;
            simMitigation.className = 'font-mono text-[11px] text-red-400 font-bold';
            backbone.setAttribute('stroke', '#ef4444');

            // Determine target node coordinates and dropline
            let targetNodeId = 'node-obd';
            let targetDropLine = 'dropline-obd';
            let cx = 660, cy = 170;
            let lockCx = 620, lockCy = 170;

            if (attackType === 'bms_overcharge') {
                targetNodeId = 'node-bms';
                targetDropLine = 'dropline-bms';
                cx = 390; cy = 245;
                lockCx = 390; lockCy = 195;
            } else if (attackType === 'speed_spoof') {
                targetNodeId = 'node-cluster';
                targetDropLine = 'dropline-cluster';
                cx = 580; cy = 230;
                lockCx = 580; lockCy = 195;
            } else if (attackType === 'ccs2_portulator') {
                targetNodeId = 'node-ccs2';
                targetDropLine = 'dropline-ccs2';
                cx = 90; cy = 120;
                lockCx = 130; lockCy = 145;
            }

            // Position and show quarantine shield
            if (qShield) {
                qShield.classList.remove('hidden');
                const ring = document.getElementById('quarantineRing');
                if (ring) { ring.setAttribute('cx', cx); ring.setAttribute('cy', cy); }
                const badgeBg = document.getElementById('quarantineBadgeBg');
                if (badgeBg) { badgeBg.setAttribute('x', cx - 45); badgeBg.setAttribute('y', cy - 42); }
                const badgeTxt = document.getElementById('quarantineBadgeText');
                if (badgeTxt) { badgeTxt.setAttribute('x', cx); badgeTxt.setAttribute('y', cy - 30); }
                const lockCircle = document.getElementById('quarantineLockCircle');
                if (lockCircle) { lockCircle.setAttribute('cx', lockCx); lockCircle.setAttribute('cy', lockCy); }
                const lockIcon = document.getElementById('quarantineLockIcon');
                if (lockIcon) { lockIcon.setAttribute('x', lockCx); lockIcon.setAttribute('y', lockCy + 4); }
            }

            // Sever dropline to compromised ECU
            const dl = document.getElementById(targetDropLine);
            if (dl) {
                dl.setAttribute('stroke', '#ef4444');
                dl.setAttribute('stroke-width', '3.5');
                dl.setAttribute('stroke-dasharray', '2,4');
            }

            // Update 3-stage quarantine pipeline cards
            if (p1) p1.textContent = `${d.affected_can_id}: ${d.attack_name.split(' ')[0]}`;
            if (p2) p2.textContent = '5.2 µs Hybrid ML (CAL-4 Confirmed)';
            if (p3) p3.textContent = d.mitigation;

            highlightAttackedSvgNode(targetNodeId);
            showToast(`Injected ${d.attack_name}! Gateway quarantined node in 5.2 µs.`, 'warning');
        }
    } catch (err) {
        console.error('Error simulating attack:', err);
    }
}

function resetDroplines() {
    const defaults = {
        'dropline-ccs2': { stroke: '#06b6d4', width: '2', dash: '2,2' },
        'dropline-mcu': { stroke: '#3b82f6', width: '2', dash: '3,3' },
        'dropline-vcu': { stroke: '#8b5cf6', width: '2', dash: '3,3' },
        'dropline-gateway': { stroke: '#6366f1', width: '2.5', dash: 'none' },
        'dropline-bms': { stroke: '#10b981', width: '2.5', dash: '3,3' },
        'dropline-tcu': { stroke: '#0ea5e9', width: '2', dash: '3,3' },
        'dropline-cluster': { stroke: '#f59e0b', width: '2', dash: '3,3' },
        'dropline-obd': { stroke: '#ef4444', width: '2', dash: '3,3' }
    };
    for (const [id, cfg] of Object.entries(defaults)) {
        const line = document.getElementById(id);
        if (line) {
            line.setAttribute('stroke', cfg.stroke);
            line.setAttribute('stroke-width', cfg.width);
            if (cfg.dash === 'none') line.removeAttribute('stroke-dasharray');
            else line.setAttribute('stroke-dasharray', cfg.dash);
        }
    }
}

function highlightAttackedSvgNode(nodeId) {
    resetSvgNodeColors();
    const g = document.getElementById(nodeId);
    if (!g) return;
    const shape = g.querySelector('circle') || g.querySelector('rect');
    if (shape) {
        shape.setAttribute('stroke', '#ef4444');
        shape.setAttribute('stroke-width', '4');
        shape.style.filter = 'drop-shadow(0 0 14px rgba(239, 68, 68, 0.9))';
    }
}

function resetSvgNodeColors() {
    const defaults = {
        'node-ccs2': '#06b6d4',
        'node-mcu': '#3b82f6',
        'node-vcu': '#8b5cf6',
        'node-gateway': '#6366f1',
        'node-bms': '#10b981',
        'node-tcu': '#0ea5e9',
        'node-cluster': '#f59e0b',
        'node-obd': '#ef4444'
    };
    for (const [id, color] of Object.entries(defaults)) {
        const g = document.getElementById(id);
        if (g) {
            const shape = g.querySelector('circle') || g.querySelector('rect');
            if (shape) {
                shape.setAttribute('stroke', color);
                shape.setAttribute('stroke-width', id === 'node-gateway' ? '3.5' : '2');
                shape.style.filter = 'none';
            }
        }
    }
}

function toggleNodeIsolation() {
    const info = ECU_REGISTRY[ACTIVE_ECU_NODE];
    showToast(`Quarantined ${info ? info.title : 'Node'} via Central Gateway Mailbox Filter.`, 'success');
}

// ─── 10. COMPLIANCE & CERT-IN MANDATORY REPORTING (TAB 3) ───────────────
function startCertInTimer() {
    setInterval(() => {
        if (CERTIN_COUNTDOWN_SECONDS > 0) {
            CERTIN_COUNTDOWN_SECONDS--;
            const h = String(Math.floor(CERTIN_COUNTDOWN_SECONDS / 3600)).padStart(2, '0');
            const m = String(Math.floor((CERTIN_COUNTDOWN_SECONDS % 3600) / 60)).padStart(2, '0');
            const s = String(CERTIN_COUNTDOWN_SECONDS % 60).padStart(2, '0');
            const el = document.getElementById('certInTimer');
            if (el) el.textContent = `${h}h : ${m}m : ${s}s`;
        }
    }, 1000);
}

function downloadCertInJson() {
    window.location.href = '/api/certin-dispatch';
    showToast('Downloaded official CERT-In Incident Notification JSON dispatch.', 'success');
}

async function openCertInModal() {
    try {
        const res = await fetch('/api/certin-dispatch');
        const d = await res.json();
        
        const docket = document.getElementById('mCertDocketId');
        if (docket) docket.textContent = d.report_id || 'CERTIN-EVS-2026';
        const ts = document.getElementById('mCertTimestamp');
        if (ts) ts.textContent = d.submission_timestamp || new Date().toISOString();
        
        const asset = d.target_asset || {};
        const oem = document.getElementById('mCertOem');
        if (oem) oem.textContent = asset.vehicle_oem || 'Tata Motors Ltd.';
        const mdl = document.getElementById('mCertModel');
        if (mdl) mdl.textContent = asset.model_architecture || 'Tata Nexon EV';
        const vin = document.getElementById('mCertVin');
        if (vin) vin.textContent = asset.vin || 'MAT621008P4N09124';
        const bat = document.getElementById('mCertBattery');
        if (bat) bat.textContent = `${asset.powertrain_type || ''} (${asset.battery_capacity || ''})`;
        const bus = document.getElementById('mCertBus');
        if (bus) bus.textContent = asset.in_vehicle_bus_rate || '500 kbps High-Speed CAN';
        
        const classif = d.incident_classification || {};
        const vec = document.getElementById('mCertThreatVector');
        if (vec) vec.textContent = classif.primary_threat_vector || 'CAN Bus Arbitration Flooding & Sensor Manipulation';
        
        const ioc = d.technical_indicators_of_compromise || {};
        const ids = document.getElementById('mCertCompromisedIds');
        if (ids) {
            ids.textContent = ioc.compromised_arbitration_ids ? ioc.compromised_arbitration_ids.join(', ') : '0x000 (DoS), 0x1C7 (BMS), 0x5A0 (Speed)';
        }
        const burst = document.getElementById('mCertBurstRate');
        if (burst) burst.textContent = ioc.frame_burst_rate || '4,200 frames/sec (Overload threshold: 3,500 fps)';
        
        const modal = document.getElementById('certInModal');
        if (modal) modal.classList.remove('hidden');
    } catch (err) {
        console.error('Error opening CERT-In modal:', err);
        showToast('Error loading CERT-In docket information', 'error');
    }
}

function closeCertInModal() {
    const modal = document.getElementById('certInModal');
    if (modal) modal.classList.add('hidden');
}

async function loadComplianceData() {
    try {
        const res = await fetch('/api/thermal-safety');
        const data = await res.json();
        const tg = document.getElementById('valThermalGradient');
        if (tg) tg.textContent = data.thermal_gradient_c_per_min;
        const cv = document.getElementById('valCellVariance');
        if (cv) cv.textContent = data.cell_voltage_variance_mv;
        const cp = document.getElementById('valCoolingPump');
        if (cp) cp.textContent = data.active_liquid_cooling_pump;

        if (data.vehicle_info) {
            const v = data.vehicle_info;
            const certInName = document.getElementById('certInVehicleName');
            if (certInName) certInName.textContent = `${v.name} (${v.oem})`;
            const certInVin = document.getElementById('certInVin');
            if (certInVin) certInVin.textContent = v.vin;
            const certInDocket = document.getElementById('certInDocketId');
            if (certInDocket) certInDocket.textContent = `DOCKET: CERTIN-EVS-${v.key}`;

            const dispPlatform = document.getElementById('dispAssetPlatform');
            if (dispPlatform) dispPlatform.textContent = v.name;
            const dispVin = document.getElementById('dispAssetVin');
            if (dispVin) dispVin.textContent = v.vin;
            const dispOem = document.getElementById('dispAssetOem');
            if (dispOem) dispOem.textContent = v.oem;
            const dispBattery = document.getElementById('dispAssetBattery');
            if (dispBattery) dispBattery.textContent = `${v.voltage} (${v.battery_capacity})`;
            const dispBus = document.getElementById('dispAssetBus');
            if (dispBus) dispBus.textContent = v.bus_type;
        }
    } catch (err) {
        console.error('Error loading compliance data:', err);
    }
}
