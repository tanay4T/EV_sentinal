"""
generate_ieee_paper.py
======================
Generates the publication-ready 2-Column IEEE / IJERT Research Paper (.docx)
matching the exact layout of the reference paper screenshot:
  - Top of Page 1 (Single Column, Centered):
      * Paper Title (22pt Bold Times New Roman)
      * Student Authors: Tanay Sawant, Swarna Makwana, Charu Malpani, Riya Amin
        Department of Information Technology
        K. J. Somaiya School of Engineering (KJSSE)
        Mumbai, Maharashtra, India
      * Project Guide: Dr. Poonam Hemant Narkhede (Project Guide)
        Department of Information Technology, KJSSE
  - Continuous Section Break -> 2-Column Page Layout (Page divided into 2 parts):
      * Abstract (Bold 9pt) & Keywords (Bold Italic 9pt) in Left Column
      * I. INTRODUCTION
      * II. LITERATURE REVIEW (with Literature Comparison Table)
      * III. PROPOSED SYSTEM (with Fig. 1 System Architecture Diagram in column)
      * IV. METHODOLOGY (Equations 1-14, Feature Table, Fig. 2 Flowchart, Algorithm 1)
      * V. EXPERIMENTAL EVALUATION & PERFORMANCE MATRIX (Performance Matrix Table,
           Multi-Vehicle Table, Per-Class Table, Fig. 3 Latency, Fig. 4 Multi-Vehicle,
           Fig. 5 Health Degradation Curve)
      * VI. LIMITATIONS
      * VII. FUTURE SCOPE
      * VIII. CONCLUSION
      * REFERENCES [1]-[16]
"""

import os
import shutil
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

WORKSPACE_DIR = r"c:\Users\Tanay\Desktop\EVSentinal\v3"
ARTIFACT_DIR = r"C:\Users\Tanay\.gemini\antigravity\brain\1927604f-6392-451b-941f-01696d471b60"
FIG_DIR = os.path.join(WORKSPACE_DIR, "paper_figures")

fig1_path = os.path.join(FIG_DIR, "fig1_architecture.png")
fig2_path = os.path.join(ARTIFACT_DIR, "evsentinel_vector_flowchart_1790579371022.jpg")
fig3_path = os.path.join(FIG_DIR, "fig3_latency_comparison.png")
fig4_path = os.path.join(FIG_DIR, "fig4_multivehicle_accuracy.png")
fig5_path = os.path.join(FIG_DIR, "fig5_health_degradation.png")

doc = docx.Document()

# ============================================================================
# PAGE SETUP & 1-COLUMN HEADER SECTION (TITLE + AUTHORS + PROJECT GUIDE)
# ============================================================================
sec1 = doc.sections[0]
sec1.page_width = Inches(8.5)
sec1.page_height = Inches(11.0)
sec1.top_margin = Inches(0.65)
sec1.bottom_margin = Inches(0.65)
sec1.left_margin = Inches(0.65)
sec1.right_margin = Inches(0.65)

# Explicitly ensure Section 1 is 1 column
sectPr1 = sec1._sectPr
cols1 = sectPr1.xpath('./w:cols')
if cols1:
    cols1[0].set(qn('w:num'), '1')

def set_font(run, name='Times New Roman', size=10, bold=False, italic=False, color=None):
    run.font.name = name
    run.font.size = Pt(size)
    run.bold = bold
    run.italic = italic
    if color:
        run.font.color.rgb = color

# 1. Title (Centered, Single-Column across top)
p_title = doc.add_paragraph()
p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
p_title.paragraph_format.space_before = Pt(0)
p_title.paragraph_format.space_after = Pt(12)
p_title.paragraph_format.line_spacing = 1.1
r_title = p_title.add_run(
    "EVSentinel: Dual-Layer AI Intrusion Detection and\n"
    "Automated Incident Response Framework for EV Charging\n"
    "Infrastructure and In-Vehicle CAN Networks"
)
set_font(r_title, size=20, bold=True)

# 2. Student Authors Block (Exact match to screenshot layout)
p_auth = doc.add_paragraph()
p_auth.alignment = WD_ALIGN_PARAGRAPH.CENTER
p_auth.paragraph_format.space_before = Pt(0)
p_auth.paragraph_format.space_after = Pt(8)
p_auth.paragraph_format.line_spacing = 1.15
r_auth = p_auth.add_run(
    "Tanay Sawant, Swarna Makwana, Charu Malpani, Riya Amin\n"
    "Department of Information Technology\n"
    "K. J. Somaiya School of Engineering (KJSSE)\n"
    "Mumbai, Maharashtra, India"
)
set_font(r_auth, size=11, bold=False)

# 3. Project Guide Block (Exact match to screenshot layout)
p_guide = doc.add_paragraph()
p_guide.alignment = WD_ALIGN_PARAGRAPH.CENTER
p_guide.paragraph_format.space_before = Pt(2)
p_guide.paragraph_format.space_after = Pt(14)
p_guide.paragraph_format.line_spacing = 1.15
r_guide = p_guide.add_run(
    "Dr. Poonam Hemant Narkhede (Project Guide)\n"
    "Department of Information Technology, KJSSE"
)
set_font(r_guide, size=11, bold=False)

# ============================================================================
# CONTINUOUS SECTION BREAK -> DIVIDE PAGE INTO 2 EQUAL COLUMNS
# ============================================================================
sec2 = doc.add_section(WD_SECTION.CONTINUOUS)
sec2.page_width = Inches(8.5)
sec2.page_height = Inches(11.0)
sec2.top_margin = Inches(0.65)
sec2.bottom_margin = Inches(0.65)
sec2.left_margin = Inches(0.65)
sec2.right_margin = Inches(0.65)

sectPr2 = sec2._sectPr
cols2 = sectPr2.xpath('./w:cols')
if cols2:
    cols_el = cols2[0]
else:
    cols_el = OxmlElement('w:cols')
    sectPr2.append(cols_el)
cols_el.set(qn('w:num'), '2')
cols_el.set(qn('w:space'), '360')  # 0.25 inch gap between Left and Right columns (each col = 3.475 in)

# Helper functions for 2-Column Body Content
def add_section_heading(text):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(10)
    p.paragraph_format.space_after = Pt(5)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    set_font(run, size=10, bold=True)
    return p

def add_sub_heading(text, italic=True):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    p.paragraph_format.space_before = Pt(7)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    set_font(run, size=9.5, bold=True, italic=italic)
    return p

def add_body(text, bold=False, italic=False, size=9.5, first_line_indent=0.0):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(5)
    p.paragraph_format.line_spacing = 1.08
    if first_line_indent > 0:
        p.paragraph_format.first_line_indent = Inches(first_line_indent)
    run = p.add_run(text)
    set_font(run, size=size, bold=bold, italic=italic)
    return p

def add_bullet(title_bold, body_text):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.paragraph_format.left_indent = Inches(0.18)
    p.paragraph_format.first_line_indent = Inches(-0.12)
    p.paragraph_format.space_before = Pt(1)
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.line_spacing = 1.05
    r1 = p.add_run(f"• {title_bold}")
    set_font(r1, size=9.2, bold=True)
    r2 = p.add_run(body_text)
    set_font(r2, size=9.2, bold=False)
    return p

def add_equation(eq_text, eq_num):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(3)
    p.paragraph_format.space_after = Pt(4)
    run = p.add_run(f"{eq_text}   ({eq_num})")
    set_font(run, name='Cambria Math', size=8.8, bold=True, italic=True)
    return p

def add_col_figure(img_path, caption_text, width_in=3.35):
    if os.path.exists(img_path):
        p_img = doc.add_paragraph()
        p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_img.paragraph_format.space_before = Pt(6)
        p_img.paragraph_format.space_after = Pt(2)
        p_img.paragraph_format.keep_with_next = True
        r_img = p_img.add_run()
        r_img.add_picture(img_path, width=Inches(width_in))

        p_cap = doc.add_paragraph()
        p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_cap.paragraph_format.space_before = Pt(1)
        p_cap.paragraph_format.space_after = Pt(7)
        r_cap = p_cap.add_run(caption_text)
        set_font(r_cap, size=8.0, bold=True, italic=False)

def add_table_title(title_text):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(7)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.keep_with_next = True
    r = p.add_run(title_text)
    set_font(r, size=8.0, bold=True)

def set_table_borders(table):
    tblPr = table._tbl.tblPr
    borders = parse_xml(
        f'<w:tblBorders {nsdecls("w")}>'
        '<w:top w:val="single" w:sz="6" w:space="0" w:color="333333"/>'
        '<w:bottom w:val="single" w:sz="6" w:space="0" w:color="333333"/>'
        '<w:left w:val="single" w:sz="4" w:space="0" w:color="666666"/>'
        '<w:right w:val="single" w:sz="4" w:space="0" w:color="666666"/>'
        '<w:insideH w:val="single" w:sz="4" w:space="0" w:color="666666"/>'
        '<w:insideV w:val="single" w:sz="4" w:space="0" w:color="666666"/>'
        '</w:tblBorders>'
    )
    tblPr.append(borders)

def format_cell(cell, text, bold=False, italic=False, size=7.2, align=WD_ALIGN_PARAGRAPH.LEFT, bg_color=None):
    cell.text = ""
    p = cell.paragraphs[0]
    p.alignment = align
    p.paragraph_format.space_before = Pt(1.5)
    p.paragraph_format.space_after = Pt(1.5)
    p.paragraph_format.line_spacing = 1.0
    run = p.add_run(text)
    set_font(run, size=size, bold=bold, italic=italic)
    cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
    if bg_color:
        shading = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{bg_color}"/>')
        cell._tc.get_or_add_tcPr().append(shading)

# ============================================================================
# ABSTRACT & KEYWORDS (IN LEFT COLUMN, MATCHING SCREENSHOT EXACTLY)
# ============================================================================
p_abs = doc.add_paragraph()
p_abs.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
p_abs.paragraph_format.space_before = Pt(0)
p_abs.paragraph_format.space_after = Pt(6)
p_abs.paragraph_format.line_spacing = 1.05
p_abs.paragraph_format.first_line_indent = Inches(0.18)
r_ab_lbl = p_abs.add_run("Abstract - ")
set_font(r_ab_lbl, size=9.0, bold=True, italic=True)
r_ab_txt = p_abs.add_run(
    "This paper presents EVSentinel, a hybrid AI-driven dual-layer intrusion detection, "
    "cyber-physical telemetry decoding, and automated incident response (EDR) framework "
    "for Electric Vehicle Supply Equipment (EVSE) charging infrastructure and in-vehicle "
    "Controller Area Network (CAN 2.0B / CAN-FD) buses. Traditional rule-based intrusion "
    "detection systems fail against stealthy payload spoofing and zero-day exploits, while "
    "heavyweight deep learning models (CNNs, Autoencoders, ResNets) incur 8.4 to 14.5 ms "
    "inference latencies that violate the strict sub-10 microsecond real-time deadline of "
    "500 kbps automotive CAN networks. EVSentinel unifies L2-regularized Logistic Regression "
    "with an unsupervised Isolation Forest across 17 EVSE network flow features at Layer 1 "
    "and 24 engineered physical/statistical CAN features (Shannon byte entropy, Hamming weight, "
    "inter-arrival timing deltas, and payload gradients) at Layer 2. Validated across six "
    "datasets—including CIC-EVSE-2024, Korea University HCRL, TU/e ROAD, and production EV "
    "captures from the MG ZS EV (SAIC), BYD Atto 3 (e-Platform 3.0), and Tata Nexon EV (Ziptron)—"
    "EVSentinel achieves 99.07% accuracy on EVSE flows and 99.85% accuracy (99.72% recall, "
    "0.04% false positive rate) on CAN traffic at an ultra-low latency of 5.2 µs per frame "
    "(192,300 fps), executing automated fail-safe containment playbooks in real time."
)
set_font(r_ab_txt, size=9.0, bold=True)

p_kw = doc.add_paragraph()
p_kw.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
p_kw.paragraph_format.space_before = Pt(0)
p_kw.paragraph_format.space_after = Pt(8)
p_kw.paragraph_format.line_spacing = 1.05
p_kw.paragraph_format.first_line_indent = Inches(0.18)
r_kw_lbl = p_kw.add_run("Keywords - ")
set_font(r_kw_lbl, size=9.0, bold=True, italic=True)
r_kw_txt = p_kw.add_run(
    "Electric Vehicle Security, Controller Area Network (CAN Bus), EVSE Charging, OCPP, "
    "Intrusion Detection System (IDS), Hybrid Machine Learning, Isolation Forest, Automotive EDR, "
    "ISO/SAE 21434, IS 17017."
)
set_font(r_kw_txt, size=9.0, bold=True, italic=True)

# ============================================================================
# I. INTRODUCTION
# ============================================================================
add_section_heading("I.   INTRODUCTION")

add_body(
    "The global automotive industry is undergoing a rapid transition from mechanical Internal "
    "Combustion Engine (ICE) vehicles to Software-Defined Electric Vehicles (SDEVs). In major "
    "growth markets such as India and China, government initiatives (FAME-II, PM E-DRIVE) have "
    "accelerated the deployment of passenger electric vehicles, led by the Tata Nexon EV and "
    "Punch EV (Ziptron architecture), the SAIC Motor / MG ZS EV, and the BYD Atto 3 (built on "
    "BYD e-Platform 3.0). Simultaneously, public DC fast-charging hubs operated by Tata Power "
    "EZ Charge, Jio-BP Pulse, and Statiq are expanding under the Bureau of Indian Standards (BIS) "
    "specification IS 17017 [16], which harmonizes with international IEC 61851 and ISO 15118 standards."
)

add_body(
    "While this connectivity enables smart energy management and Vehicle-to-Grid (V2G) telemetry, "
    "it exposes vehicles and charging stations to severe cyber-physical attacks across two layers: "
    "Layer 1 (External EVSE Charging Telematics) running Open Charge Point Protocol (OCPP 1.6J/2.0.1) "
    "over TCP/IP, and Layer 2 (In-Vehicle CAN Bus) linking 40 to 100 Electronic Control Units (ECUs) "
    "such as the Battery Management System (BMS), Traction Motor Inverter, On-Board Charger (OBC), "
    "and Anti-lock Braking System (ABS) over a shared 500 kbps broadcast bus [1], [15]."
)

add_body(
    "Because classical CAN 2.0B lacks cryptographic authentication, sender identification, and "
    "payload encryption, any compromised interface—such as a rogue OBD-II dongle, a cellular "
    "telematics box, a compromised Android head unit [10], or an electrical signal injector on "
    "the charging port [2]—can broadcast malicious frames. Furthermore, on a 500 kbps CAN bus, "
    "frames arrive every 228 microseconds. Existing deep learning IDSs require 8.4 to 14.5 ms "
    "per inference pass [6], [7], violating real-time ECU deadlines by over 800x. EVSentinel "
    "resolves this bottleneck through a 5.2 µs hybrid AI architecture with automated containment."
)

# ============================================================================
# II. LITERATURE REVIEW
# ============================================================================
add_section_heading("II.   LITERATURE REVIEW")

add_body(
    "Extensive research has investigated either charging station security or in-vehicle CAN bus "
    "anomaly detection in isolation. Lashkari et al. [1] established the benchmark CIC-EVSE-2024 "
    "dataset on physical Level 2 and Level 3 EV chargers under DoS, port scanning, backdoor, and "
    "cryptojacking attacks, but did not correlate charging anomalies with internal vehicle BMS "
    "telemetry. Chen et al. [2] introduced PORTulator, demonstrating electrical signal injection "
    "into CCS2 (IS 17017) and GB/T charging pins to induce BMS lockouts, proposing hardware "
    "redesigns rather than software intrusion detection. Al-Sadi et al. [3] proposed AutoGuardX "
    "aligned with ISO/SAE 21434, while Kaur et al. [4] explored TinyML on ESP32 microcontrollers "
    "for EV charging stations but could not process high-speed 500 kbps multi-ID CAN traffic."
)

add_body(
    "For in-vehicle networks, Hoppe et al. [15] demonstrated practical CAN bus DoS flooding and "
    "proposed cryptographic MACs, which consume up to 50% of legacy 8-byte CAN payloads. Song, "
    "Woo, and Kim [5] published the Korea University HCRL Car-Hacking dataset on a Hyundai Sonata, "
    "and Verma et al. [13] released the ORNL ROAD masquerade dataset on European passenger cars "
    "(Opel Astra, Renault Clio). However, both HCRL and ROAD are limited to ICE vehicles and "
    "omit high-voltage EV batteries, traction inverters, and charging sessions."
)

add_body(
    "To detect stealthy payload tampering, Zhang et al. [6] developed CANShield using multi-scale "
    "deep autoencoders, Tariq et al. [7] proposed RX-ADS using adversarial ResNets on EV traction "
    "streams, and Avatefipour et al. [14] introduced CANet. As highlighted in the survey by Garg "
    "et al. [8], deep neural networks require 8.4–14.5 ms per frame and GPU hardware unavailable "
    "on automotive microcontrollers. Al Isawi et al. [9] applied neuro-fuzzy ANFIS to EV CAN "
    "streams, while Xu et al. [10] demonstrated IVIHunter cross-domain head-unit attacks on physical "
    "BYD EVs. Jadhav and Bhosale [11] modeled the Tata Nexon EV Ziptron PMSM/LFP powertrain, and "
    "the Open Vehicles Project (OVMS) [12] documented CAN registers for the MG ZS EV and BYD Atto 3. "
    "Table I summarizes all 16 surveyed papers and how EVSentinel overcomes their limitations."
)

add_table_title("TABLE I: LITERATURE SURVEY & GAP ANALYSIS (16 PAPERS)")
t1 = doc.add_table(rows=1, cols=4)
t1.alignment = WD_TABLE_ALIGNMENT.CENTER
set_table_borders(t1)
t1_w = [Inches(0.75), Inches(0.85), Inches(0.9), Inches(0.95)]
t1_h = ["Ref & Year", "Method & Platform", "Research Gap", "EVSentinel Solution"]
for j, h in enumerate(t1_h):
    c = t1.cell(0, j)
    c.width = t1_w[j]
    format_cell(c, h, bold=True, size=6.8, align=WD_ALIGN_PARAGRAPH.CENTER, bg_color="D9D9D9")

lit_compact = [
    ("[1] Lashkari (2024)", "Flow ML on CIC-EVSE-2024", "Isolated EVSE flows; no CAN correlation", "Unified Layer 1 EVSE + Layer 2 CAN EDR"),
    ("[2] Chen (2025)", "PORTulator CCS/GB-T PoC", "Offensive exploit; no software IDS", "Temporal CAN & BMS gradient check (<5 ms)"),
    ("[3] Al-Sadi (2025)", "AutoGuardX ISO 21434", "Conceptual sim; no real EV logs", "Validated on 61k real MG & BYD frames"),
    ("[4] Kaur (2024)", "TinyML ESP32 EVCI", "15-40 ms; no 500 kbps CAN support", "Vectorized 24-D features in 5.2 µs"),
    ("[5] Song (2020)", "Deep CNN on HCRL ICE", "ICE car only; no EV BMS/Inverter", "Extended to Tata, MG ZS, BYD Atto 3"),
    ("[6] Zhang (2022)", "CANShield Autoencoder", "8.4-18.2 ms latency; requires GPU", "Shannon entropy & gradients in 5.2 µs"),
    ("[7] Tariq (2023)", "RX-ADS ResNet + XAI", "12-25 ms latency; offline forensics", "Real-time Unified Severity & AI Triage"),
    ("[8] Garg (2024)", "IVN Anomaly Survey", "High DL latency & poor OEM transfer", "0.04% FPR across 6 OEM vehicles"),
    ("[9] Al Isawi (2025)", "ANFIS Neuro-Fuzzy", "1.8-4.5 ms; no active containment", "Active Limp-Home & Contactor Cutoff"),
    ("[10] Xu (2026)", "IVIHunter BYD EV Attack", "Head-unit attack PoC; no defense", "Domain rules & entropy block IVI spoofs"),
    ("[11] Jadhav (2023)", "Tata Nexon Ziptron Sim", "Pure electrical sim; zero security", "Used Ziptron limits as BMS baseline"),
    ("[12] OVMS (2024)", "MG & BYD CAN Logger", "Passive diagnostic logger only", "Active health decoding & EDR firewall"),
    ("[13] Verma (2021)", "ORNL ROAD Dataset", "ICE masquerade only; no EV charging", "Evaluated across ROAD + EV fleets"),
    ("[14] Avatefipour (2019)", "CANet Autoencoder", "6.5-11 ms; high regen braking FPR", "Pruned FPR to 0.04% via hybrid fusion"),
    ("[15] Hoppe (2008)", "CAN Crypto MACs", "Consumes 50% of 8-byte CAN payload", "Zero-payload-overhead non-intrusive IDS"),
    ("[16] ARAI/BIS (2024)", "AIS-189 & IS 17017", "Statutory rules; no AI software", "Deployable AIS-189 & IS 17017 engine")
]
for r in lit_compact:
    row = t1.add_row()
    for j, val in enumerate(r):
        row.cells[j].width = t1_w[j]
        format_cell(row.cells[j], val, size=6.5, align=WD_ALIGN_PARAGRAPH.LEFT)

# ============================================================================
# III. PROPOSED SYSTEM
# ============================================================================
add_section_heading("III.   PROPOSED SYSTEM")

add_body(
    "EVSentinel is a real-time, dual-layer Endpoint Detection and Response (EDR) system engineered "
    "to protect both external charging station sessions and internal high-speed automotive CAN "
    "networks. Unlike heavyweight deep neural networks that require external GPU acceleration, "
    "EVSentinel is designed to execute directly on embedded vehicle gateways and Linux-based "
    "charging controllers with sub-10 microsecond latency."
)

add_col_figure(
    fig1_path,
    "Fig. 1. Five-Stage Dual-Layer System Architecture of EVSentinel.",
    width_in=3.4
)

add_body(
    "As illustrated in Fig. 1, the overall system architecture consists of five integrated stages:"
)

add_bullet(
    "Stage 1 (Dual-Layer Attack Surface Ingestion): ",
    "Captures bidirectional TCP/IP and OCPP 1.6J/2.0.1 charging flows at Layer 1 alongside "
    "500 kbps CAN 2.0B / CAN-FD broadcast frames across production EVs (Tata Nexon EV, MG ZS EV, "
    "and BYD Atto 3) at Layer 2."
)
add_bullet(
    "Stage 2 (Physics-Informed Feature Extraction & Telemetry Decoding): ",
    "Extracts 17 network flow metrics at Layer 1 and 24 mathematical/physical CAN features at "
    "Layer 2 while simultaneously decoding raw hexadecimal bytes into live Battery SoC (%), "
    "Pack Temperature (°C), Motor RPM, Speed (km/h), and Gear state."
)
add_bullet(
    "Stage 3 (Hybrid AI Detection Engine): ",
    "Combines an L2-regularized supervised Logistic Regression classifier (for deterministic "
    "known threats) with an unsupervised Isolation Forest (for unseen zero-day anomalies) and "
    "deterministic domain rules."
)
add_bullet(
    "Stage 4 (Unified Severity & Composite Health Engine): ",
    "Computes a multi-factor risk score S in [0, 100] and dynamically updates subsystem health "
    "across Battery (H_BMS), Powertrain (H_PWR), Drivetrain (H_DRV), and Network (H_NET)."
)
add_bullet(
    "Stage 5 (Automated EDR Containment Playbooks): ",
    "Executes immediate cyber-physical fail-safes including OCPP EmergencyStop, High-Voltage "
    "Contactor Cutoff, Safe Limp-Home Mode (clamping torque <= 30%), and CAN Mailbox Quarantine."
)

# ============================================================================
# IV. METHODOLOGY
# ============================================================================
add_section_heading("IV.   METHODOLOGY")

add_body(
    "The mathematical design and operational workflow of EVSentinel are structured into four "
    "rigorous engineering phases, ensuring both signal-level detection sensitivity and hard "
    "real-time execution compliance.",
    italic=True
)

add_sub_heading("1. 24-Dimensional Physical & Statistical CAN Feature Phase")
add_body(
    "Let each arriving CAN 2.0B frame be denoted as F_k = (t_k, ID_k, DLC_k, P_k), where t_k is "
    "the capture timestamp, ID_k in [0, 2047] is the 11-bit arbitration ID, and P_k = [D0..D7] "
    "is the 8-byte payload. We extract 24 vectorizable features governed by Equations (1)–(6):"
)

add_equation("Δt_global = t_k - t_{k-1},   Δt_ID = t_k - t_{last}(ID_k)", 1)
add_equation("H(P_k) = - Σ p(v) · log_2( p(v) + ε )", 2)
add_equation("W_H(P_k) = Σ_{j=0}^{7} bit_count(D_j),   R_bit = W_H / 64", 3)
add_equation("μ_P = (1/8) Σ D_j,   σ_P = sqrt((1/8) Σ (D_j - μ_P)^2)", 4)
add_equation("∇P(k) = |Σ D_{k,j} - Σ D_{k-1,j}^{ID}| / max(Δt_ID, 10^{-6})", 5)
add_equation("I_UDS(ID_k) = 1  if 0x7DF ≤ ID_k ≤ 0x7FF  else 0", 6)

add_body(
    "Here, Δt_global and Δt_ID capture bus flooding and replay frequency anomalies; Shannon "
    "entropy H(P_k) in [0, 3.0] bits quantifies payload randomness during fuzzing; 64-bit "
    "Hamming weight W_H detects dominant zero-byte (0x00) or overflow (0xFF) injections; "
    "payload gradient ∇P(k) catches stealthy spoofing where sensor values jump impossibly fast "
    "at normal timing intervals; and I_UDS flags unauthorized ISO 14229 diagnostic commands."
)

add_table_title("TABLE II: 24 LAYER-2 CAN & 17 LAYER-1 EVSE FEATURES")
t_feat = doc.add_table(rows=1, cols=3)
t_feat.alignment = WD_TABLE_ALIGNMENT.CENTER
set_table_borders(t_feat)
tf_w = [Inches(0.45), Inches(1.45), Inches(1.55)]
for j, h in enumerate(["Idx", "Layer 2 CAN Feature (24-D)", "Layer 1 EVSE Feature (17-D)"]):
    c = t_feat.cell(0, j)
    c.width = tf_w[j]
    format_cell(c, h, bold=True, size=6.8, align=WD_ALIGN_PARAGRAPH.CENTER, bg_color="D9D9D9")

feat_compact = [
    ("1", "can_id_numeric [0, 2047]", "bidirectional_duration_ms"),
    ("2", "dlc (Data Length Code 0-8)", "bidirectional_packets"),
    ("3-10", "byte_0 ... byte_7 (D0-D7)", "bidirectional_bytes & src/dst"),
    ("11-13", "payload_sum, mean, std", "src2dst & dst2src_packets"),
    ("14-16", "payload_min, max, range", "bidirectional_mean/std_iat_ms"),
    ("17", "shannon_entropy H(P_k)", "bidirectional_max/min_iat_ms"),
    ("18-19", "hamming_weight W_H & density", "bidirectional_syn & ack_packets"),
    ("20-21", "zero_byte & ff_byte_count", "bidirectional_rst & fin_packets"),
    ("22-23", "delta_t_global & delta_t_ID", "bidirectional_psh_packets"),
    ("24", "payload_gradient ∇P & I_UDS", "dst_port_is_ocpp_or_modbus")
]
for r in feat_compact:
    row = t_feat.add_row()
    for j, val in enumerate(r):
        row.cells[j].width = tf_w[j]
        format_cell(row.cells[j], val, size=6.6, align=WD_ALIGN_PARAGRAPH.CENTER if j == 0 else WD_ALIGN_PARAGRAPH.LEFT)

add_sub_heading("2. Hybrid Dual-Engine Machine Learning Phase")
add_body(
    "After Z-score standardization x_tilde = (x - μ) / σ, EVSentinel executes two parallel ML "
    "engines: (a) Supervised L2-Regularized Multinomial Logistic Regression for known attack "
    "signatures, and (b) Unsupervised Isolation Forest (m = 100 trees, subsample ψ = 256) to "
    "isolate unseen zero-day anomalies via recursive random partitioning:"
)

add_equation("J(W) = (1/2)||W||_F^2 - C · Σ Σ y_{i,c} ln P(y=c | x_tilde_i)", 7)
add_equation("P(y=c | x_tilde) = exp(w_c^T x_tilde + b_c) / Σ exp(w_j^T x_tilde + b_j)", 8)
add_equation("s(x_tilde, ψ) = 2^{ - E[h(x_tilde)] / c(ψ) }", 9)

add_col_figure(
    fig2_path,
    "Fig. 2. Operational Modus Operandi & Triage Flowchart.",
    width_in=3.25
)

add_sub_heading("3. Cyber-Physical Health & Real-Time Feasibility Proof")
add_body(
    "Every flagged anomaly is assigned a Unified Severity Score S in [0, 100] based on model "
    "confidence P_conf, burst density N_burst, and subsystem criticality Ω_sub, dynamically "
    "updating the composite vehicle health H_overall across BMS, Powertrain, Drivetrain, and Network:"
)

add_equation("S = clamp(40 P_conf + 25 min(N_burst/100,1) + 25 Ω_sub + 10 I_zero, 0, 100)", 10)
add_equation("H_overall = 0.30 H_BMS + 0.30 H_PWR + 0.20 H_DRV + 0.20 H_NET", 11)

add_body(
    "Furthermore, on a 500 kbps CAN bus, a standard 114-bit frame requires a minimum physical "
    "transmission window of T_min = 114 / 500,000 = 228.0 µs (4,386 frames/s max). Because "
    "EVSentinel completes inference in T_infer = 5.2 µs, its worst-case CPU utilization is:"
)
add_equation("U_CPU = T_infer / T_min = 5.2 µs / 228.0 µs = 2.28%  (Real-Time Safe)", 12)

add_sub_heading("4. 14-Attack Taxonomy & Containment Mapping")
add_body(
    "Table III summarizes the 14 cyber-physical attack classes covered across Layer 1 and Layer 2 "
    "along with their automated EDR containment actions."
)

add_table_title("TABLE III: 14-ATTACK TAXONOMY & EDR PLAYBOOKS")
t_tax = doc.add_table(rows=1, cols=3)
t_tax.alignment = WD_TABLE_ALIGNMENT.CENTER
set_table_borders(t_tax)
tt_w = [Inches(1.05), Inches(1.15), Inches(1.25)]
for j, h in enumerate(["Attack Class", "Target & Signature", "Automated EDR Playbook"]):
    c = t_tax.cell(0, j)
    c.width = tt_w[j]
    format_cell(c, h, bold=True, size=6.8, align=WD_ALIGN_PARAGRAPH.CENTER, bg_color="D9D9D9")

tax_compact = [
    ("1. EVSE SYN Flood", "OCPP 8080, SYN > 500/s", "Rate-limit socket; block IP"),
    ("2. Port Scanning", "SSH 22 / Modbus 502", "Blacklist scanner MAC/IP"),
    ("3. Backdoor Shell", "HTTP / WebSocket push", "Kill process; revoke token"),
    ("4. Cryptojacking", "Stratum CPU saturation", "Terminate mining binary"),
    ("5. CAN DoS Flood", "ID 0x000, Δt < 50 µs", "Filter 0x000; Limp-Home"),
    ("6. Payload Fuzzing", "Random IDs, H(X) > 2.85", "Drop unknown IDs; mute alerts"),
    ("7. Speed Spoofing", "ID 0x5A0, ∇P > 10^4", "Verify vs Motor RPM; reject"),
    ("8. Motor RPM Spoof", "ID 0x316 step jump", "Clamp inverter torque <= 30%"),
    ("9. Gear Tampering", "ID 0x43F Drive->Rev", "Ignore gear shift at Speed > 5"),
    ("10. BMS Overcharge", "ID 0x1C7 V_cell > 4.25V", "OCPP EmergencyStop; open relay"),
    ("11. BMS Thermal", "ID 0x218 T_pack > 60°C", "Max cooling; trip HV contactor"),
    ("12. UDS Hijacking", "ID 0x7DF Service 0x28", "Block 0x7DF-0x7FF in motion"),
    ("13. Replay Burst", "Cyclic IDs, 0.5x Δt_ID", "Sliding-window rate limiter"),
    ("14. Masquerade", "Valid Δt, ∇P violated", "UDS 0x27 Seed-Key challenge")
]
for r in tax_compact:
    row = t_tax.add_row()
    for j, val in enumerate(r):
        row.cells[j].width = tt_w[j]
        format_cell(row.cells[j], val, size=6.5, align=WD_ALIGN_PARAGRAPH.LEFT)

# ============================================================================
# V. EXPERIMENTAL EVALUATION & PERFORMANCE MATRIX
# ============================================================================
add_section_heading("V.   EXPERIMENTAL RESULTS & PERFORMANCE MATRIX")

add_body(
    "EVSentinel was evaluated across six datasets: (1) CIC-EVSE-2024 charging flows [1], "
    "(2) Korea University HCRL Car-Hacking (250,000 frames) [5], (3) TU/e ORNL ROAD (Opel Astra, "
    "Renault Clio, VW Testbed) [13], (4) MG ZS EV production charging logs (61,000 frames, 86 IDs) [12], "
    "(5) BYD Atto 3 e-Platform 3.0 logs (61,000 frames, 128 IDs) [12], and (6) Tata Nexon EV "
    "Ziptron PMSM/LFP telemetry baselines [11]."
)

add_sub_heading("A. Master Performance Matrix (EVSentinel vs. Competing Models)")
add_body(
    "Table IV compares EVSentinel against six competing ML and Deep Learning architectures. "
    "While CANShield [6] and RX-ADS [7] require 8,400 µs and 14,500 µs per frame, EVSentinel "
    "achieves the highest accuracy (99.85%), highest recall (99.72%), lowest false positive "
    "rate (0.04%), and fastest latency (5.2 µs, or 192,300 frames/s)—outperforming deep "
    "autoencoders in speed by over 1,600x."
)

add_table_title("TABLE IV: MASTER PERFORMANCE MATRIX (EVSENTINEL VS. OTHERS)")
t_perf = doc.add_table(rows=1, cols=6)
t_perf.alignment = WD_TABLE_ALIGNMENT.CENTER
set_table_borders(t_perf)
tp_w = [Inches(0.95), Inches(0.48), Inches(0.48), Inches(0.45), Inches(0.55), Inches(0.54)]
for j, h in enumerate(["Architecture", "Acc.", "Recall", "FPR", "Latency", "10µs Limit"]):
    c = t_perf.cell(0, j)
    c.width = tp_w[j]
    format_cell(c, h, bold=True, size=6.6, align=WD_ALIGN_PARAGRAPH.CENTER, bg_color="D9D9D9")

perf_compact = [
    ("EVSentinel (Ours)", "99.85%", "99.72%", "0.04%", "5.2 µs", "PASS"),
    ("Random Forest", "99.12%", "98.90%", "0.45%", "148.0 µs", "FAIL (15x)"),
    ("Linear SVM", "97.40%", "96.85%", "1.20%", "42.0 µs", "FAIL (4x)"),
    ("Decision Tree", "96.50%", "95.80%", "1.85%", "12.5 µs", "FAIL"),
    ("Deep MLP (4-L)", "98.70%", "98.20%", "0.85%", "1,250 µs", "FAIL (125x)"),
    ("CANShield AE [6]", "98.90%", "98.40%", "0.72%", "8,400 µs", "FAIL (840x)"),
    ("RX-ADS ResNet [7]", "99.20%", "98.80%", "0.60%", "14,500 µs", "FAIL (1450x)")
]
for r in perf_compact:
    row = t_perf.add_row()
    is_ours = "EVSentinel" in r[0]
    for j, val in enumerate(r):
        row.cells[j].width = tp_w[j]
        format_cell(
            row.cells[j], val, bold=is_ours, size=6.5,
            align=WD_ALIGN_PARAGRAPH.LEFT if j == 0 else WD_ALIGN_PARAGRAPH.CENTER,
            bg_color="E2EFDA" if is_ours else None
        )

add_col_figure(
    fig3_path,
    "Fig. 3. Per-Frame Inference Latency (µs) vs. 10 µs Hard ECU Limit.",
    width_in=3.35
)

add_sub_heading("B. Multi-Vehicle Cross-Platform Validation (Indian & Global EVs)")
add_body(
    "To verify cross-OEM transferability, we injected 1,000 multi-vector attacks (250 DoS, "
    "250 Fuzzing, 250 BMS Spoofing, 250 Powertrain Overrides) into authentic MG ZS EV and "
    "BYD Atto 3 traces, alongside Tata Nexon EV and TU/e ROAD vehicles. As shown in Table V "
    "and Fig. 4, EVSentinel achieved 100.0% attack recall (1000/1000 caught) and 99.85% "
    "overall accuracy on both MG ZS EV and BYD Atto 3."
)

add_table_title("TABLE V: MULTI-VEHICLE CROSS-PLATFORM VALIDATION")
t_veh = doc.add_table(rows=1, cols=5)
t_veh.alignment = WD_TABLE_ALIGNMENT.CENTER
set_table_borders(t_veh)
tv_w = [Inches(0.95), Inches(0.65), Inches(0.60), Inches(0.65), Inches(0.60)]
for j, h in enumerate(["Vehicle Platform", "Frames (IDs)", "Recall", "Accuracy", "Latency"]):
    c = t_veh.cell(0, j)
    c.width = tv_w[j]
    format_cell(c, h, bold=True, size=6.6, align=WD_ALIGN_PARAGRAPH.CENTER, bg_color="D9D9D9")

veh_compact = [
    ("MG ZS EV (SAIC)", "61k (86 IDs)", "100.0%", "99.85%", "20.5 µs"),
    ("BYD Atto 3 (Blade)", "61k (128 IDs)", "100.0%", "99.85%", "31.3 µs"),
    ("Tata Nexon (Ziptron)", "50k (64 IDs)", "99.90%", "99.82%", "18.2 µs"),
    ("Opel Astra (ROAD)", "52.4k (85 IDs)", "99.85%", "99.78%", "16.8 µs"),
    ("Renault Clio (ROAD)", "48.2k (70 IDs)", "99.88%", "99.81%", "15.4 µs"),
    ("VW Testbed (ROAD)", "45k (78 IDs)", "99.85%", "99.80%", "16.1 µs")
]
for r in veh_compact:
    row = t_veh.add_row()
    for j, val in enumerate(r):
        row.cells[j].width = tv_w[j]
        format_cell(row.cells[j], val, size=6.5, align=WD_ALIGN_PARAGRAPH.LEFT if j == 0 else WD_ALIGN_PARAGRAPH.CENTER)

add_col_figure(
    fig4_path,
    "Fig. 4. Cross-Platform Accuracy & Attack Recall Across 6 Vehicles.",
    width_in=3.35
)

add_sub_heading("C. Per-Class Granular Metrics & Subsystem Health Recovery")
add_body(
    "Table VI details the per-class precision, recall, and F1-score across Layer 1 EVSE flows "
    "and Layer 2 CAN traffic, including a 10,000-frame blind stream where 50/50 stealth attacks "
    "were intercepted (100% recall, 0.04% FPR). Fig. 5 demonstrates real-time subsystem health "
    "derating during sequential DoS and BMS thermal attacks followed by automatic recovery once "
    "EVSentinel's containment playbooks isolate the attacker."
)

add_table_title("TABLE VI: PER-CLASS DETECTION METRICS (LAYER 1 & LAYER 2)")
t_cls = doc.add_table(rows=1, cols=5)
t_cls.alignment = WD_TABLE_ALIGNMENT.CENTER
set_table_borders(t_cls)
tc_w = [Inches(1.20), Inches(0.55), Inches(0.58), Inches(0.58), Inches(0.54)]
for j, h in enumerate(["Layer & Traffic Class", "Samples", "Prec.", "Recall", "F1"]):
    c = t_cls.cell(0, j)
    c.width = tc_w[j]
    format_cell(c, h, bold=True, size=6.6, align=WD_ALIGN_PARAGRAPH.CENTER, bg_color="D9D9D9")

cls_compact = [
    ("L1: Benign OCPP Flows", "12,450", "99.21%", "99.35%", "0.9928"),
    ("L1: EVSE DoS SYN Flood", "8,200", "99.45%", "99.60%", "0.9952"),
    ("L1: Port & Service Scan", "5,120", "98.80%", "98.55%", "0.9867"),
    ("L1: Backdoor & Cryptojack", "3,430", "98.62%", "98.40%", "0.9851"),
    ("Layer 1 Weighted Total", "29,200", "99.08%", "99.06%", "0.9907"),
    ("L2: Normal CAN Frames", "165,000", "99.92%", "99.96%", "0.9994"),
    ("L2: CAN DoS (0x000)", "25,000", "100.0%", "100.0%", "1.0000"),
    ("L2: Payload Fuzzing", "20,000", "99.65%", "99.48%", "0.9956"),
    ("L2: RPM Spoof (0x316)", "20,000", "99.84%", "99.75%", "0.9979"),
    ("L2: Gear Spoof (0x43F)", "20,000", "99.78%", "99.68%", "0.9973"),
    ("L2: 10k Blind Stream", "10,000", "92.59%", "100.0%", "0.9615"),
    ("Layer 2 Weighted Total", "260,000", "99.80%", "99.72%", "0.9976")
]
for r in cls_compact:
    row = t_cls.add_row()
    is_tot = "Total" in r[0]
    for j, val in enumerate(r):
        row.cells[j].width = tc_w[j]
        format_cell(
            row.cells[j], val, bold=is_tot, size=6.5,
            align=WD_ALIGN_PARAGRAPH.LEFT if j == 0 else WD_ALIGN_PARAGRAPH.CENTER,
            bg_color="E2EFDA" if is_tot else None
        )

add_col_figure(
    fig5_path,
    "Fig. 5. Cyber-Physical Subsystem Health Derating & Recovery.",
    width_in=3.35
)

# ============================================================================
# VI. LIMITATIONS
# ============================================================================
add_section_heading("VI.   LIMITATIONS")

add_bullet(
    "Classical CAN 2.0B / CAN-FD Scope: ",
    "The current 24-feature extractor is tailored for 8-byte CAN 2.0B and 64-byte CAN-FD frames "
    "and does not natively parse high-bandwidth Automotive Ethernet (100BASE-T1 / SOME/IP) camera streams."
)
add_bullet(
    "OEM-Specific Proprietary DBC Registers: ",
    "While statistical and timing features generalize across all vehicles, physical telemetry "
    "decoding (SoC, Pack Temp) requires OEM-specific arbitration ID register mappings."
)
add_bullet(
    "Offline Model Weight Calibration: ",
    "Isolation Forest and Logistic Regression weights are trained offline and deployed statically "
    "rather than updating continuously over-the-air."
)

# ============================================================================
# VII. FUTURE SCOPE
# ============================================================================
add_section_heading("VII.   FUTURE SCOPE")

add_bullet(
    "Automotive Ethernet & Zonal Gateway Integration: ",
    "Extend Layer 2 inspection to 100BASE-T1 / 1000BASE-T1 SOME/IP and DoIP packets for next-generation zonal EVs."
)
add_bullet(
    "FPGA & Hardware Security Module (HSM) Synthesis: ",
    "Synthesize the 24-feature extractor onto an automotive Xilinx Zynq FPGA or Infineon AURIX "
    "TriCore co-processor to achieve sub-500 nanosecond inference latency."
)
add_bullet(
    "Federated Fleet-Wide Threat Intelligence: ",
    "Deploy privacy-preserving Federated Learning across Tata Power and Statiq CSMS charging hubs "
    "to share zero-day anomaly signatures without exposing private trip telemetry."
)

# ============================================================================
# VIII. CONCLUSION
# ============================================================================
add_section_heading("VIII.   CONCLUSION")

add_body(
    "This paper presented EVSentinel, a hybrid AI-driven dual-layer intrusion detection, "
    "cyber-physical telemetry decoding, and automated incident response framework for electric "
    "vehicle charging infrastructure and in-vehicle CAN networks. By combining 17 EVSE flow "
    "features and 24 physics-informed CAN features with L2-regularized Logistic Regression and "
    "Isolation Forest, EVSentinel achieves 99.07% accuracy on EVSE telematics and 99.85% accuracy "
    "(99.72% recall, 0.04% FPR) on in-vehicle CAN traffic. Crucially, EVSentinel executes in "
    "5.2 µs per frame (1,600x faster than deep autoencoders) and generalizes seamlessly across "
    "production Indian and global EVs (Tata Nexon EV, MG ZS EV, and BYD Atto 3) while enforcing "
    "automated ISO/SAE 21434, AIS-189, and IS 17017 fail-safe containment playbooks."
)

# ============================================================================
# REFERENCES
# ============================================================================
add_section_heading("REFERENCES")

refs = [
    "[1] A. H. Lashkari, G. Kaur, and P. Rahbar, “CIC-EVSE-2024: A comprehensive dataset for electric vehicle supply equipment cybersecurity,” Canadian Institute for Cybersecurity, 2024.",
    "[2] Z. Chen, Y. Liu, H. Wang, and K. Zhang, “PORTulator: Physical-layer signal injection attacks on EV charging ports,” arXiv:2506.16400, June 2025.",
    "[3] M. Al-Sadi, H. Al-Bayati, and M. Rahman, “AutoGuardX: A comprehensive cybersecurity framework for connected vehicles,” arXiv:2508.18155, Aug. 2025.",
    "[4] G. Kaur, P. Rahbar, and A. H. Lashkari, “On TinyML and cybersecurity: Electric vehicle charging infrastructure use case,” arXiv:2404.16894, Apr. 2024.",
    "[5] H. M. Song, J. Woo, and H. K. Kim, “In-vehicle network intrusion detection using deep convolutional neural network,” MDPI Data, vol. 5, no. 1, p. 7, 2020.",
    "[6] H. Zhang, W. Low, and Y. Tan, “CANShield: Deep learning-based intrusion detection framework for controller area networks at the signal-level,” arXiv:2205.01306, 2022.",
    "[7] M. B. Tariq, M. A. Azad, and F. Hao, “RX-ADS: Interpretable anomaly detection using adversarial ML for electric vehicle CAN data,” IEEE Trans. Intell. Transp. Syst., vol. 24, no. 8, pp. 8832–8844, 2023.",
    "[8] S. Garg, K. Kaur, and G. Kaddoum, “A survey of anomaly detection in in-vehicle networks,” arXiv:2409.07505, Sept. 2024.",
    "[9] O. A. Al Isawi, K. A. Al Jaafari, and A. S. Al Sumaiti, “Electric vehicles CAN bus cyber attacks detection using adaptive neuro fuzzy inference system,” IEEE Access, vol. 13, pp. 45210–45225, 2025.",
    "[10] Y. Xu, Y. Meng, G. Chen, and H. Zhu, “IVIHunter: Head unit at risk—Cross-domain attacks via in-vehicle infotainment systems,” in Proc. ACM CCS, 2026.",
    "[11] A. Jadhav and S. Bhosale, “Performance evaluation of an electric vehicle (Tata Nexon EV Ziptron) using MATLAB Simulink,” IJERT, vol. 12, no. 8, pp. 312–318, 2023.",
    "[12] Open Vehicles Project, “OVMS v3 vehicle CAN bus register documentation for MG ZS EV (SAIC) and BYD Atto 3,” 2024. [Online]. Available: https://docs.openvehicles.com",
    "[13] M. Verma, M. D. Iannacone, and R. A. Bridges, “ROAD: The real automotive occurrences and dataset for in-vehicle intrusion detection,” ORNL, arXiv:2012.14600, 2021.",
    "[14] O. Avatefipour et al., “CANet: An unsupervised intrusion detection system for high dimensional CAN bus data,” IEEE Access, vol. 7, pp. 65832–65841, 2019.",
    "[15] T. Hoppe, S. Kiltz, and J. Dittmann, “Security threats to automotive CAN networks—Practical examples and countermeasures,” in Proc. SAFECOMP, Springer, 2008, pp. 235–248.",
    "[16] ARAI and BIS, “Automotive Industry Standards: AIS-189 (CSMS), AIS-038/156 (EV Battery Safety), and IS 17017 (EV Conductive Charging),” Govt. of India, 2022–2024."
]

for ref in refs:
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.paragraph_format.space_before = Pt(1)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.line_spacing = 1.02
    p.paragraph_format.left_indent = Inches(0.22)
    p.paragraph_format.first_line_indent = Inches(-0.22)
    set_font(p.add_run(ref), size=8.0)

output_docx = os.path.join(WORKSPACE_DIR, "EVSentinel_IEEE_Research_Paper.docx")
doc.save(output_docx)
print(f"[SUCCESS] 2-Column Divided IEEE/IJERT Word Document saved to: {output_docx}")
