"""
EVSentinel Automotive EDR Dashboard Launcher
=============================================
Starts the FastAPI backend server and launches the SOC Web Dashboard in your default browser.

Usage:
    python run_edr_dashboard.py
"""

import os
import sys
import time
import webbrowser
import threading
import uvicorn

PORT = 8000
HOST = "127.0.0.1"
URL = f"http://{HOST}:{PORT}"


def open_browser():
    """Opens browser after server initializes."""
    time.sleep(1.2)
    print(f"[*] Launching EVSentinel EDR Dashboard at: {URL}")
    webbrowser.open(URL)


def main():
    print("=" * 75)
    print("  EVSentinel: Automotive Fleet Endpoint Detection & Response (EDR)")
    print("=" * 75)
    print(f"[*] Initializing FastAPI Backend on {URL}...")
    print(f"[*] Ingestion Engine: Folder Scan / Presets / Offline Captures")
    print(f"[*] ML Dual-Engine: Online (Layer 1 Telematics + Layer 2 CAN Bus)")
    print(f"[*] AI Incident Responder: Online (14-Attack ISO 21434 Knowledge Core)")
    print("=" * 75)

    # Launch browser in a background thread
    threading.Thread(target=open_browser, daemon=True).start()

    # Start FastAPI Uvicorn Server
    uvicorn.run("edr_server:app", host=HOST, port=PORT, log_level="info")


if __name__ == "__main__":
    main()
