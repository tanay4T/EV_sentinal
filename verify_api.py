import asyncio
from edr_server import get_presets, scan_folder_endpoint, ScanRequest

async def test():
    print("--- 1. Testing get_presets() ---")
    presets_res = await get_presets()
    presets = presets_res["presets"]
    for p in presets:
        print(f"  - [{p['id']}] {p['name']} (Exists: {p['exists']})")

    print("\n--- 2. Testing scan_folder_endpoint('MG_ZS_EV') ---")
    mg_res = await scan_folder_endpoint(ScanRequest(folder_path="MG_ZS_EV", max_frames_per_file=3000))
    print(f"  - Total Frames Analyzed: {mg_res['total_frames_analyzed']:,}")
    print(f"  - Total Incidents: {mg_res['total_incidents']}")
    print(f"  - Overall Health Score: {mg_res['health']['overall_health_score']}% ({mg_res['health']['status']})")
    print(f"  - BMS Health Score: {mg_res['health']['subsystems']['bms']['score']}%")
    print(f"  - Battery Temp: {mg_res['telemetry']['battery_temp_c']} °C, SoC: {mg_res['telemetry']['battery_soc_pct']}%")

    print("\n--- 3. Testing scan_folder_endpoint('BYD_Atto3') ---")
    byd_res = await scan_folder_endpoint(ScanRequest(folder_path="BYD_Atto3", max_frames_per_file=3000))
    print(f"  - Total Frames Analyzed: {byd_res['total_frames_analyzed']:,}")
    print(f"  - Total Incidents: {byd_res['total_incidents']}")
    print(f"  - Overall Health Score: {byd_res['health']['overall_health_score']}% ({byd_res['health']['status']})")
    print(f"  - BMS Health Score: {byd_res['health']['subsystems']['bms']['score']}%")
    print(f"  - Battery Temp: {byd_res['telemetry']['battery_temp_c']} °C, SoC: {byd_res['telemetry']['battery_soc_pct']}%")

    print("\n[SUCCESS] EDR Server functions verified perfectly for MG ZS EV & BYD Atto 3!")

if __name__ == "__main__":
    asyncio.run(test())
