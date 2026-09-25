"""
KernelGuard Working Demo Launcher
Launches the FastAPI server with live eBPF telemetry streaming,
interactive force-directed behavioral graph, and GNN-Transformer risk scoring.
"""

import sys
import webbrowser
import uvicorn

def main():
    port = 8000
    host = "127.0.0.1"
    url = f"http://{host}:{port}"

    print("=" * 75)
    print("   KERNELGUARD: Adaptive eBPF Behavioral Malware Detection Demo")
    print("=" * 75)
    print(" [OK] Real-Time Kernel Telemetry (Tracepoints & RingBuffer)")
    print(" [OK] Dynamic Temporal Behavioral Graph Engine")
    print(" [OK] Hybrid Graph Neural Network (GAT) + Temporal Transformer")
    print(" [OK] Adaptive Risk-Scoring & MITRE ATT&CK Causal Attribution")
    print(f"\n [+] Starting Web Command Center at: {url}")
    print(" [+] Press Ctrl+C in terminal to stop.")
    print("=" * 75)

    # Automatically open default web browser after short delay
    def open_browser():
        import time
        time.sleep(1.2)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    import threading
    threading.Thread(target=open_browser, daemon=True).start()

    # Run Uvicorn server
    uvicorn.run("web.app:app", host=host, port=port, log_level="warning")

if __name__ == "__main__":
    main()
