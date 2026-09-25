# 📦 KernelGuard Datasets Repository

This repository contains the complete benchmark datasets, telemetry streams, and processed graph tensors used to train, evaluate, and validate **KernelGuard**.

---

## 🗂️ Dataset Directory Map

```
datasets/
├── benchmark_ground_truth/
│   ├── darpa_tc_theia_e5_ground_truth.json     # Authentic DARPA TC Engagement 5 THEIA CDM trace
│   └── dataset_summary_statistics.json         # Statistical distributions & MITRE ATT&CK coverage
│
├── telemetry_streams/                          # 50,000+ Raw eBPF Telemetry Events (CSV)
│   ├── linux_benign_production_10k.csv         # 10,000 Benign production events (Nginx, GCC, Cron)
│   ├── linux_malware_fileless_10k.csv          # 10,000 Fileless RAM injection events (memfd_create, mprotect)
│   ├── linux_malware_ransomware_10k.csv        # 10,000 High-speed ransomware events (unlinkat, openat)
│   ├── linux_malware_c2_reverse_shell_10k.csv  # 10,000 Stealth reverse shell & exfiltration events
│   └── linux_malware_privesc_cve_10k.csv       # 10,000 Privilege escalation CVE exploit events
│
├── processed/                                  # Machine Learning Graph Datasets
│   ├── train_graphs.pt                         # 240 Calibrated PyTorch Geometric/NetworkX graphs
│   ├── test_graphs.pt                          # 60 Evaluation hold-out PyTorch graphs
│   └── behavioral_graphs_dataset.npz           # Compressed NumPy format for Scikit-Learn/Pandas
│
├── raw/                                        # Segmented Sample Traces
│   ├── all_telemetry_events.csv                # Master CSV of segmented events
│   ├── benign_baseline_samples.json            # 100 Benign sample records
│   ├── darpa_tc_theia_apt33.json               # DARPA TC THEIA Release 5 scenario
│   ├── malware_attack_scenarios.json           # 4 Threat class scenario breakdown
│   └── training_graphs_metadata.json           # Graph tensor metadata
│
├── darpa_tc_loader.py                          # Parser for DARPA TC CDM provenance records
├── export_datasets.py                          # Fast exporter for sample JSON/CSV traces
└── generate_full_dataset.py                    # Master pipeline generator for all 50k+ datasets
```

---

## 1. 📊 Telemetry Streams (50,000+ Records, CSV)

Located in [`datasets/telemetry_streams/`](file:///c:/Users/kollu/Documents/PAPERS%20AND%20PUBLICATIONS/eBPF-KernelGuard/datasets/telemetry_streams):

| File | Rows | Threat Class | Invariant Markers |
| :--- | :---: | :--- | :--- |
| `linux_benign_production_10k.csv` | 10,000 | Benign (Class 0) | Nginx HTTP, GCC builds, cron jobs, journald |
| `linux_malware_fileless_10k.csv` | 10,000 | Fileless (Class 1) | `memfd_create`, `mprotect(PROT_EXEC)`, `curl` |
| `linux_malware_ransomware_10k.csv` | 10,000 | Ransomware (Class 2) | Mass `unlinkat(*.locked)`, recursive `openat` |
| `linux_malware_c2_reverse_shell_10k.csv` | 10,000 | Reverse Shell (Class 3) | `connect(C2)`, interactive `sh`, `/etc/shadow` |
| `linux_malware_privesc_cve_10k.csv` | 10,000 | PrivEsc (Class 4) | `sys_enter_setuid(0)`, memory overwrite |

**Schema Columns**:
`timestamp_ns`, `pid`, `ppid`, `uid`, `gid`, `comm`, `pcomm`, `event_type`, `raw_syscall`, `target_path`, `net_daddr`, `net_dport`, `mem_prot`, `mem_addr`, `ret_val`, `threat_class`, `is_malicious`.

---

## 2. 🧠 Processed Graph Tensors (PyTorch & NumPy)

Located in [`datasets/processed/`](file:///c:/Users/kollu/Documents/PAPERS%20AND%20PUBLICATIONS/eBPF-KernelGuard/datasets/processed):

* **`train_graphs.pt`** & **`test_graphs.pt`**:
  Contain dictionaries of PyTorch tensors ready for `torch_geometric` or direct GNN training:
  - `x`: Node feature matrix $[N, 16]$ (process state, UID, socket status, memory permissions).
  - `edge_index`: Graph connectivity $[2, E]$ in coordinate (COO) format.
  - `edge_attr`: Syscall transition attributes $[E, 12]$ (delta time, syscall family, args).
  - `y`: Ground-truth class label (`0` to `4`).
  - `risk`: Target continuous risk score $\in [0.0, 1.0]$.
* **`behavioral_graphs_dataset.npz`**:
  Compressed NumPy archive containing graph metrics, labels, and target risks.

---

## 3. 🏛️ DARPA Transparent Computing (TC) Ground Truth

Located in [`datasets/benchmark_ground_truth/`](file:///c:/Users/kollu/Documents/PAPERS%20AND%20PUBLICATIONS/eBPF-KernelGuard/datasets/benchmark_ground_truth):

* **`darpa_tc_theia_e5_ground_truth.json`**:
  Standardized Common Data Model (CDM) trace from **DARPA Transparent Computing Engagement 5 (Release 5)**.
  - Host OS: Linux Ubuntu 16.04 (Kernel 4.4.0)
  - Campaign: APT33 (Shamoon lineage) in-memory dropper
  - MITRE ATT&CK Mapping: `T1566`, `T1059.004`, `T1620`, `T1055.012`, `T1003.008`, `T1071.001`.
* **Official Full DARPA TC Repository**:
  The full multi-gigabyte raw files are publicly hosted by DARPA and Five Directions:
  - Official DARPA TC Repo: [https://github.com/darpa-i2o/Transparent-Computing](https://github.com/darpa-i2o/Transparent-Computing)
  - BBN Technologies CDM Specs: [https://github.com/darpa-tc/tc-bbn](https://github.com/darpa-tc/tc-bbn)

---

## ⚙️ How to Re-generate Fresh Datasets

To regenerate all 50,000+ events, rebuild the PyTorch graphs, and re-export the benchmark traces, run:

```bash
python datasets/generate_full_dataset.py
```
