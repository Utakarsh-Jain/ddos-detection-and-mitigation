"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       DDoS AI AGENT — SCALABILITY BENCHMARK                                ║
║  SRM Institute of Science and Technology | Dept. Networking & Communications ║
║  Students : Utkarsh Jaiswal  (RA2311030010011)                               ║
║             Utakarsh Jain    (RA2311030010054)                               ║
║  Guide    : Dr. Karthikeyan H, Assistant Professor                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

Module  : benchmark.py
Purpose : Measure scalability of the DDoS AI Agent under increasing load.
          Tests throughput at multiple scales (1K → 100K+ flows) and with
          different worker counts (1, 2, 4, 8 threads).

          Outputs a clean results table and saves a performance chart to
          plots/benchmark_results.png

Usage
─────
  python benchmark.py                          # default benchmark
  python benchmark.py --max_flows 500000       # test up to 500K flows
  python benchmark.py --data "path/to/file"    # benchmark on real data
"""

import os
import sys
import time
import argparse
import numpy as np
import pandas as pd
import logging
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Add current dir to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from streaming_agent import StreamingDDoSAgent, ThreadSafeDetector

logging.basicConfig(level=logging.WARNING)  # quiet during benchmarks
log = logging.getLogger("Benchmark")

os.makedirs("plots", exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# SYNTHETIC DATA GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def generate_synthetic_flows(n: int, attack_ratio: float = 0.5) -> pd.DataFrame:
    """
    Generate realistic-looking synthetic network flows for benchmarking.
    Features match the CIC-DDoS2019 column schema.
    """
    rng = np.random.default_rng(42)

    n_attack = int(n * attack_ratio)
    n_benign = n - n_attack

    # Benign traffic patterns                         # Attack traffic patterns
    benign = pd.DataFrame({
        "Flow Duration":              rng.exponential(1000, n_benign),
        "Flow Bytes/s":               rng.normal(5000, 2000, n_benign).clip(0),
        "Flow Packets/s":             rng.normal(50, 20, n_benign).clip(0),
        "Flow IAT Mean":              rng.normal(20000, 5000, n_benign).clip(0),
        "Flow IAT Std":               rng.normal(10000, 3000, n_benign).clip(0),
        "Flow IAT Max":               rng.normal(50000, 10000, n_benign).clip(0),
        "Flow IAT Min":               rng.normal(100, 50, n_benign).clip(0),
        "Total Fwd Packets":          rng.poisson(5, n_benign),
        "Total Backward Packets":     rng.poisson(4, n_benign),
        "Total Length of Fwd Packets": rng.normal(500, 200, n_benign).clip(0),
        "Total Length of Bwd Packets": rng.normal(400, 150, n_benign).clip(0),
        "Fwd Packet Length Mean":      rng.normal(100, 40, n_benign).clip(0),
        "Bwd Packet Length Mean":      rng.normal(80, 30, n_benign).clip(0),
        "Fwd Packet Length Std":       rng.normal(50, 20, n_benign).clip(0),
        "Bwd Packet Length Std":       rng.normal(40, 15, n_benign).clip(0),
        "Fwd IAT Total":              rng.normal(100000, 30000, n_benign).clip(0),
        "Fwd IAT Mean":               rng.normal(20000, 5000, n_benign).clip(0),
        "Fwd IAT Std":                rng.normal(10000, 3000, n_benign).clip(0),
        "Bwd IAT Total":              rng.normal(80000, 25000, n_benign).clip(0),
        "Bwd IAT Mean":               rng.normal(20000, 5000, n_benign).clip(0),
        "Destination Port":           rng.choice([80, 443, 8080, 3306], n_benign),
        "SYN Flag Count":             rng.poisson(1, n_benign),
        "ACK Flag Count":             rng.poisson(3, n_benign),
        "PSH Flag Count":             rng.poisson(1, n_benign),
        "URG Flag Count":             np.zeros(n_benign),
        "FIN Flag Count":             rng.poisson(1, n_benign),
        "RST Flag Count":             np.zeros(n_benign),
        "Active Mean":                rng.normal(5000, 2000, n_benign).clip(0),
        "Active Std":                 rng.normal(2000, 1000, n_benign).clip(0),
        "Idle Mean":                  rng.normal(50000, 10000, n_benign).clip(0),
        "Idle Std":                   rng.normal(20000, 5000, n_benign).clip(0),
        "Average Packet Size":        rng.normal(200, 80, n_benign).clip(0),
        "Avg Fwd Segment Size":       rng.normal(100, 40, n_benign).clip(0),
        "Avg Bwd Segment Size":       rng.normal(80, 30, n_benign).clip(0),
        "Subflow Fwd Packets":        rng.poisson(5, n_benign),
        "Subflow Bwd Packets":        rng.poisson(4, n_benign),
        "Subflow Fwd Bytes":          rng.normal(500, 200, n_benign).clip(0),
        "Subflow Bwd Bytes":          rng.normal(400, 150, n_benign).clip(0),
        "Source IP":                  [f"10.0.{i%256}.{i%256}" for i in range(n_benign)],
    })

    attack = pd.DataFrame({
        "Flow Duration":              rng.exponential(10, n_attack),       # very short
        "Flow Bytes/s":               rng.normal(5000000, 1000000, n_attack).clip(0),  # very high
        "Flow Packets/s":             rng.normal(50000, 10000, n_attack).clip(0),
        "Flow IAT Mean":              rng.normal(10, 5, n_attack).clip(0),     # very low IAT
        "Flow IAT Std":               rng.normal(5, 2, n_attack).clip(0),
        "Flow IAT Max":               rng.normal(100, 50, n_attack).clip(0),
        "Flow IAT Min":               rng.normal(1, 1, n_attack).clip(0),
        "Total Fwd Packets":          rng.poisson(500, n_attack),          # flood
        "Total Backward Packets":     rng.poisson(1, n_attack),            # no response
        "Total Length of Fwd Packets": rng.normal(50000, 10000, n_attack).clip(0),
        "Total Length of Bwd Packets": rng.normal(10, 5, n_attack).clip(0),
        "Fwd Packet Length Mean":      rng.normal(100, 10, n_attack).clip(0),
        "Bwd Packet Length Mean":      rng.normal(5, 2, n_attack).clip(0),
        "Fwd Packet Length Std":       rng.normal(5, 2, n_attack).clip(0),
        "Bwd Packet Length Std":       rng.normal(2, 1, n_attack).clip(0),
        "Fwd IAT Total":              rng.normal(100, 30, n_attack).clip(0),
        "Fwd IAT Mean":               rng.normal(1, 0.5, n_attack).clip(0),
        "Fwd IAT Std":                rng.normal(0.5, 0.2, n_attack).clip(0),
        "Bwd IAT Total":              rng.normal(0, 0, n_attack).clip(0),
        "Bwd IAT Mean":               rng.normal(0, 0, n_attack).clip(0),
        "Destination Port":           rng.choice([80, 53, 123, 443], n_attack),
        "SYN Flag Count":             rng.poisson(50, n_attack),           # SYN flood
        "ACK Flag Count":             rng.poisson(1, n_attack),
        "PSH Flag Count":             np.zeros(n_attack),
        "URG Flag Count":             np.zeros(n_attack),
        "FIN Flag Count":             np.zeros(n_attack),
        "RST Flag Count":             rng.poisson(10, n_attack),
        "Active Mean":                rng.normal(1, 0.5, n_attack).clip(0),
        "Active Std":                 rng.normal(0.5, 0.2, n_attack).clip(0),
        "Idle Mean":                  rng.normal(0, 0, n_attack).clip(0),
        "Idle Std":                   rng.normal(0, 0, n_attack).clip(0),
        "Average Packet Size":        rng.normal(100, 10, n_attack).clip(0),
        "Avg Fwd Segment Size":       rng.normal(100, 10, n_attack).clip(0),
        "Avg Bwd Segment Size":       rng.normal(5, 2, n_attack).clip(0),
        "Subflow Fwd Packets":        rng.poisson(500, n_attack),
        "Subflow Bwd Packets":        rng.poisson(1, n_attack),
        "Subflow Fwd Bytes":          rng.normal(50000, 10000, n_attack).clip(0),
        "Subflow Bwd Bytes":          rng.normal(10, 5, n_attack).clip(0),
        "Source IP":                  [f"192.168.{i%256}.{i%256}" for i in range(n_attack)],
    })

    df = pd.concat([benign, attack], ignore_index=True)
    return df.sample(frac=1, random_state=42).reset_index(drop=True)


# ─────────────────────────────────────────────────────────────────────────────
# BENCHMARK RUNNER
# ─────────────────────────────────────────────────────────────────────────────

def run_benchmark(flow_counts: list, worker_counts: list,
                  batch_size: int = 2000, data_path: str = None):
    """
    Run throughput benchmarks across different scales and worker counts.
    Returns a dict of results.
    """
    results = []

    # Pre-load models once
    ThreadSafeDetector.load_shared_models()

    for n_flows in flow_counts:
        # Generate or load data
        if data_path:
            print(f"\n  Loading real data from {data_path} …")
            if data_path.endswith(".parquet"):
                df = pd.read_parquet(data_path)
            else:
                df = pd.read_csv(data_path, low_memory=False)
            df.columns = df.columns.str.strip()
            # Tile to reach desired flow count
            if len(df) < n_flows:
                repeats = (n_flows // len(df)) + 1
                df = pd.concat([df] * repeats, ignore_index=True)
            df = df.head(n_flows)
        else:
            print(f"\n  Generating {n_flows:,} synthetic flows …")
            df = generate_synthetic_flows(n_flows)

        for n_workers in worker_counts:
            # Suppress mitigation logs for clean benchmark
            logging.getLogger("MitigationHandler").setLevel(logging.CRITICAL)

            agent = StreamingDDoSAgent(
                num_workers=n_workers,
                batch_size=batch_size,
                dry_run=True,
            )

            # Warm-up run (small)
            warm_df = df.head(min(500, n_flows))
            agent.process_dataframe(warm_df)
            agent._stats = {"processed": 0, "attacks": 0, "benign": 0, "batches": 0}

            # Timed run
            t0 = time.perf_counter()
            agent.process_dataframe(df)
            elapsed = time.perf_counter() - t0

            fps = n_flows / elapsed if elapsed > 0 else 0
            attacks = agent._stats["attacks"]

            results.append({
                "flows": n_flows,
                "workers": n_workers,
                "batch_size": batch_size,
                "elapsed_s": round(elapsed, 3),
                "throughput_fps": round(fps, 0),
                "attacks": attacks,
            })

            print(f"    {n_flows:>10,} flows × {n_workers} workers "
                  f"→ {fps:>10,.0f} flows/sec  ({elapsed:.2f}s)")

            agent.shutdown()

    return results


def print_results_table(results: list):
    """Print a formatted results table."""
    print(f"\n{'═'*75}")
    print(f"  SCALABILITY BENCHMARK RESULTS")
    print(f"{'═'*75}")
    print(f"  {'Flows':>12}  {'Workers':>7}  {'Time (s)':>9}  "
          f"{'Throughput':>14}  {'Attacks':>8}")
    print(f"  {'─'*12}  {'─'*7}  {'─'*9}  {'─'*14}  {'─'*8}")
    for r in results:
        print(f"  {r['flows']:>12,}  {r['workers']:>7}  {r['elapsed_s']:>9.3f}  "
              f"{r['throughput_fps']:>12,.0f}/s  {r['attacks']:>8,}")
    print(f"{'═'*75}")

    # Find peak throughput
    peak = max(results, key=lambda r: r["throughput_fps"])
    print(f"\n  🏆 Peak throughput: {peak['throughput_fps']:,.0f} flows/sec "
          f"({peak['flows']:,} flows, {peak['workers']} workers)")

    # Calculate speedup
    single = [r for r in results if r["workers"] == 1]
    multi  = [r for r in results if r["workers"] == max(r2["workers"] for r2 in results)]
    if single and multi:
        # Compare at largest flow count
        s = max(single, key=lambda r: r["flows"])
        m = max(multi,  key=lambda r: r["flows"])
        if s["throughput_fps"] > 0:
            speedup = m["throughput_fps"] / s["throughput_fps"]
            print(f"  📈 Multi-thread speedup: {speedup:.1f}x "
                  f"({s['workers']} → {m['workers']} workers)")


def plot_results(results: list):
    """Generate a performance chart."""
    df = pd.DataFrame(results)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # Plot 1: Throughput vs Workers (at max flow count)
    max_flows = df["flows"].max()
    subset = df[df["flows"] == max_flows]

    ax1.bar(subset["workers"].astype(str), subset["throughput_fps"],
            color=["#2196F3", "#4CAF50", "#FF9800", "#E91E63",
                   "#9C27B0", "#00BCD4", "#795548", "#607D8B"][:len(subset)],
            edgecolor="white", linewidth=1.5)
    ax1.set_xlabel("Number of Worker Threads", fontsize=12)
    ax1.set_ylabel("Throughput (flows/sec)", fontsize=12)
    ax1.set_title(f"Throughput vs Workers ({max_flows:,} flows)", fontsize=13, fontweight="bold")
    for i, v in enumerate(subset["throughput_fps"]):
        ax1.text(i, v + max(subset["throughput_fps"]) * 0.02,
                 f"{v:,.0f}", ha="center", fontweight="bold", fontsize=10)

    # Plot 2: Throughput vs Flow Count (at max workers)
    max_workers = df["workers"].max()
    subset2 = df[df["workers"] == max_workers].sort_values("flows")

    ax2.plot(subset2["flows"], subset2["throughput_fps"],
             "o-", color="#E91E63", linewidth=2.5, markersize=8)
    ax2.set_xlabel("Number of Flows", fontsize=12)
    ax2.set_ylabel("Throughput (flows/sec)", fontsize=12)
    ax2.set_title(f"Throughput vs Scale ({max_workers} workers)", fontsize=13, fontweight="bold")
    ax2.set_xscale("log")

    for _, row in subset2.iterrows():
        ax2.annotate(f"{row['throughput_fps']:,.0f}",
                     (row["flows"], row["throughput_fps"]),
                     textcoords="offset points", xytext=(0, 12),
                     ha="center", fontweight="bold", fontsize=9)

    plt.suptitle("DDoS AI Agent — Scalability Benchmark",
                 fontsize=15, fontweight="bold", y=1.02)
    plt.tight_layout()

    path = "plots/benchmark_results.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"\n  📊 Benchmark chart saved → {path}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="DDoS AI Agent — Scalability Benchmark")
    p.add_argument("--max_flows", type=int, default=100000,
                   help="Maximum flow count to test (default: 100000)")
    p.add_argument("--data", type=str, default=None,
                   help="Optional: use real data file instead of synthetic")
    p.add_argument("--batch", type=int, default=2000,
                   help="Batch size (default: 2000)")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    print(f"\n{'═'*75}")
    print(f"  DDoS AI AGENT — SCALABILITY BENCHMARK")
    print(f"  {'-'*48}")
    print(f"  Max flows  : {args.max_flows:,}")
    print(f"  Data source: {'Synthetic' if not args.data else args.data}")
    print(f"  Batch size : {args.batch}")
    print(f"{'═'*75}")

    # Scale progression
    flow_counts = []
    n = 1000
    while n <= args.max_flows:
        flow_counts.append(n)
        n *= 10
    if flow_counts[-1] != args.max_flows:
        flow_counts.append(args.max_flows)

    worker_counts = [1, 2, 4, 8]

    results = run_benchmark(
        flow_counts=flow_counts,
        worker_counts=worker_counts,
        batch_size=args.batch,
        data_path=args.data,
    )

    print_results_table(results)
    plot_results(results)
