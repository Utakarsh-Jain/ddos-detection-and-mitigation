# Panel Demo Runbook: Real Execute Mitigation (Docker)

This guide is a copy-paste script for demonstrating **real mitigation command execution** (not dry-run) in front of a panel.

It is written for **Windows PowerShell** in this repository.

---

## 1) What You Will Prove

By the end of this demo, you will show:

1. Mixed benign + attack flow evaluation works.
2. Attack flows trigger mitigation actions.
3. Mitigation runs in **real execute mode** inside Docker (iptables commands actually execute).
4. Logs contain evidence (`[CMD OK] BLOCK_IP`, `[CMD OK] BLOCK_PORT ...`).

---

## 2) Prerequisites

Run from repository root:

```powershell
Get-Location
```

Expected: path ending with `ddos-detection-and-mitigation`.

Verify Docker:

```powershell
docker --version
docker compose version
```

---

## 3) Optional: Clean Start

```powershell
docker compose down --remove-orphans
```

---

## 4) Build the Docker Image

```powershell
docker compose build ddos-api
```

This uses the patched Docker image that includes iptables tooling.

---

## 5) Start API Container in Real Execute Mode

```powershell
$env:DRY_RUN="false"
docker compose up -d ddos-api
```

Sanity-check container status:

```powershell
docker compose ps
```

Sanity-check API health:

```powershell
Invoke-RestMethod http://localhost:8000/health
```

---

## 6) Run Real Execute Mitigation Test in Container

This command loads attack flows, injects Source IP and Destination Port, and executes mitigation with `dry_run=False`.

```powershell
docker compose run --rm ddos-api python -c "import pandas as pd; from data_preprocessing import drop_irrelevant_columns, handle_missing_and_infinite, encode_labels, engineer_features; from agent_core import DDoSAgent; agent=DDoSAgent(dry_run=False); df=pd.read_parquet('data/raw/UDP-testing.parquet'); df.columns=df.columns.str.strip(); df=drop_irrelevant_columns(df); df=handle_missing_and_infinite(df); df=encode_labels(df); df=engineer_features(df); rows=df[df['label']==1].head(20); ports=[80,443,53,8080];
for i,(_,r) in enumerate(rows.iterrows(), start=1):
 flow=r.to_dict(); flow['Source IP']=f'203.0.113.{i}'; flow['Destination Port']=ports[i%4]; pred,conf=agent.process_flow(flow);
print('done', agent.mitigator.get_stats())"
```

Expected ending line:

```text
done {'total_alerts': 20, 'ips_blocked': 20, 'ips_unblocked': 0, 'ports_blocked': 20}
```

---

## 7) Show Hard Evidence in Logs (Most Important Slide/Terminal)

```powershell
Get-Content .\logs\mitigation.log -Tail 120
```

Point out these lines live:

1. `[CMD OK] BLOCK_IP ...`
2. `[CMD OK] BLOCK_PORT TCP ...`
3. `[CMD OK] BLOCK_PORT UDP ...`
4. `[BLOCKED] ...`
5. `[PORT-BLOCK] ...`

These prove real execution (not simulation).

---

## 8) Optional: Show Inserted Rules Inside Running Container

Because the one-shot test container is removed (`--rm`), inspect rules in the long-running `ddos-api` service container:

```powershell
docker compose exec ddos-api sh -c "iptables -S INPUT | head -n 80"
```

If needed, filter by your demo IP range:

```powershell
docker compose exec ddos-api sh -c "iptables -S INPUT | grep 203.0.113."
```

---

## 9) Mention Model Accuracy (Panel Talking Point)

If you want to show model metrics too:

```powershell
Get-Content .\logs\mixed_test_with_mitigation_metrics.json
```

Call out per-model metrics:

1. Random Forest accuracy
2. XGBoost accuracy
3. Ensemble accuracy
4. Confusion matrix values

---

## 10) End Demo Safely (Cleanup)

Stop containers:

```powershell
docker compose down
```

Reset environment for future safe runs:

```powershell
$env:DRY_RUN="true"
```

---

## 11) 60-Second Panel Script

Use this exact narration:

1. "I am running the detection + mitigation system in Docker with DRY_RUN=false."
2. "Now I replay attack flows with injected source IP and destination ports."
3. "The model flags attacks and mitigation handler issues real iptables commands."
4. "These `[CMD OK] BLOCK_IP` and `[CMD OK] BLOCK_PORT` logs confirm actual execution."
5. "This demonstrates both detection quality and automated response capability."

---

## 12) Troubleshooting During Demo

If API does not start:

```powershell
docker compose logs --tail 120 ddos-api
```

If port 8000 is busy:

```powershell
docker compose down
```

Then restart service:

```powershell
$env:DRY_RUN="false"
docker compose up -d ddos-api
```

If you want a clean rebuild:

```powershell
docker compose down --remove-orphans
docker compose build --no-cache ddos-api
```
