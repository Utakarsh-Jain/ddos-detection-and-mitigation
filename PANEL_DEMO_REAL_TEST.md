docker compose build ddos-api

$env:DRY_RUN="false"
docker compose up -d ddos-api

docker compose run --rm ddos-api python -c "import pandas as pd; from data_preprocessing import drop_irrelevant_columns, handle_missing_and_infinite, encode_labels, engineer_features; from agent_core import DDoSAgent; agent=DDoSAgent(dry_run=False); df=pd.read_parquet('data/raw/UDP-testing.parquet'); df.columns=df.columns.str.strip(); df=drop_irrelevant_columns(df); df=handle_missing_and_infinite(df); df=encode_labels(df); df=engineer_features(df); rows=df[df['label']==1].head(20); ports=[80,443,53,8080];
for i,(_,r) in enumerate(rows.iterrows(), start=1):
 flow=r.to_dict(); flow['Source IP']=f'203.0.113.{i}'; flow['Destination Port']=ports[i%4]; pred,conf=agent.process_flow(flow);
print('done', agent.mitigator.get_stats())"

Get-Content .\logs\mitigation.log -Tail 120

Get-Content .\logs\mixed_test_with_mitigation_metrics.json

docker compose down

Reset environment for future safe runs:
$env:DRY_RUN="true"