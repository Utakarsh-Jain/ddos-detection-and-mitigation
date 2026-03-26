"""

Module  : scalable_pipeline.py
Purpose : Demonstrates the Big-Data / distributed architecture needed to
          scale the DDoS AI Agent to 100 BILLION requests.

Architecture Overview
─────────────────────
  ┌─────────────────────────────────────────────────────────────┐
  │  Network Edge                                               │
  │  Raw packets → Feature Extraction → Kafka Topic             │
  └──────────────────────────┬──────────────────────────────────┘
                             │  (millions of msgs/sec)
  ┌──────────────────────────▼──────────────────────────────────┐
  │  Apache Kafka   (message buffer / shock absorber)           │
  │  Topic: "network-flows"   Partitions: 64+                   │
  └──────────────────────────┬──────────────────────────────────┘
                             │
  ┌──────────────────────────▼──────────────────────────────────┐
  │  Apache Flink Streaming Job                                 │
  │  • Deserialise JSON → extract 40 features                   │
  │  • Tumbling window (1-second) → aggregate per src_ip        │
  │  • Call ML inference microservice via HTTP                  │
  └──────────────┬──────────────────────────┬───────────────────┘
                 │ BENIGN                   │ ATTACK
  ┌──────────────▼──────────┐   ┌───────────▼───────────────────┐
  │  Allow / pass           │   │  Mitigation Service           │
  └─────────────────────────┘   │  • BGP Flowspec drop          │
                                │  • AWS Shield / WAF rule      │
                                │  • Redis blocklist update     │
                                └───────────────────────────────┘

This file contains:
  1. KafkaProducerAdapter  — simulate publishing flows to Kafka
  2. FlinkStyleConsumer    — consume and process flows in micro-batches
  3. RedisConnectionTracker— fast in-memory "connections per source IP"
  4. ModelServingClient    — HTTP client to call Triton/Seldon model server
  5. EdgeMitigationRouter  — dispatch block commands to BGP / Cloud WAF

NOTE: This is a blueprint / reference implementation.
      Full deployment requires a running Kafka cluster, Redis, and Flink.
      Install stubs: pip install kafka-python redis requests
"""

import json
import time
import logging
import hashlib
import threading
from datetime import datetime
from collections import defaultdict
from typing import Any

log = logging.getLogger("ScalablePipeline")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s  [%(levelname)s]  %(message)s")



# 1.  KAFKA PRODUCER ADAPTER


class KafkaFlowProducer:
    """
    Publishes serialised network-flow dicts to a Kafka topic.

    In production, this runs at the network edge on every router/switch.
    Key = src_ip  →  ensures all flows from the same IP land on the
    same Kafka partition (locality for aggregation).

    Real usage:
        pip install kafka-python
        from kafka import KafkaProducer
    """

    TOPIC = "network-flows"

    def __init__(self, bootstrap_servers: str = "localhost:9092"):
        self.bootstrap_servers = bootstrap_servers
        self._producer = None
        self._connect()

    def _connect(self):
        try:
            from kafka import KafkaProducer  # real import
            self._producer = KafkaProducer(
                bootstrap_servers = self.bootstrap_servers,
                value_serializer  = lambda v: json.dumps(v).encode("utf-8"),
                key_serializer    = lambda k: k.encode("utf-8"),
                compression_type  = "gzip",          # reduce bandwidth
                batch_size        = 65536,            # 64 KB batch
                linger_ms         = 5,                # micro-batching
                acks              = 1,                # balance durability/speed
            )
            log.info(f"[Kafka] Connected → {self.bootstrap_servers}")
        except ImportError:
            log.warning("[Kafka] kafka-python not installed. Using stub mode.")
            self._producer = None

    def publish(self, flow: dict):
        key = flow.get("Source IP", "unknown")
        if self._producer:
            self._producer.send(self.TOPIC, key=key, value=flow)
        else:
            # STUB: just log
            log.debug(f"[Kafka-STUB] Published flow from {key}")

    def publish_batch(self, flows: list[dict]):
        for flow in flows:
            self.publish(flow)
        if self._producer:
            self._producer.flush()



# 2.  FLINK-STYLE STREAM CONSUMER  (Python approximation)


class FlinkStyleConsumer:
    """
    Reads from Kafka and processes flows in parallel.

    In production this is a proper Apache Flink job written in Java/Python.
    This Python class mirrors the logic for testing and documentation.

    Key operations:
      • TumblingWindow(1s)  — aggregate stats per src_ip per second
      • Feature assembly    — build the same 40-feature vector as training
      • Inference call      — POST to ModelServingClient
      • Routing             — BENIGN → pass, ATTACK → EdgeMitigationRouter
    """

    WINDOW_SECONDS = 1

    def __init__(self,
                 model_server_url : str = "http://localhost:8000",
                 redis_host       : str = "localhost",
                 mitigation_url   : str = "http://localhost:9000",
                 bootstrap_servers: str = "localhost:9092",
                 topic            : str = "network-flows",
                 num_partitions   : int = 8):

        self.model_client  = ModelServingClient(model_server_url)
        self.conn_tracker  = RedisConnectionTracker(redis_host)
        self.mitigator     = EdgeMitigationRouter(mitigation_url)
        self.topic         = topic
        self.bootstrap     = bootstrap_servers
        self.n_partitions  = num_partitions

        self._window_buffer: dict[str, list] = defaultdict(list)
        self._lock = threading.Lock()

    def start(self):
        """Spawn one consumer thread per Kafka partition."""
        log.info(f"[Flink] Starting {self.n_partitions} partition consumers …")
        threads = []
        for partition_id in range(self.n_partitions):
            t = threading.Thread(
                target=self._consume_partition,
                args=(partition_id,),
                daemon=True,
            )
            t.start()
            threads.append(t)

        # Window aggregator runs in main thread
        try:
            self._window_aggregation_loop()
        except KeyboardInterrupt:
            log.info("[Flink] Shutting down.")

    def _consume_partition(self, partition_id: int):
        try:
            from kafka import KafkaConsumer, TopicPartition
            consumer = KafkaConsumer(
                bootstrap_servers    = self.bootstrap,
                value_deserializer   = lambda v: json.loads(v.decode("utf-8")),
                group_id             = "ddos-agent-group",
                auto_offset_reset    = "latest",
                enable_auto_commit   = True,
            )
            tp = TopicPartition(self.topic, partition_id)
            consumer.assign([tp])

            for message in consumer:
                flow = message.value
                with self._lock:
                    src = flow.get("Source IP", "unknown")
                    self._window_buffer[src].append(flow)

        except ImportError:
            log.warning(f"[Flink-STUB] Partition {partition_id}: kafka-python not installed.")

    def _window_aggregation_loop(self):
        """Every WINDOW_SECONDS, process buffered flows per src_ip."""
        while True:
            time.sleep(self.WINDOW_SECONDS)
            with self._lock:
                snapshot = dict(self._window_buffer)
                self._window_buffer.clear()

            for src_ip, flows in snapshot.items():
                features = self._aggregate_window_features(src_ip, flows)
                prediction, confidence = self.model_client.predict(features)
                if prediction == 1:
                    self.mitigator.block(src_ip, confidence)

    def _aggregate_window_features(self, src_ip: str, flows: list[dict]) -> dict:
        """
        Aggregate a window of flows from one src_ip into a single feature
        vector.  This is where 'connections per source IP' is computed.
        """
        if not flows:
            return {}

        n = len(flows)
        total_bytes   = sum(float(f.get("Total Length of Fwd Packets", 0)) for f in flows)
        total_packets = sum(float(f.get("Total Fwd Packets", 0)) for f in flows)
        avg_duration  = sum(float(f.get("Flow Duration", 0)) for f in flows) / n
        syn_count     = sum(float(f.get("SYN Flag Count", 0)) for f in flows)

        # Connections per source IP in this window — key DDoS signal
        conn_per_src_ip = self.conn_tracker.increment_and_get(src_ip)

        return {
            "Source IP"                 : src_ip,
            "feat_conn_per_src_ip"      : conn_per_src_ip,
            "Flow Bytes/s"              : total_bytes / (avg_duration + 1e-6),
            "Flow Packets/s"            : total_packets / (avg_duration + 1e-6),
            "Flow Duration"             : avg_duration,
            "SYN Flag Count"            : syn_count,
            "Total Fwd Packets"         : total_packets,
            "Total Length of Fwd Packets": total_bytes,
            # Pass through other features from first flow in window
            **{k: v for k, v in flows[0].items() if k not in (
                "Source IP", "Flow Bytes/s", "Flow Packets/s"
            )},
        }



# 3.  REDIS CONNECTION TRACKER


class RedisConnectionTracker:
    """
    Uses Redis in-memory store to maintain a per-source-IP connection counter
    with a 60-second TTL.  O(1) GET + INCR at millions of ops/sec.

    Requirement: pip install redis
    """

    TTL_SECONDS = 60

    def __init__(self, host: str = "localhost", port: int = 6379):
        self._client = None
        self._local  = defaultdict(int)   # fallback if Redis unavailable
        try:
            import redis
            self._client = redis.Redis(host=host, port=port,
                                       decode_responses=True)
            self._client.ping()
            log.info(f"[Redis] Connected → {host}:{port}")
        except Exception as e:
            log.warning(f"[Redis] Not available ({e}). Using local counter.")

    def increment_and_get(self, src_ip: str) -> int:
        key = f"conn:{src_ip}"
        if self._client:
            count = self._client.incr(key)
            if count == 1:
                self._client.expire(key, self.TTL_SECONDS)
            return count
        else:
            self._local[src_ip] += 1
            return self._local[src_ip]

    def get(self, src_ip: str) -> int:
        if self._client:
            val = self._client.get(f"conn:{src_ip}")
            return int(val) if val else 0
        return self._local.get(src_ip, 0)



# 4.  MODEL SERVING CLIENT  (Triton / Seldon / FastAPI)


class ModelServingClient:
    """
    Sends feature vectors to a model serving endpoint and returns predictions.

    Compatible with:
      • NVIDIA Triton Inference Server  (KFServing V2 protocol)
      • Seldon Core
      • A simple FastAPI wrapper around the .pkl models

    For the academic demo, we fall back to local inference if no server is up.
    """

    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url  = base_url
        self._local_rf  = None
        self._local_xgb_clf = None
        self._scaler    = None
        self._features  = None
        self._load_local_fallback()

    def _load_local_fallback(self):
        """Load local models for when the server is unavailable."""
        try:
            import joblib, xgboost as xgb
            self._local_rf  = joblib.load("models/rf_model.pkl")
            self._local_xgb_clf = xgb.XGBClassifier()
            self._local_xgb_clf.load_model("models/xgb_model.json")
            self._scaler    = joblib.load("models/scaler.pkl")
            with open("data/processed/feature_names.txt") as f:
                self._features = [l.strip() for l in f.readlines()]
            log.info("[ModelServer] Local model fallback loaded.")
        except Exception:
            log.warning("[ModelServer] Local models not available yet. Run train first.")

    def predict(self, flow: dict) -> tuple[int, float]:
        """Returns (prediction, confidence)."""
        try:
            return self._predict_http(flow)
        except Exception:
            return self._predict_local(flow)

    def _predict_http(self, flow: dict) -> tuple[int, float]:
        import requests
        payload = {"inputs": [{"name": "flow", "data": flow}]}
        r = requests.post(f"{self.base_url}/v2/models/ddos_agent/infer",
                          json=payload, timeout=0.05)   # 50ms max latency
        r.raise_for_status()
        data = r.json()
        prob = data["outputs"][0]["data"][0]
        return int(prob >= 0.60), prob

    def _predict_local(self, flow: dict) -> tuple[int, float]:
        if self._local_rf is None:
            return 0, 0.0
        import numpy as np
        row = [float(flow.get(f, 0.0)) for f in self._features]
        X = self._scaler.transform(np.array(row).reshape(1, -1))
        rf_p  = self._local_rf.predict_proba(X)[0, 1]
        xgb_p = self._local_xgb_clf.predict_proba(X)[0, 1]
        prob  = 0.45 * rf_p + 0.55 * xgb_p
        return int(prob >= 0.60), float(prob)



# 5.  EDGE MITIGATION ROUTER


class EdgeMitigationRouter:
    """
    Dispatches block commands to the network edge.

    Strategies (in order of priority)
    ───────────────────────────────────
    1. BGP Flowspec  — inject a /32 blackhole route for the attacking IP.
                       Traffic is dropped at the ISP level, never reaches server.
    2. AWS Shield    — call AWS Shield Advanced API to add WAF rule.
    3. Local iptables— fallback for on-premise or lab environments.
    """

    def __init__(self, mitigation_service_url: str = "http://localhost:9000"):
        self.url = mitigation_service_url

    def block(self, src_ip: str, confidence: float):
        log.warning(f"[EdgeMitigation] Blocking {src_ip}  conf={confidence:.3f}")
        self._bgp_flowspec_block(src_ip)
        self._aws_shield_block(src_ip, confidence)

    def _bgp_flowspec_block(self, src_ip: str):
        """
        BGP Flowspec RFC 5575 — announce a /32 blackhole to upstream routers.
        In production: use ExaBGP or GoBGP to inject the route.
        """
        log.info(f"[BGP-Flowspec] ANNOUNCE blackhole {src_ip}/32 community 65001:666")
        # Example ExaBGP command (run on BGP router):
        # neighbor 192.0.2.1 announce flow route {
        #     match { source 10.0.0.1/32; }
        #     then  { discard; }
        # }

    def _aws_shield_block(self, src_ip: str, confidence: float):
        """
        Add WAF IP set rule via AWS Shield Advanced / AWS WAF.
        Requires: pip install boto3 + AWS credentials configured.
        """
        if confidence < 0.90:
            return    # only escalate to cloud WAF for high-confidence attacks
        log.info(f"[AWS-Shield] Adding WAF rule for {src_ip}")
        try:
            import boto3
            waf = boto3.client("wafv2", region_name="us-east-1")
            # In production: call waf.update_ip_set() to add the attacking IP
        except ImportError:
            log.debug("[AWS-Shield] boto3 not installed — skipped.")



# QUICK DEMO


if __name__ == "__main__":
    print("\n" + "═"*60)
    print("  SCALABLE PIPELINE — COMPONENT DEMO")
    print("═"*60)

    # Redis tracker demo
    tracker = RedisConnectionTracker()
    for i in range(5):
        count = tracker.increment_and_get("192.168.1.1")
        print(f"  Connections from 192.168.1.1 : {count}")

    # Model serving demo (local fallback)
    client = ModelServingClient()
    dummy_flow = {" Flow Duration": 1000, " Flow Bytes/s": 5000000,
                  " SYN Flag Count": 50, " Total Fwd Packets": 100}
    pred, conf = client.predict(dummy_flow)
    print(f"\n  Dummy flow prediction : {'ATTACK' if pred else 'BENIGN'}  ({conf:.4f})")

    # Edge mitigation demo
    router = EdgeMitigationRouter()
    router.block("192.168.1.1", confidence=0.97)
    print("\n[✓] All pipeline components initialised successfully.")
