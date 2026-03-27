"""
Usage:
    python app.py
    
    # or with uvicorn directly:
    uvicorn app:app --host 0.0.0.0 --port 8000 --reload
"""

import os
import sys
import logging
from typing import List, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (
    API_HOST, API_PORT, API_RELOAD,
    DETECTION_THRESHOLD, DRY_RUN
)

# Conditional import (graceful degradation if agent not available)
try:
    from agent_core import DDoSAgent
    AGENT_AVAILABLE = True
except Exception as e:
    AGENT_AVAILABLE = False
    print(f"[WARN] Agent not available ({e}). API will run in demo mode.")


# LOGGING


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("FastAPI")


# FASTAPI APP


app = FastAPI(
    title="DDoS AI Agent API",
    description="Real-time DDoS detection and mitigation using ML ensemble",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Global agent instance
agent = None


@app.on_event("startup")
async def startup_event():
    """Initialize agent on API startup."""
    global agent
    if AGENT_AVAILABLE:
        try:
            logger.info("Loading DDoS Agent...")
            agent = DDoSAgent(dry_run=DRY_RUN)
            logger.info("DDoS Agent loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load agent: {e}")
            agent = None



# PYDANTIC MODELS


class NetworkFlow(BaseModel):
    """Network flow for DDoS detection."""
    
    source_ip: str = Field(..., description="Source IP address")
    destination_ip: str = Field(..., description="Destination IP address")
    destination_port: int = Field(..., description="Destination port", ge=0, le=65535)
    flow_duration: float = Field(default=1000000, description="Flow duration in microseconds")
    flow_bytes_per_sec: float = Field(default=1024.0, description="Bytes per second")
    flow_packets_per_sec: float = Field(default=10.0, description="Packets per second")
    total_fwd_packets: int = Field(default=50, description="Total forward packets")
    total_bwd_packets: int = Field(default=50, description="Total backward packets")
    syn_flag_count: int = Field(default=0, description="SYN flag count")
    ack_flag_count: int = Field(default=50, description="ACK flag count")
    fin_flag_count: int = Field(default=0, description="FIN flag count")
    rst_flag_count: int = Field(default=0, description="RST flag count")
    average_packet_size: float = Field(default=512.0, description="Average packet size")
    
    class Config:
        schema_extra = {
            "example": {
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.1",
                "destination_port": 443,
                "flow_duration": 1000000,
                "flow_bytes_per_sec": 1024.0,
                "flow_packets_per_sec": 10.0,
                "total_fwd_packets": 50,
                "total_bwd_packets": 50,
                "syn_flag_count": 1,
                "ack_flag_count": 50,
                "fin_flag_count": 1,
                "rst_flag_count": 0,
                "average_packet_size": 512.0,
            }
        }


class DetectionResponse(BaseModel):
    """Response from detection endpoint."""
    
    is_attack: bool = Field(..., description="Whether flow is classified as attack")
    confidence: float = Field(..., description="Ensemble confidence score [0, 1]")
    rf_score: float = Field(..., description="Random Forest score [0, 1]")
    xgb_score: float = Field(..., description="XGBoost score [0, 1]")
    threshold: float = Field(..., description="Detection threshold used")
    timestamp: str = Field(..., description="Detection timestamp")


class HealthResponse(BaseModel):
    """Health check response."""
    
    status: str = Field(..., description="Service status")
    agent_available: bool = Field(..., description="Whether agent is loaded")
    timestamp: str = Field(..., description="Response timestamp")


class ErrorResponse(BaseModel):
    """Error response."""
    
    error: str = Field(..., description="Error message")
    detail: Optional[str] = Field(None, description="Error details")
    timestamp: str = Field(..., description="Error timestamp")



# API ENDPOINTS


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with API information."""
    return {
        "name": "DDoS AI Agent API",
        "version": "1.0.0",
        "status": "online",
        "endpoints": {
            "health": "/health",
            "detect": "/detect",
            "batch": "/batch",
            "docs": "/docs",
            "redoc": "/redoc",
        }
    }


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Check API and agent health."""
    return HealthResponse(
        status="healthy" if agent else "degraded",
        agent_available=agent is not None,
        timestamp=datetime.now().isoformat(),
    )


@app.post("/detect", response_model=DetectionResponse, tags=["Detection"])
async def detect_ddos(flow: NetworkFlow):
    """
    Detect if a network flow is a DDoS attack.
    
    **Parameters:**
    - `flow`: Network flow data with 13 features
    
    **Returns:**
    - `is_attack`: Boolean prediction (True = attack, False = benign)
    - `confidence`: Ensemble confidence [0, 1]
    - `rf_score`: Random Forest score
    - `xgb_score`: XGBoost score
    - `threshold`: Detection threshold
    - `timestamp`: Detection time
    
    **Example Request:**
    ```json
    {
      "source_ip": "192.168.1.100",
      "destination_ip": "10.0.0.1",
      "destination_port": 443,
      "flow_bytes_per_sec": 50000,
      "flow_packets_per_sec": 5000
    }
    ```
    """
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not available")
    
    try:
        # Convert flow to dictionary
        flow_dict = {
            "Source IP": flow.source_ip,
            "Destination IP": flow.destination_ip,
            "Destination Port": flow.destination_port,
            "Flow Duration": flow.flow_duration,
            "Flow Bytes/s": flow.flow_bytes_per_sec,
            "Flow Packets/s": flow.flow_packets_per_sec,
            "Total Fwd Packets": flow.total_fwd_packets,
            "Total Backward Packets": flow.total_bwd_packets,
            "SYN Flag Count": flow.syn_flag_count,
            "ACK Flag Count": flow.ack_flag_count,
            "FIN Flag Count": flow.fin_flag_count,
            "RST Flag Count": flow.rst_flag_count,
            "Average Packet Size": flow.average_packet_size,
        }
        
        # Run detection
        pred, conf, rf_score, xgb_score = agent.detector.predict(flow_dict)
        
        is_attack = pred == 1 and conf >= DETECTION_THRESHOLD

        if is_attack:
            agent.mitigator.handle_alert(
                src_ip=flow.source_ip,
                dst_port=flow.destination_port,
                confidence=float(conf),
                model_name="Ensemble(RF+XGB)",
            )
        
        logger.info(
            f"[DETECT] {flow.source_ip} -> {flow.destination_ip}:{flow.destination_port} "
            f"| Attack: {is_attack} | Conf: {conf:.4f}"
        )
        
        return DetectionResponse(
            is_attack=is_attack,
            confidence=float(conf),
            rf_score=float(rf_score),
            xgb_score=float(xgb_score),
            threshold=DETECTION_THRESHOLD,
            timestamp=datetime.now().isoformat(),
        )
    
    except Exception as e:
        logger.error(f"Detection error: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Detection failed"
        )


@app.post("/batch", tags=["Detection"])
async def detect_batch(flows: List[NetworkFlow]):
    """
    Detect multiple flows in a single batch request.
    
    **Parameters:**
    - `flows`: List of network flows
    
    **Returns:**
    - Array of detection results
    """
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not available")
    
    results = []
    for flow in flows:
        try:
            flow_dict = {
                "Source IP": flow.source_ip,
                "Destination IP": flow.destination_ip,
                "Destination Port": flow.destination_port,
                "Flow Duration": flow.flow_duration,
                "Flow Bytes/s": flow.flow_bytes_per_sec,
                "Flow Packets/s": flow.flow_packets_per_sec,
                "Total Fwd Packets": flow.total_fwd_packets,
                "Total Backward Packets": flow.total_bwd_packets,
                "SYN Flag Count": flow.syn_flag_count,
                "ACK Flag Count": flow.ack_flag_count,
                "FIN Flag Count": flow.fin_flag_count,
                "RST Flag Count": flow.rst_flag_count,
                "Average Packet Size": flow.average_packet_size,
            }
            
            pred, conf, rf_score, xgb_score = agent.detector.predict(flow_dict)
            is_attack = pred == 1 and conf >= DETECTION_THRESHOLD

            if is_attack:
                agent.mitigator.handle_alert(
                    src_ip=flow.source_ip,
                    dst_port=flow.destination_port,
                    confidence=float(conf),
                    model_name="Ensemble(RF+XGB)",
                )
            
            results.append({
                "source_ip": flow.source_ip,
                "destination_ip": flow.destination_ip,
                "is_attack": is_attack,
                "confidence": float(conf),
                "timestamp": datetime.now().isoformat(),
            })
        except Exception as e:
            logger.error(f"Batch detection error: {e}")
    
    logger.info(f"[BATCH] Processed {len(flows)} flows | Attacks: {sum(1 for r in results if r['is_attack'])}")
    
    return {"flows": results, "total": len(flows), "attacks": sum(1 for r in results if r['is_attack'])}


@app.get("/stats", tags=["Monitoring"])
async def get_stats():
    """Get agent statistics."""
    if not agent:
        raise HTTPException(status_code=503, detail="Agent not available")
    
    return {
        "processed_flows": agent._counters.get("processed", 0),
        "attacks_detected": agent._counters.get("attacks", 0),
        "benign_flows": agent._counters.get("benign", 0),
        "timestamp": datetime.now().isoformat(),
    }



# ERROR HANDLERS


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle unexpected exceptions."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": "An unexpected error occurred",
            "timestamp": datetime.now().isoformat(),
        },
    )



# MAIN


if __name__ == "__main__":
    import uvicorn
    
    logger.info(f"Starting DDoS AI Agent API on {API_HOST}:{API_PORT}")
    logger.info("Docs available at: http://localhost:8000/docs")
    
    uvicorn.run(
        app,
        host=API_HOST,
        port=API_PORT,
        reload=API_RELOAD,
        log_level="info",
    )
