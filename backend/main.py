import os
import time
import numpy as np
from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from web3 import Web3
from solcx import compile_source, install_solc, get_installed_solc_versions
from sklearn.ensemble import IsolationForest
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST, Counter, Histogram

app = FastAPI(title="Appstars AI-Driven Web3 Secure Gateway with Observability")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

ML_INFERENCE_LATENCY = Histogram('appstars_ml_inference_latency_seconds', 'Time taken for Isolation Forest to compute anomaly scores')
SECURITY_EVENTS_TOTAL = Counter('appstars_security_events_total', 'Total login attempts tracked by type', ['status', 'safety_rating'])

RPC_URL = os.getenv("RPC_URL", "http://web3-app-rpc-service:8545")
w3 = Web3(Web3.HTTPProvider(RPC_URL))
contract_address, contract_abi = None, None

SOLIDITY_CODE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract LoginAudit {
    struct LogEntry { string username; uint256 timestamp; string status; string safetyRating; }
    LogEntry[] public auditTrail;
    function recordLogin(string memory _username, string memory _status, string memory _rating) public {
        auditTrail.push(LogEntry(_username, block.timestamp, _status, _rating));
    }
}
"""

normal_behavior_data = np.array([[9,2,1], [10,1,1], [14,2,1], [16,1,1], [11,2,2]])
clf = IsolationForest(contamination=0.1, random_state=42).fit(normal_behavior_data)

class LoginRequest(BaseModel):
    username: str
    password: str
    password_attempts: int

@app.on_event("startup")
def setup_services():
    global contract_address, contract_abi
    if "0.8.20" not in [str(v) for v in get_installed_solc_versions()]:
        install_solc("0.8.20")
    if w3.is_connected():
        compiled_sol = compile_source(SOLIDITY_CODE, solc_version="0.8.20")
        _, contract_interface = compiled_sol.popitem()
        tx_hash = w3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin']).constructor().transact({'from': w3.eth.accounts[0]})
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        contract_address, contract_abi = tx_receipt.contractAddress, contract_interface['abi']

@app.get("/metrics")
def get_metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.post("/api/login")
def login_user(data: LoginRequest):
    global contract_address, contract_abi
    current_hour = time.localtime().tm_hour
    user_feature_vector = np.array([[current_hour, 2, data.password_attempts]])

    with ML_INFERENCE_LATENCY.time():
        ml_prediction = clf.predict(user_feature_vector)

    ai_safety_rating = "SAFE_NORMAL_TRAFFIC" if ml_prediction == 1 else "ANOMALOUS_ATTACK_WARNING"
    status_msg = "SUCCESS" if (data.username == "admin" and data.password == "password123" and ai_safety_rating == "SAFE_NORMAL_TRAFFIC") else "REJECTED_OR_BLOCKED"

    SECURITY_EVENTS_TOTAL.labels(status=status_msg, safety_rating=ai_safety_rating).inc()

    try:
        contract = w3.eth.contract(address=contract_address, abi=contract_abi)
        tx_hash = contract.functions.recordLogin(data.username, status_msg, ai_safety_rating).transact({'from': w3.eth.accounts[0]})
        w3.eth.wait_for_transaction_receipt(tx_hash)
        if status_msg == "REJECTED_OR_BLOCKED":
            raise HTTPException(status_code=401, detail=f"Blocked. Threat Assessment: {ai_safety_rating}")
        return {"message": "Authenticated!", "ai_threat_assessment": ai_safety_rating, "blockchain_audit_tx": tx_hash.hex()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
