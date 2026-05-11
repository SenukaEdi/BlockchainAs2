# INTE2627 Assignment 2 — DLT Inventory Web Application

## Setup & Run

```bash
# 1. Install Flask (only dependency)
pip install flask

# 2. Run the server
python app.py

# 3. Open in browser
http://127.0.0.1:5000
```

## Project Structure

```
dlt_web/
├── app.py                  # Flask backend — all API routes
├── requirements.txt
├── templates/
│   └── index.html          # Single-page frontend application
├── data/
│   └── default_records.json  # Seed records (edit to change defaults)
│
│   ── Crypto modules (unchanged from CLI version) ──
├── keys_config.py          # Hardcoded RSA keys from List of Keys
├── crypto_utils.py         # RSA primitives from scratch
├── inventory_node.py       # Node class + JSON file persistence
├── consensus.py            # Simplified PBFT consensus engine
├── harn_multisig.py        # Harn identity-based multi-signature
└── dlt_system.py           # Central orchestrator
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/nodes` | All nodes with records and public keys |
| POST | `/api/task1` | Sign a new record (RSA digital signature) |
| POST | `/api/task2` | Run PBFT consensus on a signed record |
| POST | `/api/task1and2` | Combined sign + consensus in one call |
| POST | `/api/task3` | Harn multi-sig query + RSA encrypted delivery |
| POST | `/api/reset` | Reset all nodes to default_records.json |

## Request/Response Examples

### POST /api/task1
```json
// Request
{ "node_id": "A", "record": { "item_id": "004", "qty": 12, "price": 18, "location": "A" } }

// Response
{ "signature": "12345...", "verifications": {"A":true,"B":true,...}, "all_valid": true, "logs": [...] }
```

### POST /api/task3
```json
// Request
{ "item_id": "002" }

// Response
{ "success": true, "result_record": {...}, "S": "...", "R": "...", "encrypted": "...", "decrypted": "item_id=002,qty=20", "sig_verified": true, "sig_consistent": true, "logs": [...] }
```
