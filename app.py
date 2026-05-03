# =============================================================================
# app.py  –  Flask web server for the DLT Inventory Management System
# INTE2627 Assignment 2
# =============================================================================

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, request, render_template
from dlt_system import DLTSystem

app = Flask(__name__)

# Single shared system instance (in-memory state + JSON-file persistence)
system = DLTSystem()


# ---------------------------------------------------------------------------
# Helper: capture logs emitted by DLTSystem methods
# ---------------------------------------------------------------------------

def make_logger():
    """Returns (log_callback, get_logs).  Call get_logs() after the operation."""
    logs = []
    def callback(msg):
        logs.append(msg)
    def get():
        return logs
    return callback, get


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# API – nodes / records
# ---------------------------------------------------------------------------

@app.route("/api/nodes", methods=["GET"])
def api_nodes():
    """Return all nodes with their current records and public keys."""
    data = {}
    for nid, node in system.nodes.items():
        data[nid] = {
            "records":    node.records,
            "public_key": {"e": str(node.keys["e"]), "n": str(node.keys["n"])},
        }
    return jsonify({"nodes": data})


# ---------------------------------------------------------------------------
# API – Task 1: sign a new record
# ---------------------------------------------------------------------------

@app.route("/api/task1", methods=["POST"])
def api_task1():
    """
    Body JSON: { node_id, record: {item_id, qty, price, location} }
    Returns:   { signature, verifications, logs }
    """
    body = request.get_json(force=True)
    node_id = body.get("node_id", "").strip().upper()
    record  = body.get("record", {})

    # Validate
    if node_id not in system.nodes:
        return jsonify({"error": f"Unknown node '{node_id}'. Valid: {list(system.nodes.keys())}"}), 400
    required = {"item_id", "qty", "price", "location"}
    missing  = required - record.keys()
    if missing:
        return jsonify({"error": f"Record missing fields: {missing}"}), 400

    try:
        record["qty"]   = int(record["qty"])
        record["price"] = int(record["price"])
    except (ValueError, TypeError):
        return jsonify({"error": "qty and price must be integers"}), 400

    log_cb, get_logs = make_logger()
    signature, verifications = system.task1_sign_and_verify(
        originating_node_id=node_id,
        new_record=record,
        log_callback=log_cb,
    )

    return jsonify({
        "signature":     str(signature),
        "verifications": {k: bool(v) for k, v in verifications.items()},
        "all_valid":     all(verifications.values()),
        "logs":          get_logs(),
        "node_id":       node_id,
        "record":        record,
    })


# ---------------------------------------------------------------------------
# API – Task 2: run consensus on a pre-signed record
# ---------------------------------------------------------------------------

@app.route("/api/task2", methods=["POST"])
def api_task2():
    """
    Body JSON: { node_id, record, signature }
    Returns:   { consensus_reached, votes, logs }
    """
    body      = request.get_json(force=True)
    node_id   = body.get("node_id", "").strip().upper()
    record    = body.get("record", {})
    signature = body.get("signature")

    if node_id not in system.nodes:
        return jsonify({"error": f"Unknown node '{node_id}'"}), 400
    if not signature:
        return jsonify({"error": "signature is required"}), 400

    try:
        record["qty"]   = int(record["qty"])
        record["price"] = int(record["price"])
        signature       = int(signature)
    except (ValueError, TypeError):
        return jsonify({"error": "qty, price and signature must be integers"}), 400

    log_cb, get_logs = make_logger()
    consensus_reached, votes = system.task2_consensus(
        originating_node_id=node_id,
        new_record=record,
        signature=signature,
        log_callback=log_cb,
    )

    return jsonify({
        "consensus_reached": consensus_reached,
        "votes":             votes,
        "logs":              get_logs(),
    })


# ---------------------------------------------------------------------------
# API – Tasks 1 + 2 combined (most common flow)
# ---------------------------------------------------------------------------

@app.route("/api/task1and2", methods=["POST"])
def api_task1and2():
    """
    Body JSON: { node_id, record: {item_id, qty, price, location} }
    Runs Task 1 then Task 2 sequentially, returns combined result.
    """
    body    = request.get_json(force=True)
    node_id = body.get("node_id", "").strip().upper()
    record  = body.get("record", {})

    if node_id not in system.nodes:
        return jsonify({"error": f"Unknown node '{node_id}'"}), 400

    try:
        record["qty"]   = int(record["qty"])
        record["price"] = int(record["price"])
    except (ValueError, TypeError):
        return jsonify({"error": "qty and price must be integers"}), 400

    # Task 1
    log1, get1 = make_logger()
    signature, verifications = system.task1_sign_and_verify(
        originating_node_id=node_id,
        new_record=record,
        log_callback=log1,
    )

    # Task 2
    log2, get2 = make_logger()
    consensus_reached, votes = system.task2_consensus(
        originating_node_id=node_id,
        new_record=record,
        signature=signature,
        log_callback=log2,
    )

    return jsonify({
        "signature":         str(signature),
        "verifications":     {k: bool(v) for k, v in verifications.items()},
        "all_valid":         all(verifications.values()),
        "consensus_reached": consensus_reached,
        "votes":             votes,
        "logs":              get1() + [""] + get2(),
        "node_id":           node_id,
        "record":            record,
    })


# ---------------------------------------------------------------------------
# API – Task 3: multi-signature query
# ---------------------------------------------------------------------------

@app.route("/api/task3", methods=["POST"])
def api_task3():
    """
    Body JSON: { item_id }
    Returns:   { success, result_record, S, R, encrypted, decrypted, logs, ... }
    """
    body    = request.get_json(force=True)
    item_id = body.get("item_id", "").strip()

    if not item_id:
        return jsonify({"error": "item_id is required"}), 400

    log_cb, get_logs = make_logger()
    result = system.task3_query(item_id=item_id, log_callback=log_cb)

    if result is None:
        return jsonify({"error": "Item not found in any node", "logs": get_logs()}), 404

    # Convert big integers to strings for JSON serialisation
    safe = {k: (str(v) if isinstance(v, int) else v) for k, v in result.items()}
    safe["partial_sigs"] = [str(s) for s in result.get("partial_sigs", [])]
    safe["logs"] = get_logs()
    return jsonify(safe)


# ---------------------------------------------------------------------------
# API – Reset all nodes to defaults
# ---------------------------------------------------------------------------

@app.route("/api/reset", methods=["POST"])
def api_reset():
    """Clear all records from every node. Nodes return to empty state."""
    for node in system.nodes.values():
        node.clear_all_records()
    return jsonify({"ok": True, "message": "All node records cleared."})


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n  DLT Inventory System — web interface")
    print("  Open http://127.0.0.1:5000 in your browser\n")
    app.run(debug=True, port=5000)
