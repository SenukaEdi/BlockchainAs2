import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, request, render_template
from dlt_system import DLTSystem

app = Flask(__name__)

# Keeps backend errors in JSON format so the webpage can read them properly
@app.errorhandler(Exception)
def handle_exception(e):
    import traceback
    traceback.print_exc()
    return jsonify({"error": str(e)}), 500

@app.errorhandler(404)
def handle_404(e):
    return jsonify({"error": "Not found"}), 404

# Creates one shared DLT system for all the API routes to use
system = DLTSystem()


# Collects the step-by-step messages from the DLT system
def make_logger():
    logs = []
    def callback(msg):
        logs.append(msg)
    def get():
        return logs
    return callback, get


@app.route("/")
def index():
    return render_template("index.html")


# Sends all current node records and public keys to the frontend
@app.route("/api/nodes", methods=["GET"])
def api_nodes():
    data = {}
    for nid, node in system.nodes.items():
        data[nid] = {
            "records":    node.records,
            "public_key": {"e": str(node.keys["e"]), "n": str(node.keys["n"])},
        }
    return jsonify({"nodes": data})


# Task 1: signs a new inventory record and checks if all nodes verify it
@app.route("/api/task1", methods=["POST"])
def api_task1():
    body = request.get_json(force=True)
    node_id = body.get("node_id", "").strip().upper()
    record  = body.get("record", {})

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
        return jsonify({"error": "qty and price have to be integers"}), 400

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


# Task 2: runs consensus using the signed record from Task 1
@app.route("/api/task2", methods=["POST"])
def api_task2():
    body      = request.get_json(force=True)
    node_id   = body.get("node_id", "").strip().upper()
    record    = body.get("record", {})
    signature = body.get("signature")

    if node_id not in system.nodes:
        return jsonify({"error": f"Unknown node '{node_id}'"}), 400
    if not signature:
        return jsonify({"error": "signature is needed"}), 400

    try:
        record["qty"]   = int(record["qty"])
        record["price"] = int(record["price"])
        signature       = int(signature)
    except (ValueError, TypeError):
        return jsonify({"error": "qty, price and signature have to be integers"}), 400

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


# Combined flow: does Task 1 first, then immediately runs Task 2
@app.route("/api/task1and2", methods=["POST"])
def api_task1and2():
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

    log1, get1 = make_logger()
    signature, verifications = system.task1_sign_and_verify(
        originating_node_id=node_id,
        new_record=record,
        log_callback=log1,
    )

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


# Task 3: queries an item and returns the multi-signature result
@app.route("/api/task3", methods=["POST"])
def api_task3():
    body    = request.get_json(force=True)
    item_id = body.get("item_id", "").strip()

    if not item_id:
        return jsonify({"error": "item_id is needed"}), 400

    log_cb, get_logs = make_logger()
    result = system.task3_query(item_id=item_id, log_callback=log_cb)

    if result is None:
        return jsonify({"error": "Item not found in any node", "logs": get_logs()}), 404

    safe = {k: (str(v) if isinstance(v, int) else v) for k, v in result.items()}
    safe["partial_sigs"] = [str(s) for s in result.get("partial_sigs", [])]
    safe["logs"] = get_logs()
    return jsonify(safe)


# Clears all stored inventory records from every node
@app.route("/api/reset", methods=["POST"])
def api_reset():
    for node in system.nodes.values():
        node.clear_all_records()
    return jsonify({"ok": True, "message": "All nodes cleared records."})


# Starts the Flask server
if __name__ == "__main__":
    print("\n  web page")
    print("  http://127.0.0.1:5000 \n")
    app.run(debug=True, port=5000)
