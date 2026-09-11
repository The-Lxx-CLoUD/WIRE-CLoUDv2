import os
import sys
import json
import tempfile
import webbrowser
import threading
from datetime import datetime

from flask import Flask, jsonify, request, render_template, send_file
from flask_socketio import SocketIO

sys.path.insert(0, os.path.dirname(__file__))
from capture_engine import CaptureEngine, platform_hint 

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(os.path.dirname(BASE_DIR), "frontend")

app = Flask(
    __name__,
    template_folder=os.path.join(FRONTEND_DIR, "templates"),
    static_folder=os.path.join(FRONTEND_DIR, "static"),
)
app.config["SECRET_KEY"] = "wire-cloud-local-secret"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

engine = CaptureEngine()


def push_packet(entry):
    """Callback from CaptureEngine -> broadcast to all connected clients."""
    if "error" in entry:
        socketio.emit("capture_error", entry)
    else:
        socketio.emit("packet", entry)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/platform")
def api_platform():
    return jsonify(platform_hint())


@app.route("/api/interfaces")
def api_interfaces():
    try:
        return jsonify({"ok": True, "interfaces": engine.list_interfaces()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/capture/start", methods=["POST"])
def api_start():
    data = request.get_json(silent=True) or {}
    ok, msg = engine.start(
        interface=data.get("interface"),
        bpf_filter=data.get("filter", ""),
        on_packet=push_packet,
    )
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/capture/stop", methods=["POST"])
def api_stop():
    ok, msg = engine.stop()
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/capture/clear", methods=["POST"])
def api_clear():
    engine.clear()
    return jsonify({"ok": True})


@app.route("/api/packets")
def api_packets():
    offset = int(request.args.get("offset", 0))
    limit = int(request.args.get("limit", 200))
    proto = request.args.get("protocol") or None
    search = request.args.get("search") or None
    
    display_filter = request.args.get("filter") or None
    items, total = engine.get_packets(offset, limit, proto, search, display_filter)
    return jsonify({"ok": True, "items": items, "total": total})


@app.route("/api/packet/<int:pkt_id>")
def api_packet_detail(pkt_id):
    detail = engine.get_packet_detail(pkt_id)
    if detail is None:
        return jsonify({"ok": False, "error": "not found"}), 404
    return jsonify({"ok": True, "detail": detail})


@app.route("/api/stats")
def api_stats():
    return jsonify({"ok": True, "stats": engine.stats, "running": engine.running})


@app.route("/api/hierarchy")
def api_hierarchy():
    """Protocol-hierarchy tree, like Wireshark's Statistics -> Protocol Hierarchy."""
    return jsonify({"ok": True, "hierarchy": engine.get_protocol_hierarchy()})


@app.route("/api/conversations")
def api_conversations():
    """Endpoint-pair traffic aggregation, like Wireshark's Statistics -> Conversations."""
    return jsonify({"ok": True, "conversations": engine.get_conversations()})


@app.route("/api/stream/<int:pkt_id>")
def api_stream(pkt_id):
    """Reassembled TCP stream for the given packet, like Wireshark's
    "Follow -> TCP Stream"."""
    stream = engine.get_tcp_stream(pkt_id)
    if stream is None:
        return jsonify({"ok": False, "error": "packet is not part of a TCP stream"}), 404
    return jsonify({"ok": True, "stream": stream})


@app.route("/api/export")
def api_export():
    tmp = os.path.join(tempfile.gettempdir(), "wire-cloud-export.pcap")
    ok = engine.export_pcap(tmp)
    if not ok:
        return jsonify({"ok": False, "error": "buffer empty"}), 400
    return send_file(tmp, as_attachment=True, download_name="wire-cloud-capture.pcap")


@app.route("/api/session/save", methods=["POST"])
def api_session_save():
    """
    Save the current buffer as a .pcap + a JSON summary into /captures.
    The PHP reporting dashboard (php/index.php) reads this folder to
    show a history of past capture sessions.
    """
    captures_dir = os.path.join(os.path.dirname(FRONTEND_DIR), "captures")
    os.makedirs(captures_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_path = os.path.join(captures_dir, f"session_{stamp}.pcap")
    json_path = os.path.join(captures_dir, f"session_{stamp}.json")

    if not engine.export_pcap(pcap_path):
        return jsonify({"ok": False, "error": "buffer empty"}), 400

    summary = {
        "session": f"session_{stamp}",
        "created_at": stamp,
        "interface": engine.interface,
        "filter": engine.bpf_filter,
        "stats": engine.stats,
        "pcap_file": os.path.basename(pcap_path),
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    return jsonify({"ok": True, "session": summary["session"]})


def _open_browser():
    webbrowser.open("http://127.0.0.1:5000")


if __name__ == "__main__":
    if "--no-browser" not in sys.argv:
        threading.Timer(1.2, _open_browser).start()
    print("=" * 60)
    print(" WIRE-CLOUD  is running at  http://127.0.0.1:5000")
    print(" WIRE-CLOUD  در حال اجراست:  http://127.0.0.1:5000")
    print(" Press CTRL+C to stop / برای توقف Ctrl+C را بزنید")
    print("=" * 60)
    socketio.run(app, host="127.0.0.1", port=5000, debug=False, allow_unsafe_werkzeug=True)
