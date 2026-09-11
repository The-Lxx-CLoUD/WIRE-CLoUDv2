import threading
import time
import platform
from collections import deque, OrderedDict
from datetime import datetime

from scapy.all import sniff, get_if_list, wrpcap, conf
from scapy.packet import Raw
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from filters import make_predicate

PROTO_COLORS = {
    "TCP": "tcp", "UDP": "udp", "DNS": "dns", "HTTP": "http",
    "ICMP": "icmp", "ARP": "arp", "TLS": "tls", "IPv6": "ipv6",
    "DHCP": "dhcp", "NTP": "ntp", "SSH": "ssh", "FTP": "ftp",
    "SMTP": "smtp", "SNMP": "snmp", "MDNS": "mdns", "QUIC": "quic",
    "OTHER": "other",
}


_PORT_PROTO = {
    (20, "TCP"): "FTP", (21, "TCP"): "FTP",
    (22, "TCP"): "SSH",
    (23, "TCP"): "TELNET",
    (25, "TCP"): "SMTP", (587, "TCP"): "SMTP",
    (53, "UDP"): "DNS", (53, "TCP"): "DNS",
    (67, "UDP"): "DHCP", (68, "UDP"): "DHCP",
    (69, "UDP"): "TFTP",
    (80, "TCP"): "HTTP", (8080, "TCP"): "HTTP",
    (110, "TCP"): "POP3",
    (123, "UDP"): "NTP",
    (143, "TCP"): "IMAP",
    (161, "UDP"): "SNMP", (162, "UDP"): "SNMP",
    (443, "TCP"): "TLS",
    (445, "TCP"): "SMB",
    (5353, "UDP"): "MDNS",
}

_TLS_HANDSHAKE_TYPES = {
    1: "Client Hello", 2: "Server Hello", 11: "Certificate",
    12: "Server Key Exchange", 14: "Server Hello Done",
    16: "Client Key Exchange", 20: "Finished",
}


def _friendly_ifaces():
    """Return list of {id, name} for the interface dropdown."""
    ifaces = []
    raw_ifaces = get_if_list()
    pretty = {}
    if HAS_PSUTIL:
        try:
            stats = psutil.net_if_addrs()
            pretty = {k: k for k in stats.keys()}
        except Exception:
            pretty = {}
    for i in raw_ifaces:
        ifaces.append({"id": i, "name": pretty.get(i, i)})
    return ifaces


def _parse_tls_client_hello_sni(payload):
    """Best-effort extraction of the SNI extension from a raw TLS
    ClientHello, without pulling in scapy's heavyweight TLS stack.
    Returns the hostname string, or None."""
    try:
        if len(payload) < 6 or payload[0] != 0x16:  
            return None
        
        hs = payload[5:]
        if len(hs) < 4 or hs[0] != 0x01: 
            return None
        pos = 4 + 2 + 32  
        if pos >= len(hs):
            return None
        sess_len = hs[pos]
        pos += 1 + sess_len
        if pos + 2 > len(hs):
            return None
        cs_len = int.from_bytes(hs[pos:pos + 2], "big")
        pos += 2 + cs_len
        if pos >= len(hs):
            return None
        comp_len = hs[pos]
        pos += 1 + comp_len
        if pos + 2 > len(hs):
            return None
        ext_total_len = int.from_bytes(hs[pos:pos + 2], "big")
        pos += 2
        end = pos + ext_total_len
        while pos + 4 <= min(end, len(hs)):
            ext_type = int.from_bytes(hs[pos:pos + 2], "big")
            ext_len = int.from_bytes(hs[pos + 2:pos + 4], "big")
            ext_body = hs[pos + 4:pos + 4 + ext_len]
            if ext_type == 0x00 and len(ext_body) >= 5:  
                name_len = int.from_bytes(ext_body[3:5], "big")
                name = ext_body[5:5 + name_len]
                return name.decode("ascii", errors="replace")
            pos += 4 + ext_len
    except Exception:
        return None
    return None


def _tls_record_type(payload):
    if len(payload) < 6 or payload[0] != 0x16:
        return None
    hs_type = payload[5]
    return _TLS_HANDSHAKE_TYPES.get(hs_type)


def _parse_http(payload):
    """Return dict with method/path/host or status line info for a plaintext
    HTTP request/response, else None."""
    try:
        text = payload[:2048].decode("latin-1", errors="replace")
    except Exception:
        return None
    first_line, _, rest = text.partition("\r\n")
    parts = first_line.split(" ")
    if len(parts) >= 3 and parts[0] in (
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"
    ):
        host = None
        for line in rest.split("\r\n"):
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break
        return {"kind": "request", "method": parts[0], "path": parts[1], "host": host}
    if first_line.startswith("HTTP/"):
        status = parts[1] if len(parts) >= 2 else None
        return {"kind": "response", "status": status}
    return None


def _dns_info(pkt):
    try:
        dns = pkt[DNS]
        is_response = dns.qr == 1
        qname = qtype = None
        qd = dns.qd
        
        if qd:
            first = qd[0] if isinstance(qd, list) else qd
            qname = first.qname.decode(errors="replace").rstrip(".")
            qtype = first.qtype
        return {"is_response": is_response, "qname": qname, "qtype": qtype,
                "ancount": dns.ancount}
    except Exception:
        return {}


def _highest_layer_name(pkt, extra):
    """Determine the protocol label shown in the packet list, and populate
    `extra` with any dissected metadata (http/dns/tls fields)."""
    if pkt.haslayer(DNS):
        info = _dns_info(pkt)
        extra["dns_qname"] = info.get("qname")
        extra["dns_qtype"] = info.get("qtype")
        return "DNS"

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        sport, dport = tcp.sport, tcp.dport
        raw = bytes(pkt[Raw]) if pkt.haslayer(Raw) else b""

        if raw and (sport in (80, 8080) or dport in (80, 8080)):
            http = _parse_http(raw)
            if http:
                if http["kind"] == "request":
                    extra["http_method"] = http["method"]
                    extra["http_path"] = http["path"]
                    extra["http_host"] = http["host"]
                else:
                    extra["http_status"] = http["status"]
                return "HTTP"

        if raw and (sport == 443 or dport == 443):
            sni = _parse_tls_client_hello_sni(raw)
            if sni:
                extra["tls_sni"] = sni
            hs_name = _tls_record_type(raw)
            if hs_name:
                extra["tls_handshake"] = hs_name
            return "TLS"

        proto = _PORT_PROTO.get((sport, "TCP")) or _PORT_PROTO.get((dport, "TCP"))
        if proto:
            return proto
        return "TCP"

    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        sport, dport = udp.sport, udp.dport
        proto = _PORT_PROTO.get((sport, "UDP")) or _PORT_PROTO.get((dport, "UDP"))
        if proto:
            return proto
        
        if (sport == 443 or dport == 443) and pkt.haslayer(Raw):
            raw = bytes(pkt[Raw])
            if raw and (raw[0] & 0x80):
                return "QUIC"
        return "UDP"

    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(IPv6):
        return "IPv6"
    if pkt.haslayer(IP):
        return "IP"
    return pkt.lastlayer().name.upper() if pkt.lastlayer() else "OTHER"


def _build_info_string(pkt, proto, extra, fallback_summary):
    """Craft a richer, Wireshark-flavoured Info column instead of scapy's
    raw repr summary, when we have dissected metadata for it."""
    if proto == "DNS":
        qname = extra.get("dns_qname")
        if qname:
            try:
                is_resp = pkt[DNS].qr == 1
            except Exception:
                is_resp = False
            kind = "response" if is_resp else "query"
            return f"Standard {kind} {qname}"
    if proto == "HTTP":
        if extra.get("http_method"):
            host = f" Host: {extra['http_host']}" if extra.get("http_host") else ""
            return f"{extra['http_method']} {extra['http_path']} HTTP/1.1{host}"
        if extra.get("http_status"):
            return f"HTTP/1.1 {extra['http_status']}"
    if proto == "TLS":
        hs = extra.get("tls_handshake")
        sni = extra.get("tls_sni")
        if hs:
            return f"{hs}" + (f" (SNI={sni})" if sni else "")
    return fallback_summary


def _layer_tree(pkt):
    """Walk scapy layers -> nested list of {layer, fields:[...]}."""
    layers = []
    cur = pkt
    while cur is not None:
        try:
            fields = []
            for fname, fval in cur.fields.items():
                try:
                    fields.append({"name": fname, "value": str(fval)})
                except Exception:
                    continue
            layers.append({"layer": cur.__class__.__name__, "fields": fields})
        except Exception:
            pass
        cur = cur.payload if hasattr(cur, "payload") and cur.payload else None
        if cur is not None and cur.__class__.__name__ == "NoPayload":
            break
    return layers


def _layer_chain_names(pkt):
    names = []
    cur = pkt
    while cur is not None:
        cls = cur.__class__.__name__
        if cls == "NoPayload":
            break
        names.append(cls)
        cur = cur.payload if hasattr(cur, "payload") and cur.payload else None
    return names


def _hexdump(raw_bytes):
    lines = []
    for i in range(0, len(raw_bytes), 16):
        chunk = raw_bytes[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append({
            "offset": f"{i:04x}",
            "hex": hex_part,
            "ascii": ascii_part,
        })
    return lines


class CaptureEngine:
    def __init__(self, buffer_size=8000):
        self.buffer_size = buffer_size
        self.packets = deque(maxlen=buffer_size)
        self.raw_packets = deque(maxlen=buffer_size)
        self.lock = threading.Lock()
        self._thread = None
        self._stop_flag = threading.Event()
        self._counter = 0
        self._start_time = None
        self.running = False
        self.interface = None
        self.bpf_filter = ""
        self.on_packet = None
        self.stats = {"total": 0, "bytes": 0, "by_proto": {}}

    def list_interfaces(self):
        return _friendly_ifaces()

    @staticmethod
    def validate_filter(bpf_filter):
        """Try to compile the BPF filter up-front so bad syntax is reported
        synchronously instead of only surfacing after the capture thread
        has already started. Returns (ok, message).

        This only rejects genuine filter-syntax errors. Environment
        problems (no libpcap/Npcap installed, no capture device available)
        are NOT syntax errors - compile_filter() can raise for those too,
        and we must not misreport "libpcap missing" as "bad filter syntax".
        Those cases are left for the actual capture start to surface, since
        that failure message is accurate and actionable ("run as root",
        "install Npcap"), whereas ours would not be.
        """
        if not bpf_filter:
            return True, ""
        try:
            from scapy.arch import compile_filter  
        except ImportError:
            return True, ""  
        try:
            compile_filter(bpf_filter)
            return True, ""
        except Exception as e:
            msg = str(e).lower()
            if "libpcap" in msg or "npcap" in msg or "no such device" in msg:
                
                return True, ""
            return False, f"Invalid capture filter: {e}"

    def start(self, interface=None, bpf_filter="", on_packet=None):
        if self.running:
            return False, "Capture already running / ضبط از قبل در حال اجراست"
        bpf_filter = bpf_filter or ""
        ok, msg = self.validate_filter(bpf_filter)
        if not ok:
            return False, msg
        self.interface = interface or conf.iface
        self.bpf_filter = bpf_filter
        self.on_packet = on_packet
        self._stop_flag.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._start_time = time.time()
        self.running = True
        self._thread.start()
        return True, "started"

    def stop(self):
        if not self.running:
            return False, "Capture not running / ضبط در حال اجرا نیست"
        self._stop_flag.set()
        self.running = False
        return True, "stopped"

    def clear(self):
        with self.lock:
            self.packets.clear()
            self.raw_packets.clear()
            self._counter = 0
            self.stats = {"total": 0, "bytes": 0, "by_proto": {}}

    def export_pcap(self, path):
        with self.lock:
            pkts = list(self.raw_packets)
        if not pkts:
            return False
        wrpcap(path, pkts)
        return True

    def get_packets(self, offset=0, limit=200, proto=None, search=None, display_filter=None):
        with self.lock:
            items = list(self.packets)
        if proto:
            items = [p for p in items if p["protocol"] == proto]
        if display_filter:
            pred = make_predicate(display_filter)
            items = [p for p in items if pred(p)]
        elif search:
            s = search.lower()
            items = [p for p in items if s in p["info"].lower()
                     or s in p["src"].lower() or s in p["dst"].lower()]
        total = len(items)
        return items[offset:offset + limit], total

    def get_packet_detail(self, pkt_id):
        with self.lock:
            raw = None
            for p in self.raw_packets:
                if getattr(p, "pcap_meta_id", None) == pkt_id:
                    raw = p
                    break
        if raw is None:
            return None
        return {
            "id": pkt_id,
            "layers": _layer_tree(raw),
            "hex": _hexdump(bytes(raw)),
            "summary": raw.summary(),
        }

    def get_protocol_hierarchy(self):
        """Nested counts of layer chains, e.g. Ether/IP/TCP/HTTP, the same
        idea as Wireshark's Statistics -> Protocol Hierarchy."""
        root = OrderedDict()
        with self.lock:
            pkts = list(self.raw_packets)
        for pkt in pkts:
            chain = _layer_chain_names(pkt)
            node = root
            for name in chain:
                if name not in node:
                    node[name] = {"count": 0, "bytes": 0, "children": OrderedDict()}
                node[name]["count"] += 1
                node[name]["bytes"] += len(pkt)
                node = node[name]["children"]

        def serialize(tree):
            out = []
            for name, data in tree.items():
                out.append({
                    "name": name,
                    "count": data["count"],
                    "bytes": data["bytes"],
                    "children": serialize(data["children"]),
                })
            return out

        return serialize(root)

    def get_conversations(self):
        """Aggregate traffic by unordered (endpoint A, endpoint B) pair -
        Wireshark calls this Statistics -> Conversations."""
        convs = {}
        with self.lock:
            items = list(self.packets)
        for p in items:
            src, dst = p.get("src") or "?", p.get("dst") or "?"
            key = tuple(sorted((src, dst)))
            c = convs.setdefault(key, {
                "a": key[0], "b": key[1], "packets": 0, "bytes": 0, "protocols": set(),
            })
            c["packets"] += 1
            c["bytes"] += p.get("length", 0)
            c["protocols"].add(p.get("protocol", "OTHER"))
        out = []
        for c in convs.values():
            out.append({
                "a": c["a"], "b": c["b"], "packets": c["packets"], "bytes": c["bytes"],
                "protocols": sorted(c["protocols"]),
            })
        out.sort(key=lambda c: c["bytes"], reverse=True)
        return out

    def get_tcp_stream(self, pkt_id):
        """Reassemble the plaintext payload of the TCP stream that
        `pkt_id` belongs to - Wireshark's "Follow TCP Stream"."""
        with self.lock:
            pkts = list(self.raw_packets)
        target = next((p for p in pkts if getattr(p, "pcap_meta_id", None) == pkt_id), None)
        if target is None or not target.haslayer(TCP) or not target.haslayer(IP):
            return None

        t_ip, t_tcp = target[IP], target[TCP]
        client_tuple = (t_ip.src, t_tcp.sport, t_ip.dst, t_tcp.dport)

        def tuple_of(pkt):
            ip, tcp = pkt[IP], pkt[TCP]
            return (ip.src, tcp.sport, ip.dst, tcp.dport)

        blocks = []
        for pkt in pkts:
            if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
                continue
            tup = tuple_of(pkt)
            if tup == client_tuple:
                direction = "client"
            elif tup == (client_tuple[2], client_tuple[3], client_tuple[0], client_tuple[1]):
                direction = "server"
            else:
                continue
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw])
                if payload:
                    text = payload.decode("utf-8", errors="replace")
                    blocks.append({"direction": direction, "text": text, "bytes": len(payload)})

        if not blocks:
            return {"blocks": [], "client": f"{client_tuple[0]}:{client_tuple[1]}",
                    "server": f"{client_tuple[2]}:{client_tuple[3]}", "empty": True}

        return {
            "blocks": blocks,
            "client": f"{client_tuple[0]}:{client_tuple[1]}",
            "server": f"{client_tuple[2]}:{client_tuple[3]}",
            "empty": False,
        }

    def _run(self):
        try:
            while not self._stop_flag.is_set():
                sniff(
                    iface=self.interface,
                    filter=self.bpf_filter or None,
                    prn=self._handle_packet,
                    store=False,
                    stop_filter=lambda p: self._stop_flag.is_set(),
                    timeout=1,
                )
        except PermissionError:
            self.running = False
            if self.on_packet:
                self.on_packet({"error": "permission",
                                 "message": "Run as root/Administrator to capture packets."})
        except Exception as e:
            self.running = False
            if self.on_packet:
                self.on_packet({"error": "capture", "message": str(e)})

    def _handle_packet(self, pkt):
        try:
            with self.lock:
                self._counter += 1
                pid = self._counter
            pkt.pcap_meta_id = pid

            extra = {}
            proto = _highest_layer_name(pkt, extra)
            length = len(pkt)

           
            layer_set = set()
            if pkt.haslayer(Ether):
                layer_set.add("eth")
            if pkt.haslayer(ARP):
                layer_set.add("arp")
            if pkt.haslayer(IP):
                layer_set.add("ip")
            if pkt.haslayer(IPv6):
                layer_set.add("ipv6")
            if pkt.haslayer(TCP):
                layer_set.add("tcp")
            if pkt.haslayer(UDP):
                layer_set.add("udp")
            if pkt.haslayer(ICMP):
                layer_set.add("icmp")
            if pkt.haslayer(DNS):
                layer_set.add("dns")
            layer_set.add(proto.lower())

            src = dst = ""
            sport = dport = None
            if pkt.haslayer(IP):
                src, dst = pkt[IP].src, pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
            elif pkt.haslayer(ARP):
                src, dst = pkt[ARP].psrc, pkt[ARP].pdst
            elif pkt.haslayer(Ether):
                src, dst = pkt[Ether].src, pkt[Ether].dst

            if pkt.haslayer(TCP):
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
            elif pkt.haslayer(UDP):
                sport, dport = pkt[UDP].sport, pkt[UDP].dport

            info = _build_info_string(pkt, proto, extra, pkt.summary())

            entry = {
                "id": pid,
                "time": round(time.time() - self._start_time, 6) if self._start_time else 0,
                "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "src": src,
                "dst": dst,
                "sport": sport,
                "dport": dport,
                "protocol": proto,
                "css_class": PROTO_COLORS.get(proto, "other"),
                "length": length,
                "info": info,
                "layers": sorted(layer_set),
            }
            entry.update(extra)

            with self.lock:
                self.packets.append(entry)
                self.raw_packets.append(pkt)
                self.stats["total"] += 1
                self.stats["bytes"] += length
                self.stats["by_proto"][proto] = self.stats["by_proto"].get(proto, 0) + 1

            if self.on_packet:
                self.on_packet(entry)
        except Exception:
            pass


def platform_hint():
    return {
        "system": platform.system(),
        "needs_admin": platform.system() == "Windows",
        "needs_root": platform.system() != "Windows",
    }
