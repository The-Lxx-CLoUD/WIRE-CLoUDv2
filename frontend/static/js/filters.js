(() => {
  "use strict";

  const FIELD_MAP = {
    "ip.addr": ["src", "dst"],
    "ip.src": ["src"],
    "ip.dst": ["dst"],
    "ipv6.addr": ["src", "dst"],
    "ipv6.src": ["src"],
    "ipv6.dst": ["dst"],
    "eth.addr": ["src", "dst"],
    "port": ["sport", "dport"],
    "tcp.port": ["sport", "dport"],
    "udp.port": ["sport", "dport"],
    "tcp.srcport": ["sport"],
    "tcp.dstport": ["dport"],
    "udp.srcport": ["sport"],
    "udp.dstport": ["dport"],
    "frame.len": ["length"],
    "len": ["length"],
    "http.host": ["http_host"],
    "http.uri": ["http_path"],
    "http.path": ["http_path"],
    "http.method": ["http_method"],
    "http.status": ["http_status"],
    "dns.qry.name": ["dns_qname"],
    "dns.qry.type": ["dns_qtype"],
    "tls.sni": ["tls_sni"],
    "info": ["info"],
    "protocol": ["protocol"],
  };

  const TOKEN_RE = new RegExp(
    "(\\()|(\\))|(==|!=|>=|<=|>|<)|" +
      '("[^"]*"|\'[^\']*\')|' +
      "\\b(and|&&)\\b|\\b(or|\\|\\|)\\b|\\b(not)\\b|!|" +
      "\\b(contains)\\b|\\b(matches)\\b|" +
      "([A-Za-z_][A-Za-z0-9_.\\-]*)|" +
      "(\\d+(?:\\.\\d+){0,3})",
    "gi"
  );

  function tokenize(expr) {
    const tokens = [];
    let m;
    let lastIndex = 0;
    TOKEN_RE.lastIndex = 0;
    while ((m = TOKEN_RE.exec(expr))) {
      if (m.index !== lastIndex) {
       
        const gap = expr.slice(lastIndex, m.index);
        if (gap.trim() !== "") throw new Error("bad token near " + gap);
      }
      lastIndex = TOKEN_RE.lastIndex;
      if (m[1]) tokens.push({ kind: "LPAREN", value: "(" });
      else if (m[2]) tokens.push({ kind: "RPAREN", value: ")" });
      else if (m[3]) tokens.push({ kind: "OP", value: m[3] });
      else if (m[4]) tokens.push({ kind: "STRING", value: m[4].slice(1, -1) });
      else if (m[5]) tokens.push({ kind: "AND", value: "and" });
      else if (m[6]) tokens.push({ kind: "OR", value: "or" });
      else if (m[7]) tokens.push({ kind: "NOT", value: "not" });
      else if (m[0] === "!") tokens.push({ kind: "NOT", value: "!" });
      else if (m[8]) tokens.push({ kind: "CONTAINS", value: "contains" });
      else if (m[9]) tokens.push({ kind: "MATCHES", value: "matches" });
      else if (m[10]) tokens.push({ kind: "FIELD", value: m[10] });
      else if (m[11]) tokens.push({ kind: "NUMBER", value: m[11] });
    }
    if (lastIndex !== expr.length) {
      const gap = expr.slice(lastIndex);
      if (gap.trim() !== "") throw new Error("bad trailing token " + gap);
    }
    return tokens;
  }

  function parse(tokens) {
    let i = 0;
    const peek = () => tokens[i];
    const advance = () => tokens[i++];

    function parseOr() {
      let node = parseAnd();
      while (peek() && peek().kind === "OR") {
        advance();
        node = { op: "or", left: node, right: parseAnd() };
      }
      return node;
    }
    function parseAnd() {
      let node = parseNot();
      while (peek() && peek().kind === "AND") {
        advance();
        node = { op: "and", left: node, right: parseNot() };
      }
      return node;
    }
    function parseNot() {
      if (peek() && peek().kind === "NOT") {
        advance();
        return { op: "not", child: parseNot() };
      }
      return parseAtom();
    }
    function parseAtom() {
      const tok = peek();
      if (!tok) throw new Error("unexpected end");
      if (tok.kind === "LPAREN") {
        advance();
        const node = parseOr();
        if (!peek() || peek().kind !== "RPAREN") throw new Error("missing )");
        advance();
        return node;
      }
      if (tok.kind === "FIELD" || tok.kind === "NUMBER") {
        const nxt = tokens[i + 1];
        if (
          nxt &&
          (nxt.kind === "OP" || nxt.kind === "CONTAINS" || nxt.kind === "MATCHES") &&
          FIELD_MAP[tok.value.toLowerCase()]
        ) {
          const field = advance().value;
          const opTok = advance();
          const litTok = advance();
          if (!litTok || !["STRING", "NUMBER", "FIELD"].includes(litTok.kind)) {
            throw new Error("expected value after operator");
          }
          const op =
            opTok.kind === "CONTAINS" ? "contains" : opTok.kind === "MATCHES" ? "matches" : opTok.value;
          return { cmp: true, field, op, literal: litTok.value };
        }
        advance();
        return { bare: tok.value };
      }
      throw new Error("unexpected token " + JSON.stringify(tok));
    }

    const node = parseOr();
    if (peek()) throw new Error("trailing tokens");
    return node;
  }

  function compare(value, op, literal) {
    const lv = parseFloat(value);
    const rv = parseFloat(literal);
    const numeric = !Number.isNaN(lv) && !Number.isNaN(rv) && /^-?\d+(\.\d+)?$/.test(String(value)) && /^-?\d+(\.\d+)?$/.test(String(literal));
    if (numeric) {
      switch (op) {
        case "==": return lv === rv;
        case "!=": return lv !== rv;
        case ">": return lv > rv;
        case "<": return lv < rv;
        case ">=": return lv >= rv;
        case "<=": return lv <= rv;
      }
    }
    const sv = String(value ?? "").toLowerCase();
    const sl = String(literal ?? "").toLowerCase();
    if (op === "==") return sv === sl;
    if (op === "!=") return sv !== sl;
    return false;
  }

  function evaluate(node, pkt) {
    if (node.op === "and") return evaluate(node.left, pkt) && evaluate(node.right, pkt);
    if (node.op === "or") return evaluate(node.left, pkt) || evaluate(node.right, pkt);
    if (node.op === "not") return !evaluate(node.child, pkt);
    if (node.cmp) {
      const keys = FIELD_MAP[node.field.toLowerCase()];
      if (!keys) return false;
      for (const k of keys) {
        const v = pkt[k];
        if (v === undefined || v === null) continue;
        if (node.op === "contains") {
          if (String(node.literal).toLowerCase().length && String(v).toLowerCase().includes(String(node.literal).toLowerCase())) return true;
          continue;
        }
        if (node.op === "matches") {
          try {
            if (new RegExp(node.literal, "i").test(String(v))) return true;
          } catch (e) { /* bad regex, ignore */ }
          continue;
        }
        if (compare(v, node.op, node.literal)) return true;
      }
      return false;
    }
    if (node.bare !== undefined) {
      const text = String(node.bare).toLowerCase();
      const proto = String(pkt.protocol || "").toLowerCase();
      if (text === proto) return true;
      if (Array.isArray(pkt.layers) && pkt.layers.includes(text)) return true;
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(text) || text.includes(":")) {
        if (text === String(pkt.src || "").toLowerCase()) return true;
        if (text === String(pkt.dst || "").toLowerCase()) return true;
      }
      const haystack = [
        pkt.info, pkt.src, pkt.dst, pkt.sport, pkt.dport, pkt.protocol,
        pkt.http_host, pkt.http_path, pkt.dns_qname, pkt.tls_sni,
      ].join(" ").toLowerCase();
      return haystack.includes(text);
    }
    return false;
  }

  function substringFallback(expr, pkt) {
    const needle = expr.toLowerCase();
    const haystack = [
      pkt.info, pkt.src, pkt.dst, pkt.sport, pkt.dport, pkt.protocol,
      pkt.http_host, pkt.http_path, pkt.dns_qname, pkt.tls_sni,
    ].join(" ").toLowerCase();
    return haystack.includes(needle);
  }

  
  function makePredicate(expr) {
    const trimmed = (expr || "").trim();
    if (!trimmed) return () => true;
    try {
      const ast = parse(tokenize(trimmed));
      return (pkt) => {
        try {
          return !!evaluate(ast, pkt);
        } catch (e) {
          return false;
        }
      };
    } catch (e) {
      return (pkt) => substringFallback(trimmed, pkt);
    }
  }

  window.WireCloudFilters = { makePredicate };
})();
