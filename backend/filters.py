import re

_TOKEN_SPEC = [
    ("WS", r"\s+"),
    ("LPAREN", r"\("),
    ("RPAREN", r"\)"),
    ("OP", r"==|!=|>=|<=|>|<"),
    ("STRING", r'"[^"]*"|\'[^\']*\''),
    ("AND", r"\b(and|&&)\b"),
    ("OR", r"\b(or|\|\|)\b"),
    ("NOT", r"\b(not)\b|!"),
    ("CONTAINS", r"\bcontains\b"),
    ("MATCHES", r"\bmatches\b"),
    ("FIELD", r"[A-Za-z_][A-Za-z0-9_.\-]*"),
    
    ("NUMBER", r"\d+(\.\d+){0,3}"),
]
_TOKEN_RE = re.compile(
    "|".join(f"(?P<{name}>{pat})" for name, pat in _TOKEN_SPEC), re.IGNORECASE
)


class Token:
    __slots__ = ("kind", "value")

    def __init__(self, kind, value):
        self.kind = kind
        self.value = value

    def __repr__(self):
        return f"Token({self.kind!r}, {self.value!r})"


class FilterSyntaxError(Exception):
    pass


def tokenize(expr):
    tokens = []
    pos = 0
    while pos < len(expr):
        m = _TOKEN_RE.match(expr, pos)
        if not m:
            raise FilterSyntaxError(f"Unexpected character at position {pos}")
        kind = m.lastgroup
        value = m.group()
        pos = m.end()
        if kind == "WS":
            continue
        tokens.append(Token(kind, value))
    return tokens




class Node:
    def evaluate(self, entry):
        raise NotImplementedError


class BinOp(Node):
    def __init__(self, op, left, right):
        self.op, self.left, self.right = op, left, right

    def evaluate(self, entry):
        if self.op == "and":
            return self.left.evaluate(entry) and self.right.evaluate(entry)
        if self.op == "or":
            return self.left.evaluate(entry) or self.right.evaluate(entry)
        raise FilterSyntaxError(f"Unknown boolean op {self.op}")


class NotOp(Node):
    def __init__(self, child):
        self.child = child

    def evaluate(self, entry):
        return not self.child.evaluate(entry)


class Comparison(Node):
    def __init__(self, field, op, literal):
        self.field, self.op, self.literal = field, op, literal

    def evaluate(self, entry):
        values = get_field_values(entry, self.field)
        if values is None:
            return False
        lit = self.literal
        for v in values:
            if v is None:
                continue
            if self.op == "contains":
                if lit.lower() in str(v).lower():
                    return True
                continue
            if self.op == "matches":
                try:
                    if re.search(lit, str(v), re.IGNORECASE):
                        return True
                except re.error:
                    continue
                continue
            
            ok = _compare(v, self.op, lit)
            if ok:
                return True
        return False


class BareToken(Node):
    """A single bare word/number with no operator: protocol name, IP, or
    plain substring (Wireshark: `dns`, `192.168.1.1`, `arp`)."""

    def __init__(self, text):
        self.text = text

    def evaluate(self, entry):
        text = self.text.lower()
        proto = str(entry.get("protocol", "")).lower()
        if text == proto:
            return True
        
        layers = entry.get("layers")
        if layers and text in layers:
            return True
       
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", text) or ":" in text:
            if text == str(entry.get("src", "")).lower():
                return True
            if text == str(entry.get("dst", "")).lower():
                return True
        
        haystack = " ".join(
            str(entry.get(k, "")) for k in
            ("info", "src", "dst", "sport", "dport", "protocol",
             "http_host", "http_path", "dns_qname", "tls_sni")
        ).lower()
        return text in haystack


def _compare(value, op, literal):
    
    try:
        lv = float(value)
        rv = float(literal)
        numeric = True
    except (TypeError, ValueError):
        numeric = False
    if numeric:
        if op == "==":
            return lv == rv
        if op == "!=":
            return lv != rv
        if op == ">":
            return lv > rv
        if op == "<":
            return lv < rv
        if op == ">=":
            return lv >= rv
        if op == "<=":
            return lv <= rv
    sv, sl = str(value).lower(), str(literal).lower()
    if op == "==":
        return sv == sl
    if op == "!=":
        return sv != sl
    return False


_FIELD_MAP = {
    "ip.addr": ("src", "dst"),
    "ip.src": ("src",),
    "ip.dst": ("dst",),
    "ipv6.addr": ("src", "dst"),
    "ipv6.src": ("src",),
    "ipv6.dst": ("dst",),
    "eth.addr": ("src", "dst"),
    "port": ("sport", "dport"),
    "tcp.port": ("sport", "dport"),
    "udp.port": ("sport", "dport"),
    "tcp.srcport": ("sport",),
    "tcp.dstport": ("dport",),
    "udp.srcport": ("sport",),
    "udp.dstport": ("dport",),
    "frame.len": ("length",),
    "len": ("length",),
    "http.host": ("http_host",),
    "http.uri": ("http_path",),
    "http.path": ("http_path",),
    "http.method": ("http_method",),
    "http.status": ("http_status",),
    "dns.qry.name": ("dns_qname",),
    "dns.qry.type": ("dns_qtype",),
    "tls.sni": ("tls_sni",),
    "tls.handshake.extensions_server_name": ("tls_sni",),
    "info": ("info",),
    "protocol": ("protocol",),
    "frame.protocols": ("protocol",),
}


def get_field_values(entry, field):
    field = field.lower()
    keys = _FIELD_MAP.get(field)
    if keys is None:
        return None
    return [entry.get(k) for k in keys]




class Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.i = 0

    def peek(self):
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def advance(self):
        tok = self.peek()
        self.i += 1
        return tok

    def expect_end(self):
        if self.peek() is not None:
            raise FilterSyntaxError(f"Unexpected trailing token {self.peek()}")

    def parse(self):
        node = self.parse_or()
        self.expect_end()
        return node

    def parse_or(self):
        node = self.parse_and()
        while self.peek() and self.peek().kind == "OR":
            self.advance()
            rhs = self.parse_and()
            node = BinOp("or", node, rhs)
        return node

    def parse_and(self):
        node = self.parse_not()
        while self.peek() and self.peek().kind == "AND":
            self.advance()
            rhs = self.parse_not()
            node = BinOp("and", node, rhs)
        return node

    def parse_not(self):
        if self.peek() and self.peek().kind == "NOT":
            self.advance()
            return NotOp(self.parse_not())
        return self.parse_atom()

    def parse_atom(self):
        tok = self.peek()
        if tok is None:
            raise FilterSyntaxError("Unexpected end of expression")
        if tok.kind == "LPAREN":
            self.advance()
            node = self.parse_or()
            if not self.peek() or self.peek().kind != "RPAREN":
                raise FilterSyntaxError("Missing closing parenthesis")
            self.advance()
            return node
        if tok.kind in ("FIELD", "NUMBER"):
            
            nxt = self.tokens[self.i + 1] if self.i + 1 < len(self.tokens) else None
            if nxt is not None and nxt.kind in ("OP", "CONTAINS", "MATCHES") \
                    and tok.value.lower() in _FIELD_MAP:
                field_tok = self.advance()
                op_tok = self.advance()
                lit_tok = self.advance()
                if lit_tok is None or lit_tok.kind not in ("STRING", "NUMBER", "FIELD"):
                    raise FilterSyntaxError("Expected a value after operator")
                literal = lit_tok.value
                if lit_tok.kind == "STRING":
                    literal = literal[1:-1]
                op = {"CONTAINS": "contains", "MATCHES": "matches"}.get(
                    op_tok.kind, op_tok.value
                )
                return Comparison(field_tok.value, op, literal)
            
            self.advance()
            return BareToken(tok.value)
        raise FilterSyntaxError(f"Unexpected token {tok}")


def compile_filter(expr):
    """Parse `expr` into an evaluatable Node. Raises FilterSyntaxError."""
    tokens = tokenize(expr)
    if not tokens:
        raise FilterSyntaxError("Empty filter")
    return Parser(tokens).parse()


def make_predicate(expr):
    """
    Returns a callable(entry) -> bool for the given filter expression.
    Never raises: on a syntax error it silently falls back to a plain
    case-insensitive substring match (same behaviour the old search box had).
    """
    expr = (expr or "").strip()
    if not expr:
        return lambda entry: True
    try:
        node = compile_filter(expr)

        def predicate(entry, _node=node):
            try:
                return bool(_node.evaluate(entry))
            except Exception:
                return False

        return predicate
    except FilterSyntaxError:
        needle = expr.lower()

        def fallback(entry, _needle=needle):
            haystack = " ".join(
                str(entry.get(k, "")) for k in
                ("info", "src", "dst", "sport", "dport", "protocol",
                 "http_host", "http_path", "dns_qname", "tls_sni")
            ).lower()
            return _needle in haystack

        return fallback
