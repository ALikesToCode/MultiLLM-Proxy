"""Bounded JSON-like parser. Tokens are interpreted only outside quoted strings."""

import json
import math
import re

MAX_BYTES = 64 * 1024
MAX_DEPTH = 32
MAX_NODES = 4096
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_WORD = re.compile(r"[A-Za-z_$][A-Za-z0-9_$-]*")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate property")
        result[key] = value
    return result


def finite_number(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Non-finite number")
    return number


def reject_constant(value):
    raise ValueError("Non-finite number")


def check_bounds(value):
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_NODES:
            raise ValueError("Arguments exceed complexity limit")
        children = item.values() if isinstance(item, dict) else item if isinstance(item, list) else ()
        if len(children) + len(pending) + count > MAX_NODES:
            raise ValueError("Arguments exceed complexity limit")
        if isinstance(item, str) and len(item.encode("utf-8")) > MAX_BYTES:
            raise ValueError("Arguments exceed size limit")
        pending.extend((child, depth + 1) for child in children)


def strict_loads(text):
    if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_BYTES:
        raise ValueError("Arguments exceed size limit")
    value = json.loads(text, object_pairs_hook=unique_object,
                       parse_constant=reject_constant, parse_float=finite_number)
    check_bounds(value)
    return value


class Parser:
    def __init__(self, text):
        if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_BYTES:
            raise ValueError("Arguments exceed size limit")
        self.text, self.pos, self.nodes = text, 0, 0

    def space(self):
        while self.pos < len(self.text):
            if self.text[self.pos].isspace():
                self.pos += 1
            elif self.text.startswith("//", self.pos):
                end = self.text.find("\n", self.pos)
                self.pos = len(self.text) if end < 0 else end + 1
            elif self.text.startswith("/*", self.pos):
                end = self.text.find("*/", self.pos + 2)
                if end < 0:
                    raise ValueError("Unclosed comment")
                self.pos = end + 2
            else:
                break

    def take(self, char):
        self.space()
        if self.text.startswith(char, self.pos):
            self.pos += len(char)
            return True
        return False

    def string(self):
        quote = self.text[self.pos]
        self.pos += 1
        output = []
        while self.pos < len(self.text):
            char = self.text[self.pos]
            self.pos += 1
            if char == quote:
                return "".join(output)
            if char != "\\":
                output.append(char)
                continue
            if self.pos >= len(self.text):
                break
            char = self.text[self.pos]
            self.pos += 1
            escapes = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f",
                       "\\": "\\", "/": "/", '"': '"', "'": "'"}
            if char in escapes:
                output.append(escapes[char])
            elif char == "u" and self.pos + 4 <= len(self.text):
                output.append(json.loads('"\\u' + self.text[self.pos:self.pos + 4] + '"'))
                self.pos += 4
            else:
                raise ValueError("Invalid escape")
        raise ValueError("Unclosed string")

    def value(self, depth=0):
        self.nodes += 1
        if depth > MAX_DEPTH or self.nodes > MAX_NODES:
            raise ValueError("Arguments exceed complexity limit")
        self.space()
        if self.pos >= len(self.text):
            raise ValueError("Missing value")
        char = self.text[self.pos]
        if char in "\"'":
            return self.string()
        if char in "{[":
            return self.container(char, depth)
        match = _NUMBER.match(self.text, self.pos)
        if match:
            self.pos = match.end()
            return strict_loads(match.group())
        for token, value in (("true", True), ("false", False), ("null", None),
                             ("True", True), ("False", False), ("None", None)):
            if self.text.startswith(token, self.pos):
                self.pos += len(token)
                return value
        raise ValueError("Invalid token")

    def container(self, char, depth):
        self.pos += 1
        end = "}" if char == "{" else "]"
        output = {} if char == "{" else []
        if self.take(end):
            return output
        while True:
            if char == "{":
                self.space()
                if self.pos < len(self.text) and self.text[self.pos] in "\"'":
                    key = self.string()
                else:
                    match = _WORD.match(self.text, self.pos)
                    if not match:
                        raise ValueError("Missing key")
                    key, self.pos = match.group(), match.end()
                if key in output or not self.take(":"):
                    raise ValueError("Invalid or duplicate key")
                output[key] = self.value(depth + 1)
            else:
                output.append(self.value(depth + 1))
            if self.take(end):
                return output
            if not self.take(","):
                raise ValueError("Missing separator")
            if self.take(end):
                return output


def tolerant_loads(text):
    parser = Parser(text)
    value = parser.value()
    parser.space()
    if parser.pos != len(text):
        raise ValueError("Extra input")
    return value


def single_object(text):
    """Only unwrap a single balanced object, never choose between candidate calls."""
    start = text.find("{")
    if start < 0:
        return text
    parser = Parser(text[start:])
    value = parser.value()
    if not isinstance(value, dict) or "{" in text[start + parser.pos:]:
        raise ValueError("Not a single object")
    return text[start:start + parser.pos]
