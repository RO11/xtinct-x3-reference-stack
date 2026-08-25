#!/usr/bin/env python3
"""Behavioral, mutation, and source-hash gate for XTINCT's WebServer parser."""

from __future__ import annotations

import hashlib
import re
import sys
from dataclasses import dataclass
from pathlib import Path


PATCH_RELATIVE = Path("patches/arduino-webserver-bounded-Parsing.cpp")
EXPECTED_PATCH_BYTES = 40356
EXPECTED_PATCH_SHA256 = "d008565080114bf6044a0070952ef9cd63976c887ffd58df66f73b571ba7a20d"
REQUEST_LINE_BYTES = 1024
TARGET_BYTES = 768
HEADER_LINE_BYTES = 1024
HEADER_COUNT = 32
QUERY_BYTES = 4096
QUERY_ARGS = 32
PLAIN_BODY_BYTES = 64 * 1024
FORM_FIELD_BYTES = 4096
FORM_FIELD_WIRE_BYTES = 8192
FORM_RETAINED_BYTES = 8192
BOUNDARY_BYTES = 128
INT_MAX = (1 << 31) - 1
UPLOAD_CHUNK = 1436
KNOWN_METHODS = frozenset(
    b"DELETE GET HEAD POST PUT CONNECT OPTIONS TRACE COPY LOCK MKCOL MOVE PROPFIND "
    b"PROPPATCH SEARCH UNLOCK BIND REBIND UNBIND ACL REPORT MKACTIVITY CHECKOUT "
    b"MERGE M-SEARCH NOTIFY SUBSCRIBE UNSUBSCRIBE PATCH PURGE MKCALENDAR LINK UNLINK".split()
)
BODY_METHODS = frozenset((b"POST", b"PUT", b"PATCH", b"DELETE"))
HEADER_TOKEN_BYTES = frozenset(
    b"!#$%&'*+-.^_`|~"
    + bytes(range(ord("0"), ord("9") + 1))
    + bytes(range(ord("A"), ord("Z") + 1))
    + bytes(range(ord("a"), ord("z") + 1))
)


class ParserFixtureError(RuntimeError):
    """The reviewed parser or its executable boundary model failed a gate."""


class Rejected(ValueError):
    """The bounded parser model rejected malformed or faulted input."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ParserFixtureError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class FaultPlan:
    stage: str | None = None
    fired: bool = False

    def hit(self, stage: str) -> None:
        if self.stage == stage and not self.fired:
            self.fired = True
            raise Rejected(f"injected allocation failure: {stage}")


@dataclass(frozen=True)
class ParseResult:
    accepted: bool
    events: tuple[str, ...]
    reads: tuple[tuple[int, int], ...]
    post_args_present: bool = False
    post_args_len: int = 0


def read_line(
    data: bytes,
    offset: int,
    capacity: int,
    *,
    allow_tab: bool = False,
    limit: int | None = None,
) -> tuple[bytes, int]:
    """Byte-for-byte model of xtinctReadBoundedLine's pre-read budget."""
    absolute_limit = len(data) if limit is None else limit
    require(0 <= offset <= absolute_limit <= len(data), "line fixture budget is invalid")
    line = bytearray()
    while True:
        if offset >= absolute_limit:
            raise Rejected("line exceeded its declared byte budget")
        byte = data[offset]
        offset += 1
        if byte == 0x0D:
            if offset >= absolute_limit or data[offset] != 0x0A:
                raise Rejected("line did not use a complete CRLF terminator")
            offset += 1
            return bytes(line), offset
        if byte == 0 or byte == 0x7F or (byte < 0x20 and not (allow_tab and byte == 0x09)):
            raise Rejected("line contained a forbidden control byte")
        if len(line) >= capacity:
            raise Rejected("line exceeded its fixed capacity")
        line.append(byte)


def valid_header_name(name: bytes) -> bool:
    return bool(name) and all(byte in HEADER_TOKEN_BYTES for byte in name)


def valid_argument_data(data: bytes, maximum: int = QUERY_BYTES) -> bool:
    if len(data) > maximum:
        return False
    arguments = 0 if not data else 1
    index = 0
    while index < len(data):
        byte = data[index]
        if byte == 0 or byte == 0x7F or byte < 0x20:
            return False
        if byte == 0x26:  # &
            arguments += 1
            if arguments > QUERY_ARGS:
                return False
        if byte == 0x25:  # %
            if index + 2 >= len(data) or re.fullmatch(rb"[0-9A-Fa-f]{2}", data[index + 1:index + 3]) is None:
                return False
            decoded = int(data[index + 1:index + 3], 16)
            if decoded == 0 or decoded == 0x7F or decoded < 0x20:
                return False
            index += 2
        index += 1
    return arguments <= QUERY_ARGS


def url_decode(data: bytes, plan: FaultPlan, stage: str) -> bytes:
    plan.hit(stage)
    decoded = bytearray()
    index = 0
    while index < len(data):
        byte = data[index]
        index += 1
        if byte == 0x25:
            if index + 1 >= len(data) or re.fullmatch(rb"[0-9A-Fa-f]{2}", data[index:index + 2]) is None:
                raise Rejected("invalid percent escape")
            byte = int(data[index:index + 2], 16)
            index += 2
        elif byte == 0x2B:
            byte = 0x20
        if byte < 0x20 or byte == 0x7F:
            raise Rejected("decoded argument contained a forbidden control byte")
        decoded.append(byte)
    return bytes(decoded)


def parse_arguments(data: bytes, plan: FaultPlan) -> list[tuple[bytes, bytes]]:
    if not valid_argument_data(data):
        raise Rejected("query arguments are invalid")
    plan.hit("query_array")
    if not data:
        return []
    if len(data.split(b"&")) > QUERY_ARGS:
        raise Rejected("too many query arguments")
    parsed: list[tuple[bytes, bytes]] = []
    for segment in data.split(b"&"):
        if b"=" not in segment:
            continue
        key, value = segment.split(b"=", 1)
        parsed.append(
            (
                url_decode(key, plan, "query_key_decode"),
                url_decode(value, plan, "query_value_decode"),
            )
        )
    return parsed


def parse_content_length(value: bytes) -> int:
    if not value or re.fullmatch(rb"[0-9]+", value) is None:
        raise Rejected("Content-Length was not nonempty decimal")
    parsed = 0
    for byte in value:
        digit = byte - 0x30
        if parsed > (INT_MAX - digit) // 10:
            raise Rejected("Content-Length overflowed int")
        parsed = parsed * 10 + digit
    return parsed


def parse_parameter_value(raw: bytes, *, allow_empty: bool) -> bytes:
    value = raw.strip(b" \t")
    if not value:
        raise Rejected("parameter value is missing")
    if value.startswith(b'"'):
        if len(value) < 2 or not value.endswith(b'"'):
            raise Rejected("quoted parameter is unterminated")
        value = value[1:-1]
    if not allow_empty and not value:
        raise Rejected("required parameter is empty")
    if any(byte < 0x20 or byte >= 0x7F or byte in (0x22, 0x5C, 0x3B) for byte in value):
        raise Rejected("parameter contains a forbidden byte")
    return value


def parse_boundary(content_type: bytes) -> bytes:
    boundary: bytes | None = None
    parts = content_type.split(b";")
    for parameter in parts[1:]:
        parameter = parameter.strip(b" \t")
        if not parameter or b"=" not in parameter:
            raise Rejected("multipart parameter syntax is invalid")
        name, value = parameter.split(b"=", 1)
        name = name.strip(b" \t")
        if not valid_header_name(name):
            raise Rejected("multipart parameter name is invalid")
        if name.lower() == b"boundary":
            if boundary is not None:
                raise Rejected("multipart boundary is duplicated")
            boundary = parse_parameter_value(value, allow_empty=False)
    if boundary is None or len(boundary) > BOUNDARY_BYTES:
        raise Rejected("multipart boundary is missing or oversized")
    return boundary


def parse_content_disposition(line: bytes, plan: FaultPlan) -> tuple[bytes, bytes | None]:
    if b":" not in line:
        raise Rejected("Content-Disposition omitted its colon")
    header_name, raw_value = line.split(b":", 1)
    if not valid_header_name(header_name) or header_name.lower() != b"content-disposition":
        raise Rejected("multipart disposition header name is not exact")
    parts = raw_value.strip(b" \t").split(b";")
    if not parts or parts[0].strip(b" \t").lower() != b"form-data":
        raise Rejected("multipart disposition token is not form-data")
    name: bytes | None = None
    filename: bytes | None = None
    for parameter in parts[1:]:
        parameter = parameter.strip(b" \t")
        if not parameter or b"=" not in parameter:
            raise Rejected("multipart disposition parameter is malformed")
        parameter_name, raw_parameter_value = parameter.split(b"=", 1)
        parameter_name = parameter_name.strip(b" \t")
        if not valid_header_name(parameter_name):
            raise Rejected("multipart disposition parameter name is invalid")
        lowered = parameter_name.lower()
        if lowered == b"name":
            if name is not None:
                raise Rejected("multipart name parameter is duplicated")
            plan.hit("disposition_name")
            name = parse_parameter_value(raw_parameter_value, allow_empty=False)
            if len(name) > 255:
                raise Rejected("multipart name is oversized")
        elif lowered == b"filename":
            if filename is not None:
                raise Rejected("multipart filename parameter is duplicated")
            plan.hit("disposition_filename")
            filename = parse_parameter_value(raw_parameter_value, allow_empty=True)
            if len(filename) > 255:
                raise Rejected("multipart filename is oversized")
        else:
            parse_parameter_value(raw_parameter_value, allow_empty=True)
    if name is None or not name:
        raise Rejected("multipart part omitted a real nonempty name")
    return name, filename


def valid_fallback_filename(value: bytes) -> bool:
    return (
        0 < len(value) <= 255
        and not any(byte < 0x20 or byte >= 0x7F or byte in (0x22, 0x5C, 0x3B) for byte in value)
    )


def parse_multipart(
    body: bytes,
    declared: int,
    boundary: bytes,
    *,
    query_args: list[tuple[bytes, bytes]] | None = None,
    plan: FaultPlan | None = None,
    upload_chunk: int = UPLOAD_CHUNK,
) -> ParseResult:
    events: list[str] = []
    reads: list[tuple[int, int]] = []
    fault = plan or FaultPlan()
    started = False
    post_args: list[tuple[bytes, bytes]] = []
    current_args = list(query_args or [])
    retained = sum(len(key) + len(value) for key, value in current_args)
    if declared <= 0 or retained > FORM_RETAINED_BYTES:
        return ParseResult(False, (), ())
    available_limit = min(declared, len(body))
    offset = 0

    def bounded_line(capacity: int = HEADER_LINE_BYTES, *, allow_tab: bool = False) -> bytes:
        nonlocal offset
        before = offset
        line, offset = read_line(body, offset, capacity, allow_tab=allow_tab, limit=available_limit)
        reads.append((before, offset))
        return line

    def reject(message: str) -> None:
        nonlocal started
        if started:
            events.append("ABORT")
            started = False
        post_args.clear()
        raise Rejected(message)

    opening = b"--" + boundary
    closing = opening + b"--"
    try:
        if bounded_line() != opening:
            reject("opening boundary is invalid")
        fault.hit("form_array")
        finished = False
        while not finished:
            disposition = bounded_line(allow_tab=True)
            name, filename = parse_content_disposition(disposition, fault)
            file_part = filename is not None
            if filename == b"blob":
                for query_name, query_value in current_args:
                    if query_name == b"filename":
                        fault.hit("fallback_filename_copy")
                        if not valid_fallback_filename(query_value):
                            reject("blob query filename is empty, oversized, or outside policy")
                        filename = bytes(query_value)
                        break
            part_header_count = 1  # Content-Disposition is wire header one.
            part_content_type: bytes = b"text/plain"
            saw_part_content_type = False
            while True:
                line = bounded_line(allow_tab=True)
                if not line:
                    break
                part_header_count += 1
                if part_header_count > HEADER_COUNT or b":" not in line:
                    reject("multipart part header count or syntax is invalid")
                header_name, header_value = line.split(b":", 1)
                if not valid_header_name(header_name):
                    reject("multipart part header name is invalid")
                fault.hit("part_header_assign")
                if header_name.lower() == b"content-type":
                    if saw_part_content_type:
                        reject("multipart Content-Type is duplicated")
                    part_content_type = header_value.strip(b" \t")
                    if not part_content_type or len(part_content_type) > 255:
                        reject("multipart Content-Type is empty or oversized")
                    saw_part_content_type = True

            if not file_part:
                value = bytearray()
                saw_value_line = False
                field_wire_start = offset
                while True:
                    line = bounded_line(allow_tab=True)
                    if offset - field_wire_start > FORM_FIELD_WIRE_BYTES:
                        reject("multipart field consumed-wire budget was exceeded")
                    if line in (opening, closing):
                        break
                    separator = 1 if saw_value_line else 0
                    if len(value) + separator + len(line) > FORM_FIELD_BYTES:
                        reject("multipart retained field exceeded its cap")
                    fault.hit("form_value_append")
                    if separator:
                        value.extend(b"\n")
                    value.extend(line)
                    saw_value_line = True
                entry_bytes = len(name) + len(value)
                if len(post_args) >= QUERY_ARGS or retained + entry_bytes > FORM_RETAINED_BYTES:
                    reject("multipart request-wide retained budget was exceeded")
                fault.hit("form_key_move")
                fault.hit("form_value_move")
                post_args.append((name, bytes(value)))
                retained += entry_bytes
                if line == closing:
                    finished = True
                continue

            fault.hit("upload_object")
            fault.hit("upload_name")
            fault.hit("upload_filename")
            fault.hit("upload_type")
            require(part_content_type is not None, "multipart model lost upload type")
            events.append("START")
            started = True
            fault.hit("upload_after_start")

            marker = b"\r\n--" + boundary
            marker_at = body.find(marker, offset, available_limit)
            if marker_at < 0:
                reject("file boundary was absent within Content-Length")
            file_bytes = marker_at - offset
            write_callbacks = max(1, (file_bytes + upload_chunk - 1) // upload_chunk)
            events.extend("WRITE" for _ in range(write_callbacks))
            before = offset
            offset = marker_at + len(marker)
            reads.append((before, offset))
            fault.hit("upload_after_write")
            suffix = bounded_line()
            if suffix != b"--" or offset != declared:
                reject("file boundary was nonfinal or body accounting was not exact")
            if len(post_args) + len(current_args) > QUERY_ARGS:
                reject("combined multipart argument count exceeded its cap")
            fault.hit("final_args")
            post_args.clear()
            current_args.clear()
            events.append("END")
            started = False
            finished = True
        if offset != declared:
            reject("multipart body retained trailing declared bytes")
        if post_args:
            if len(post_args) + len(current_args) > QUERY_ARGS:
                reject("combined multipart argument count exceeded its cap")
            fault.hit("final_args")
            post_args.clear()
            current_args.clear()
    except Rejected:
        if started:
            events.append("ABORT")
            started = False
        require(events.count("ABORT") <= 1, "multipart model emitted duplicate ABORT")
        require("END" not in events, "rejected multipart model emitted END")
        require(all(end <= declared for _start, end in reads),
                "multipart model read beyond declared Content-Length")
        return ParseResult(False, tuple(events), tuple(reads), False, 0)
    require(all(end <= declared for _start, end in reads),
            "accepted multipart model read beyond declared Content-Length")
    return ParseResult(True, tuple(events), tuple(reads), False, 0)


def parse_request(
    wire: bytes,
    *,
    fail_stage: str | None = None,
    raw_handler: bool = False,
) -> ParseResult:
    events: list[str] = []
    reads: list[tuple[int, int]] = []
    plan = FaultPlan(fail_stage)
    offset = 0
    try:
        before = offset
        request_line, offset = read_line(wire, offset, REQUEST_LINE_BYTES)
        reads.append((before, offset))
        plan.hit("request_line_assign")
        fields = request_line.split(b" ")
        if len(fields) != 3 or any(not field for field in fields):
            raise Rejected("request line did not contain exactly three nonempty tokens")
        method, target, version = fields
        plan.hit("request_method")
        plan.hit("request_target")
        plan.hit("request_version")
        if method not in KNOWN_METHODS:
            raise Rejected("request method is not an exact known method")
        if version not in (b"HTTP/1.0", b"HTTP/1.1"):
            raise Rejected("HTTP version is not 1.0 or 1.1")
        if not target or len(target) > TARGET_BYTES:
            raise Rejected("request target is empty or oversized")
        route, separator, query = target.partition(b"?")
        plan.hit("route_assign")
        if separator:
            plan.hit("query_assign")
        if not route or not valid_argument_data(query):
            raise Rejected("request target/query is invalid")

        headers: list[tuple[bytes, bytes]] = []
        while True:
            before = offset
            line, offset = read_line(wire, offset, HEADER_LINE_BYTES, allow_tab=True)
            reads.append((before, offset))
            if not line:
                break
            if len(headers) >= HEADER_COUNT or b":" not in line:
                raise Rejected("header count or syntax is invalid")
            name, value = line.split(b":", 1)
            plan.hit("header_name_assign")
            plan.hit("header_value_assign")
            if not valid_header_name(name):
                raise Rejected("request header name is invalid")
            plan.hit("collect_header")
            headers.append((name.lower(), value.strip(b" \t")))

        if any(name == b"transfer-encoding" for name, _value in headers):
            raise Rejected("Transfer-Encoding is forbidden")
        lengths = [value for name, value in headers if name == b"content-length"]
        if len(lengths) > 1:
            raise Rejected("duplicate Content-Length is forbidden")
        declared = parse_content_length(lengths[0]) if lengths else 0
        content_types = [value for name, value in headers if name == b"content-type"]
        if len(content_types) > 1:
            raise Rejected("duplicate Content-Type is forbidden")
        content_type = content_types[0] if content_types else b""
        plan.hit("host_reset")

        is_form = False
        is_encoded = False
        if content_type:
            plan.hit("media_type_assign")
            media_type = content_type.split(b";", 1)[0].strip(b" \t").lower()
            if not media_type:
                raise Rejected("Content-Type media token is empty")
            if media_type == b"text/plain":
                pass
            elif media_type == b"application/x-www-form-urlencoded":
                is_encoded = True
            elif media_type == b"multipart/form-data":
                is_form = True
            elif (
                media_type.startswith(b"text/plain")
                or media_type.startswith(b"application/x-www-form-urlencoded")
                or media_type.startswith(b"multipart/")
            ):
                raise Rejected("special Content-Type lookalike is forbidden")

        if method not in BODY_METHODS:
            parse_arguments(query, plan)
            return ParseResult(True, (), tuple(reads))

        body = wire[offset:]
        if is_form:
            boundary = parse_boundary(content_type)
            plan.hit("boundary_assign")
            query_args = parse_arguments(query, plan)
            result = parse_multipart(body, declared, boundary, query_args=query_args, plan=plan)
            return ParseResult(
                result.accepted,
                result.events,
                tuple(reads) + result.reads,
                result.post_args_present,
                result.post_args_len,
            )

        if raw_handler:
            plan.hit("raw_object")
            events.append("RAW_START")
            plan.hit("raw_after_start")
            total = 0
            while total < declared:
                available = min(UPLOAD_CHUNK, len(body) - total, declared - total)
                if available <= 0:
                    events.append("RAW_ABORT")
                    raise Rejected("raw body ended before Content-Length")
                total += available
                events.append("RAW_WRITE")
                plan.hit("raw_after_write")
            events.append("RAW_END")
            return ParseResult(True, tuple(events), tuple(reads))

        if declared > PLAIN_BODY_BYTES or declared > len(body):
            raise Rejected("plain body is oversized or short")
        if declared > 0:
            plan.hit("plain_buffer")
        body = body[:declared]
        if any(byte in (0, 0x7F) or (is_encoded and byte < 0x20) for byte in body):
            raise Rejected("plain/encoded body contains a forbidden byte")
        combined = query
        if is_encoded:
            if declared > FORM_FIELD_BYTES:
                raise Rejected("encoded body exceeded its cap")
            if combined and body:
                plan.hit("encoded_separator")
                combined += b"&"
            if body:
                plan.hit("encoded_body_append")
                combined += body
            if not valid_argument_data(combined):
                raise Rejected("encoded body arguments are invalid")
        parsed = parse_arguments(combined if is_encoded else query, plan)
        if not is_encoded and body:
            plan.hit("plain_args_array")
            plan.hit("plain_arg_move")
            plan.hit("plain_key_assign")
            plan.hit("plain_value_assign")
            parsed.append((b"plain", body))
        require(parsed is not None, "plain argument model lost parsed state")
        return ParseResult(True, tuple(events), tuple(reads))
    except Rejected:
        if "RAW_START" in events and "RAW_END" not in events and "RAW_ABORT" not in events:
            events.append("RAW_ABORT")
        require(events.count("RAW_ABORT") <= 1, "raw model emitted duplicate ABORT")
        require("RAW_END" not in events, "rejected raw model emitted END")
        return ParseResult(False, tuple(events), tuple(reads), False, 0)


def request(
    headers: list[bytes] | None = None,
    *,
    method: bytes = b"GET",
    target: bytes = b"/",
    version: bytes = b"HTTP/1.1",
    body: bytes = b"",
    request_line: bytes | None = None,
) -> bytes:
    first = request_line if request_line is not None else method + b" " + target + b" " + version
    rows = [first]
    rows.extend(headers or [])
    return b"\r\n".join(rows) + b"\r\n\r\n" + body


def retained_lines(length: int, byte: bytes = b"a") -> list[bytes]:
    require(len(byte) == 1 and length >= 0, "retained-line fixture is invalid")
    lines: list[bytes] = []
    remaining = length
    while remaining:
        if lines:
            remaining -= 1  # retained newline inserted between source lines
            if remaining < 0:
                raise ParserFixtureError("retained-line fixture cannot represent requested length")
        take = min(1024, remaining)
        lines.append(byte * take)
        remaining -= take
    return lines or [b""]


def multipart(
    boundary: bytes,
    *,
    fields: list[tuple[bytes, list[bytes]]] | None = None,
    file_bytes: bytes = b"FILE",
    final: bool = True,
    trailing: bytes = b"",
    file_disposition: bytes | None = None,
    part_headers: list[bytes] | None = None,
) -> bytes:
    rows = bytearray()
    for name, lines in fields or []:
        rows.extend(b"--" + boundary + b"\r\n")
        rows.extend(b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n')
        for line in lines:
            rows.extend(line + b"\r\n")
    rows.extend(b"--" + boundary + b"\r\n")
    rows.extend(
        file_disposition
        or b'Content-Disposition: form-data; name="file"; filename="x.bin"'
    )
    rows.extend(b"\r\n")
    for header in (
        part_headers if part_headers is not None else [b"Content-Type: application/octet-stream"]
    ):
        rows.extend(header + b"\r\n")
    rows.extend(b"\r\n")
    rows.extend(file_bytes)
    rows.extend(b"\r\n--" + boundary)
    rows.extend(b"--\r\n" if final else b"\r\n")
    rows.extend(trailing)
    return bytes(rows)


def function_block(source: str, signature: str) -> str:
    start = source.find(signature)
    require(start >= 0, f"source function is missing: {signature}")
    brace = source.find("{", start)
    require(brace >= 0, f"source function body is missing: {signature}")
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise ParserFixtureError(f"source function braces are unbalanced: {signature}")


def verify_source_contract(source: str) -> None:
    for fragment in (
        "#define XX(num, name, string) _STR(string),",
        "XTINCT_HTTP_FORM_FIELD_WIRE_BYTES = 8192",
        "XTINCT_HTTP_FORM_RETAINED_BYTES = 8192",
        "req.indexOf(' ', addr_end + 1) >= 0",
        'version == F("HTTP/1.0")',
        'version == F("HTTP/1.1")',
        "if (sawContentType) return false;",
        'mediaType.equalsIgnoreCase(F("multipart/form-data"))',
        "partHeaderCount = 1U",
        "userHeaders = _headerKeysCount - preseededHeaders",
        "xtinctUrlDecodeExact(encodedKey, arg.key)",
        "xtinctAppendExact(searchStr, '&')",
        "xtinctAssignExact(arg.key, \"plain\")",
        "xtinctMoveExact(_currentUpload->name, argName)",
        "xtinctMoveExact(_currentUpload->filename, argFilename)",
        "xtinctMoveExact(_currentUpload->type, argType)",
        "xtinctValidFallbackFilename(argFilename)",
    ):
        require(fragment in source, f"bounded parser source invariant is missing: {fragment}")
    require("readStringUntil" not in source and "readBytesUntil" not in source,
            "bounded parser uses an unbudgeted line reader")

    request_block = function_block(source, "bool WebServer::_parseRequest")
    form_block = function_block(source, "bool WebServer::_parseForm(")
    collect_block = function_block(source, "bool WebServer::_collectHeader")
    arguments_block = function_block(source, "void WebServer::_parseArguments")
    disposition_block = function_block(source, "bool xtinctParseContentDisposition")
    fallback_block = function_block(source, "bool xtinctValidFallbackFilename")
    require(request_block.count("RAW_ABORTED") == 1 and request_block.count("RAW_END") == 1,
            "raw body terminal statuses are not single and explicit")
    require(form_block.count("UPLOAD_FILE_ABORTED") == 1,
            "multipart parser does not have exactly one fail-path ABORT status")
    require(form_block.count("UPLOAD_FILE_END") == 1,
            "multipart parser does not have exactly one END status")
    require(form_block.index("!finalizeArguments()") < form_block.index("UPLOAD_FILE_END"),
            "multipart END precedes fallible argument finalization")
    require(form_block.count("return fail();") >= 20,
            "multipart malformed/OOM exits do not converge on fail cleanup")
    for fragment in (
        "delete[] _postArgs;",
        "_postArgs = nullptr;",
        "_postArgsLen = 0;",
        "delete[] _currentArgs;",
        "_currentArgs = nullptr;",
        "_currentArgCount = 0;",
        "if (uploadStarted && _currentUpload)",
    ):
        require(fragment in form_block, f"multipart cleanup invariant is missing: {fragment}")
    require("_parseFormUploadAborted" not in form_block,
            "multipart parser bypasses its single cleanup path")
    require('headerName.equalsIgnoreCase(F("Content-Disposition"))' in disposition_block and
            'disposition.equalsIgnoreCase(F("form-data"))' in disposition_block and
            "if (sawName" in disposition_block and "if (sawFilename" in disposition_block,
            "Content-Disposition grammar is not exact/duplicate-safe")
    require("value.isEmpty() || value.length() > 255U" in fallback_block and
            "byte == '\\\\'" in fallback_block,
            "blob query filename policy is not nonempty/bounded/as-policy")
    require("if (!xtinctAssignExact(argFilename, _currentArgs[index].value) ||" in form_block and
            "!xtinctValidFallbackFilename(argFilename)) return fail();" in form_block and
            "break;" in form_block,
            "blob query filename fallback is not checked before upload metadata/START")
    for block, label in (
        (request_block, "request"),
        (form_block, "multipart"),
        (collect_block, "header collection"),
        (arguments_block, "argument parsing"),
    ):
        require(".substring(" not in block and ".concat(" not in block,
                f"{label} still contains an unchecked String construction/append")
        require(
            re.search(
                r"\b(?:req|methodStr|url|version|searchStr|boundaryStr|headerName|headerValue|"
                r"line|opening|closing|argName|argValue|argType|argFilename|partHeaderName|"
                r"partHeaderValue|encodedKey|encodedValue)\s*\+=",
                block,
            ) is None,
            f"{label} still contains an unchecked String operator+=",
        )


def verify_patch(project_root: Path) -> None:
    patch = project_root / PATCH_RELATIVE
    require(patch.is_file() and not patch.is_symlink(), "bounded parser patch is missing or linked")
    payload = patch.read_bytes()
    require(EXPECTED_PATCH_BYTES > 0 and EXPECTED_PATCH_SHA256 != "UNPINNED",
            "bounded parser checker has not been re-pinned")
    require(len(payload) == EXPECTED_PATCH_BYTES and sha256(payload) == EXPECTED_PATCH_SHA256,
            "bounded parser patch bytes changed")
    verify_source_contract(payload.decode("utf-8"))


def expect_rejected(
    wire: bytes,
    label: str,
    *,
    fail_stage: str | None = None,
    raw_handler: bool = False,
    require_abort: bool = False,
    raw_abort: bool = False,
) -> ParseResult:
    result = parse_request(wire, fail_stage=fail_stage, raw_handler=raw_handler)
    require(not result.accepted, f"malformed/faulted parser fixture was accepted: {label}")
    require("END" not in result.events and "RAW_END" not in result.events,
            f"malformed/faulted parser fixture emitted END: {label}")
    require(not result.post_args_present and result.post_args_len == 0,
            f"malformed/faulted parser fixture retained post-argument residue: {label}")
    if require_abort:
        require(result.events.count("ABORT") == 1,
                f"started malformed upload did not emit exactly one ABORT: {label}")
    if raw_abort:
        require(result.events.count("RAW_ABORT") == 1,
                f"started malformed raw body did not emit exactly one ABORT: {label}")
    return result


def expect_mutation_rejected(source: str, old: str, new: str, label: str) -> None:
    require(old in source, f"source mutation anchor is missing: {label}")
    mutated = source.replace(old, new, 1)
    try:
        verify_source_contract(mutated)
    except ParserFixtureError:
        return
    raise ParserFixtureError(f"source-structural mutation escaped the checker: {label}")


def self_test(project_root: Path) -> int:
    verify_patch(project_root)
    source = (project_root / PATCH_RELATIVE).read_text(encoding="utf-8")
    passes = 0

    def passed(count: int = 1) -> None:
        nonlocal passes
        passes += count

    line, offset = read_line(b"A" * 1024 + b"\r\n", 0, 1024)
    require(len(line) == 1024 and offset == 1026, "exact-cap request line failed")
    passed()
    for label, wire in (
        ("request-1025", b"A" * 1025 + b"\r\n"),
        ("request-nonterminated", b"GET / HTTP/1.1"),
        ("request-missing-lf", b"GET / HTTP/1.1\rX"),
        ("request-nul", b"GET /\0x HTTP/1.1\r\n"),
        ("request-c0", b"GET /\x01x HTTP/1.1\r\n"),
    ):
        try:
            read_line(wire, 0, 1024)
        except Rejected:
            passed()
        else:
            raise ParserFixtureError(f"line fixture was accepted: {label}")

    for method in sorted(KNOWN_METHODS):
        require(parse_request(request(method=method)).accepted,
                f"known HTTP method was rejected: {method!r}")
        passed()
    require(parse_request(request(version=b"HTTP/1.0")).accepted, "HTTP/1.0 was rejected")
    passed()
    for label, request_line in (
        ("unknown-method", b"BREH / HTTP/1.1"),
        ("lowercase-method", b"get / HTTP/1.1"),
        ("missing-version", b"GET /"),
        ("arbitrary-version", b"GET / HTTP/1.9"),
        ("truncated-version", b"GET / HTTP/1."),
        ("extra-token", b"GET / HTTP/1.1 EXTRA"),
        ("double-space", b"GET  / HTTP/1.1"),
    ):
        expect_rejected(request(request_line=request_line), label)
        passed()

    header_1024 = b"Destination: /" + b"a" * (1024 - len(b"Destination: /"))
    require(parse_request(request([header_1024])).accepted, "exact-cap Destination header failed")
    passed()
    expect_rejected(request([header_1024 + b"a"]), "Destination-1025")
    passed()
    expect_rejected(b"GET / HTTP/1.1\r\nDestination: /x", "header-nonterminated")
    passed()
    require(parse_request(request([f"X-{index}: v".encode() for index in range(32)])).accepted,
            "32 request headers were rejected")
    passed()
    expect_rejected(request([f"X-{index}: v".encode() for index in range(33)]), "33 headers")
    passed()
    for label, malformed in (
        ("transfer-encoding-name-whitespace", b"Transfer-Encoding : chunked"),
        ("content-length-name-whitespace", b"Content-Length\t: 0"),
    ):
        expect_rejected(request([malformed], method=b"POST"), label)
        passed()
    require(parse_request(request([b"X-Transfer-Encoding: chunked"])).accepted,
            "valid Transfer-Encoding lookalike header was rejected")
    passed()

    target_32 = b"/?" + b"&".join(f"a{i}=x".encode() for i in range(32))
    require(parse_request(request(target=target_32)).accepted, "32 query args were rejected")
    passed()
    target_33 = b"/?" + b"&".join(f"a{i}=x".encode() for i in range(33))
    expect_rejected(request(target=target_33), "33 query args")
    passed()
    expect_rejected(request(target=b"/?a=%0G"), "malformed percent escape")
    passed()

    for label, headers in (
        ("duplicate-cl", [b"Content-Length: 0", b"Content-Length: 0"]),
        ("conflicting-cl", [b"Content-Length: 0", b"Content-Length: 1"]),
        ("negative-cl", [b"Content-Length: -1"]),
        ("overflow-cl", [b"Content-Length: 2147483648"]),
        ("nonnumeric-cl", [b"Content-Length: nope"]),
        ("empty-cl", [b"Content-Length:"]),
        ("transfer-encoding", [b"Transfer-Encoding: chunked"]),
        ("duplicate-content-type", [b"Content-Type: text/plain", b"Content-Type: text/plain"]),
    ):
        expect_rejected(request(headers, method=b"POST"), label)
        passed()
    for media in (
        b"Content-Type: text/plainx",
        b"Content-Type: application/x-www-form-urlencodedx",
        b"Content-Type: multipart/form-datax; boundary=X",
        b"Content-Type: multipart/mixed; boundary=X",
    ):
        expect_rejected(request([media, b"Content-Length: 0"], method=b"POST"), media.decode())
        passed()
    require(parse_request(request(
        [b"Content-Type: Text/Plain; charset=utf-8", b"Content-Length: 0"], method=b"POST"
    )).accepted, "exact case-insensitive text/plain media token was rejected")
    passed()

    require(parse_request(request([b"Content-Length: 0"], method=b"POST")).accepted,
            "zero-length POST was rejected")
    passed()
    require(parse_request(request([b"Content-Length: 65536"], method=b"POST", body=b"x" * 65536)).accepted,
            "64KiB plain body was rejected")
    passed()
    expect_rejected(request([b"Content-Length: 65537"], method=b"POST", body=b"x" * 65537),
                    "64KiB+1 plain body")
    passed()

    raw_zero = parse_request(request([b"Content-Length: 0"], method=b"POST"), raw_handler=True)
    require(raw_zero.accepted and raw_zero.events == ("RAW_START", "RAW_END"),
            "zero-length raw body callback contract changed")
    passed()
    raw_exact = parse_request(request([b"Content-Length: 1436"], method=b"POST", body=b"x" * 1436),
                              raw_handler=True)
    require(raw_exact.accepted and raw_exact.events == ("RAW_START", "RAW_WRITE", "RAW_END"),
            "exact raw chunk callback contract changed")
    passed()
    raw_plus_one = parse_request(request([b"Content-Length: 1437"], method=b"POST", body=b"x" * 1437),
                                 raw_handler=True)
    require(raw_plus_one.accepted and raw_plus_one.events.count("RAW_WRITE") == 2 and
            raw_plus_one.events[-1] == "RAW_END", "raw chunk+1 callback contract changed")
    passed()
    raw_short = expect_rejected(
        request([b"Content-Length: 1437"], method=b"POST", body=b"x" * 1436),
        "raw-short", raw_handler=True, raw_abort=True,
    )
    require(raw_short.events[:2] == ("RAW_START", "RAW_WRITE"),
            "raw short body did not write its received prefix before ABORT")
    passed()
    for stage, expects_abort in (
        ("raw_object", False),
        ("raw_after_start", True),
        ("raw_after_write", True),
    ):
        result = expect_rejected(
            request([b"Content-Length: 1"], method=b"POST", body=b"x"),
            stage, fail_stage=stage, raw_handler=True, raw_abort=expects_abort,
        )
        if not expects_abort:
            require(not result.events, "raw allocation failure emitted callbacks before START")
        passed()

    for stage in (
        "request_line_assign",
        "request_method",
        "request_target",
        "request_version",
        "route_assign",
        "query_assign",
        "header_name_assign",
        "header_value_assign",
        "collect_header",
        "host_reset",
        "media_type_assign",
        "query_array",
        "query_key_decode",
        "query_value_decode",
        "plain_buffer",
        "plain_args_array",
        "plain_arg_move",
        "plain_key_assign",
        "plain_value_assign",
        "encoded_separator",
        "encoded_body_append",
    ):
        if stage in ("query_assign", "query_key_decode", "query_value_decode"):
            wire = request(target=b"/?a=b")
        elif stage in ("header_name_assign", "header_value_assign", "collect_header"):
            wire = request([b"Host: x"])
        elif stage == "media_type_assign":
            wire = request([b"Content-Type: text/plain", b"Content-Length: 0"], method=b"POST")
        elif stage in ("plain_buffer", "plain_args_array", "plain_arg_move", "plain_key_assign", "plain_value_assign"):
            wire = request([b"Content-Type: text/plain", b"Content-Length: 1"], method=b"POST", body=b"x")
        elif stage in ("encoded_separator", "encoded_body_append"):
            wire = request(
                [b"Content-Type: application/x-www-form-urlencoded", b"Content-Length: 3"],
                method=b"POST", target=b"/?q=x", body=b"a=b",
            )
        else:
            wire = request()
        expect_rejected(wire, f"String allocation stage {stage}", fail_stage=stage)
        passed()

    for label, content_type in (
        ("missing-boundary", b"Content-Type: multipart/form-data"),
        ("empty-boundary", b"Content-Type: multipart/form-data; boundary="),
        ("overlong-boundary", b"Content-Type: multipart/form-data; boundary=" + b"b" * 129),
        ("boundary-lookalike", b"Content-Type: multipart/form-data; xboundary=XTINCT"),
        ("duplicate-boundary", b"Content-Type: multipart/form-data; boundary=XTINCT; boundary=OTHER"),
    ):
        expect_rejected(request([content_type, b"Content-Length: 1"], method=b"POST", body=b"x"), label)
        passed()

    boundary = b"XTINCT"
    valid_body = multipart(boundary, fields=[(b"family", [b"stack"])], file_bytes=b"F" * 5000)
    valid = parse_request(request([
        b'Content-Type: multipart/form-data; Boundary="XTINCT"',
        f"Content-Length: {len(valid_body)}".encode(),
    ], method=b"POST", body=valid_body))
    require(valid.accepted and valid.events[0] == "START" and valid.events[-1] == "END" and
            valid.events.count("WRITE") == 4 and "ABORT" not in valid.events,
            "valid field-then-large-file multipart sequence changed")
    passed()

    empty_file = multipart(boundary, file_bytes=b"")
    empty_result = parse_request(request([
        b"Content-Type: multipart/form-data; boundary=XTINCT",
        f"Content-Length: {len(empty_file)}".encode(),
    ], method=b"POST", body=empty_file))
    require(empty_result.accepted and empty_result.events == ("START", "WRITE", "END"),
            "empty multipart file must emit one zero-byte WRITE between START and END")
    passed()

    blob_disposition = b'Content-Disposition: form-data; name="file"; filename="blob"'
    blob_body = multipart(boundary, file_disposition=blob_disposition)
    blob_255 = parse_request(request([
        b"Content-Type: multipart/form-data; boundary=XTINCT",
        f"Content-Length: {len(blob_body)}".encode(),
    ], method=b"POST", target=b"/?filename=" + b"a" * 255, body=blob_body))
    require(blob_255.accepted and blob_255.events[-1] == "END",
            "255-byte blob query filename fallback was rejected")
    passed()
    blob_256_wire = request([
        b"Content-Type: multipart/form-data; boundary=XTINCT",
        f"Content-Length: {len(blob_body)}".encode(),
    ], method=b"POST", target=b"/?filename=" + b"a" * 256, body=blob_body)
    blob_256 = expect_rejected(blob_256_wire, "256-byte blob query filename fallback")
    require("ABORT" not in blob_256.events,
            "pre-START oversized blob fallback emitted ABORT")
    passed()
    blob_policy_wire = request([
        b"Content-Type: multipart/form-data; boundary=XTINCT",
        f"Content-Length: {len(blob_body)}".encode(),
    ], method=b"POST", target=b"/?filename=bad%5Cname", body=blob_body)
    blob_policy = expect_rejected(blob_policy_wire, "out-of-policy blob query filename fallback")
    require("ABORT" not in blob_policy.events,
            "pre-START out-of-policy blob fallback emitted ABORT")
    passed()
    blob_copy_fault = expect_rejected(
        request([
            b"Content-Type: multipart/form-data; boundary=XTINCT",
            f"Content-Length: {len(blob_body)}".encode(),
        ], method=b"POST", target=b"/?filename=good.bin", body=blob_body),
        "blob fallback checked-copy failure", fail_stage="fallback_filename_copy",
    )
    require("ABORT" not in blob_copy_fault.events and "END" not in blob_copy_fault.events,
            "pre-START blob fallback copy failure emitted a terminal upload callback")
    passed()

    disposition_prefix = b'Content-Disposition: form-data; name="file"; filename="x.bin"; x='
    disposition_1024 = disposition_prefix + b"a" * (1024 - len(disposition_prefix))
    control_body = multipart(boundary, file_disposition=disposition_1024)
    require(parse_request(request([
        b"Content-Type: multipart/form-data; boundary=XTINCT",
        f"Content-Length: {len(control_body)}".encode(),
    ], method=b"POST", body=control_body)).accepted, "exact-cap multipart control line failed")
    passed()
    overlong_control = multipart(boundary, file_disposition=disposition_1024 + b"a")
    expect_rejected(request([
        b"Content-Type: multipart/form-data; boundary=XTINCT",
        f"Content-Length: {len(overlong_control)}".encode(),
    ], method=b"POST", body=overlong_control), "1025-byte multipart control line")
    passed()

    for label, disposition in (
        ("disposition-header-lookalike", b'X-Content-Disposition: form-data; name="file"; filename="x"'),
        ("disposition-name-whitespace", b'Content-Disposition : form-data; name="file"; filename="x"'),
        ("disposition-token-lookalike", b'Content-Disposition: xform-data; name="file"; filename="x"'),
        ("filename-cannot-substitute", b'Content-Disposition: form-data; filename="x"'),
        ("name-lookalike", b'Content-Disposition: form-data; xname="file"; filename="x"'),
        ("empty-name", b'Content-Disposition: form-data; name=""; filename="x"'),
        ("duplicate-name", b'Content-Disposition: form-data; name="a"; name="b"; filename="x"'),
        ("duplicate-filename", b'Content-Disposition: form-data; name="a"; filename="x"; filename="y"'),
        ("malformed-param", b'Content-Disposition: form-data; name="a"; nope'),
    ):
        malformed = multipart(boundary, file_disposition=disposition)
        expect_rejected(request([
            b"Content-Type: multipart/form-data; boundary=XTINCT",
            f"Content-Length: {len(malformed)}".encode(),
        ], method=b"POST", body=malformed), label)
        passed()

    extras_31 = [f"X-{index}: v".encode() for index in range(31)]
    headers_31_body = multipart(boundary, part_headers=extras_31)
    require(parse_request(request([
        b"Content-Type: multipart/form-data; boundary=XTINCT",
        f"Content-Length: {len(headers_31_body)}".encode(),
    ], method=b"POST", body=headers_31_body)).accepted,
            "31 extra multipart headers plus disposition were rejected")
    passed()
    extras_32 = [f"X-{index}: v".encode() for index in range(32)]
    headers_32_body = multipart(boundary, part_headers=extras_32)
    expect_rejected(request([
        b"Content-Type: multipart/form-data; boundary=XTINCT",
        f"Content-Length: {len(headers_32_body)}".encode(),
    ], method=b"POST", body=headers_32_body), "32 extras exceed total 32 multipart headers")
    passed()

    retained_4096 = multipart(boundary, fields=[(b"f", retained_lines(4096))])
    require(parse_request(request([
        b"Content-Type: multipart/form-data; boundary=XTINCT",
        f"Content-Length: {len(retained_4096)}".encode(),
    ], method=b"POST", body=retained_4096)).accepted, "4096-byte retained field was rejected")
    passed()
    retained_4097 = multipart(boundary, fields=[(b"f", retained_lines(4097))])
    expect_rejected(request([
        b"Content-Type: multipart/form-data; boundary=XTINCT",
        f"Content-Length: {len(retained_4097)}".encode(),
    ], method=b"POST", body=retained_4097), "4097-byte retained field")
    passed()

    wire_exact = multipart(boundary, fields=[(b"f", [b""] * 4091)])
    require(parse_request(request([
        b"Content-Type: multipart/form-data; boundary=XTINCT",
        f"Content-Length: {len(wire_exact)}".encode(),
    ], method=b"POST", body=wire_exact)).accepted,
            "8192-byte field wire budget including empty CRLF lines was rejected")
    passed()
    wire_plus_one = multipart(boundary, fields=[(b"f", [b"x"] + [b""] * 4090)])
    expect_rejected(request([
        b"Content-Type: multipart/form-data; boundary=XTINCT",
        f"Content-Length: {len(wire_plus_one)}".encode(),
    ], method=b"POST", body=wire_plus_one), "8193-byte field wire budget")
    passed()

    retained_budget_exact = multipart(boundary, fields=[
        (b"a", retained_lines(4095, b"a")),
        (b"b", retained_lines(4095, b"b")),
    ])
    require(parse_request(request([
        b"Content-Type: multipart/form-data; boundary=XTINCT",
        f"Content-Length: {len(retained_budget_exact)}".encode(),
    ], method=b"POST", body=retained_budget_exact)).accepted,
            "exact 8192-byte request-wide retained form budget was rejected")
    passed()
    retained_budget_plus_one = multipart(boundary, fields=[
        (b"a", retained_lines(4096, b"a")),
        (b"b", retained_lines(4095, b"b")),
    ])
    expect_rejected(request([
        b"Content-Type: multipart/form-data; boundary=XTINCT",
        f"Content-Length: {len(retained_budget_plus_one)}".encode(),
    ], method=b"POST", body=retained_budget_plus_one), "8193-byte request-wide retained budget")
    passed()

    file_only = multipart(boundary, file_bytes=b"FILE")
    for label, declared, malformed in (
        ("multipart-short", len(file_only), file_only[:-3]),
        ("multipart-declared-underrun", len(file_only) - 1, file_only),
        ("multipart-trailing", len(file_only) + 4, file_only + b"JUNK"),
        ("multipart-nonfinal", len(multipart(boundary, final=False)), multipart(boundary, final=False)),
    ):
        expect_rejected(request([
            b"Content-Type: multipart/form-data; boundary=XTINCT",
            f"Content-Length: {declared}".encode(),
        ], method=b"POST", body=malformed), label, require_abort=True)
        passed()

    for stage, after_start in (
        ("boundary_assign", False),
        ("form_array", False),
        ("disposition_name", False),
        ("disposition_filename", False),
        ("part_header_assign", False),
        ("upload_object", False),
        ("upload_name", False),
        ("upload_filename", False),
        ("upload_type", False),
        ("upload_after_start", True),
        ("upload_after_write", True),
        ("final_args", True),
    ):
        expect_rejected(request([
            b"Content-Type: multipart/form-data; boundary=XTINCT",
            f"Content-Length: {len(file_only)}".encode(),
        ], method=b"POST", body=file_only), stage, fail_stage=stage, require_abort=after_start)
        passed()
    field_body = multipart(boundary, fields=[(b"f", [b"x"])])
    for stage in ("form_value_append", "form_key_move", "form_value_move"):
        expect_rejected(request([
            b"Content-Type: multipart/form-data; boundary=XTINCT",
            f"Content-Length: {len(field_body)}".encode(),
        ], method=b"POST", body=field_body), stage, fail_stage=stage)
        passed()

    for old, new, label in (
        ("req.indexOf(' ', addr_end + 1) >= 0", "false", "extra request token"),
        ('version == F("HTTP/1.1")', 'version == F("HTTP/1.9")', "HTTP version"),
        ("if (sawContentType) return false;", "if (false) return false;", "duplicate Content-Type"),
        ("size_t partHeaderCount = 1U;", "size_t partHeaderCount = 0U;", "disposition header count"),
        ("if (uploadStarted && _currentUpload)", "if (_currentUpload)", "post-START ABORT guard"),
        ("xtinctMoveExact(_currentUpload->name, argName)", "true", "upload name assignment"),
        ('headerName.equalsIgnoreCase(F("Content-Disposition"))',
         'headerName.startsWith(F("Content-Disposition"))', "Content-Disposition token"),
        ("!xtinctValidFallbackFilename(argFilename)) return fail();",
         "false) return fail();", "blob fallback filename policy"),
    ):
        expect_mutation_rejected(source, old, new, label)
        passed()

    return passes


def main(argv: list[str]) -> int:
    project_root = Path(__file__).resolve().parents[1]
    try:
        if argv not in ([], ["--self-test"]):
            raise ParserFixtureError("Usage: check_bounded_webserver_parser.py [--self-test]")
        passes = self_test(project_root) if argv == ["--self-test"] else (verify_patch(project_root) or 0)
    except (OSError, UnicodeError, ParserFixtureError) as error:
        print(f"BOUNDED_WEBSERVER_PARSER_ERROR: {error}", file=sys.stderr)
        return 1
    if argv == ["--self-test"]:
        print(f"BOUNDED_WEBSERVER_PARSER_SELF_TEST_OK {passes}")
    else:
        print("BOUNDED_WEBSERVER_PARSER_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
