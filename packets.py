"""Decode headers conservatively. A malformed frame remains inspectable."""

import ipaddress
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime

from capture import Frame


FILTERS = ("全部", "HTTP", "TCP", "UDP", "IPv4", "IPv6", "ICMP", "ICMPv6", "ARP")
HTTP_START = re.compile(
    rb"(?:[A-Z]{1,24} [^ \r\n]+ HTTP/1\.[01]|HTTP/1\.[01] [1-5][0-9]{2}(?: [^\r\n]*)?)"
)


@dataclass(frozen=True)
class TcpHeader:
    source_port: int
    destination_port: int
    sequence: int
    flags: int


@dataclass
class Packet:
    number: int
    frame: Frame
    source: str = "—"
    destination: str = "—"
    network: str = ""
    transport: str = ""
    application: str = ""
    info: str = ""
    sections: list[tuple[str, list[str]]] = field(default_factory=list)
    tcp: TcpHeader | None = None
    flow_id: int | None = None

    @property
    def protocol(self):
        return self.application or self.transport or self.network or "其他"

    @property
    def time(self):
        return datetime.fromtimestamp(self.frame.timestamp).strftime("%H:%M:%S.%f")[:-3]

    def matches(self, protocol):
        if protocol == "ICMP":
            return self.transport in ("ICMP", "ICMPv6")
        return protocol in ("全部", self.network, self.transport, self.application)


def mac(data):
    return data.hex(":")


def decode_frame(number, frame):
    packet = Packet(number, frame)
    raw = frame.data
    try:
        if frame.link_type == 1:
            if len(raw) < 14:
                raise ValueError("以太网头部被截断")
            packet.destination, packet.source = mac(raw[:6]), mac(raw[6:12])
            ether_type = struct.unpack_from("!H", raw, 12)[0]
            offset = 14
            fields = [f"源 MAC = {packet.source}", f"目标 MAC = {packet.destination}"]
            while ether_type in (0x8100, 0x88A8, 0x9100):
                tag, ether_type = struct.unpack_from("!HH", raw, offset)
                fields.append(f"VLAN ID = {tag & 0x0FFF}")
                offset += 4
            fields.append(f"EtherType = 0x{ether_type:04X}")
            packet.sections.append(("以太网", fields))
        else:
            if len(raw) < 5:
                raise ValueError("回环头部或 IP 版本字段被截断")
            packet.sections.append(("回环", [f"地址族原始字节 = {raw[:4].hex(' ')}"]))
            offset = 4
            # DLT_NULL encodes the host address family in host byte order.
            # The IP version also works with captures written on a different OS.
            ether_type = {4: 0x0800, 6: 0x86DD}.get(raw[offset] >> 4, 0)

        if ether_type == 0x0800:
            decode_ipv4(packet, raw[offset:])
        elif ether_type == 0x86DD:
            decode_ipv6(packet, raw[offset:])
        elif ether_type == 0x0806:
            packet.network = "ARP"
            packet.info = "地址解析报文"
            decode_arp(packet, raw[offset:])
        else:
            packet.info = f"未解析的链路协议 0x{ether_type:04X}"
    except (struct.error, ValueError) as error:
        packet.info = "报文截断或格式异常"
        packet.sections.append(("解析提示", [str(error)]))
    if len(raw) < frame.wire_length:
        packet.sections.append(("捕获提示", [f"保留 {len(raw)} 字节，原始长度 {frame.wire_length} 字节"]))
    return packet


def decode_arp(packet, data):
    hardware, protocol, hardware_size, protocol_size, operation = struct.unpack_from("!HHBBH", data)
    fields = [f"操作码 = {operation}", f"硬件类型 = {hardware}", f"协议类型 = 0x{protocol:04X}"]
    if (hardware, protocol, hardware_size, protocol_size) == (1, 0x0800, 6, 4):
        if len(data) < 28:
            raise ValueError("ARP 地址字段被截断")
        sender = ipaddress.IPv4Address(data[14:18])
        target = ipaddress.IPv4Address(data[24:28])
        fields.extend((f"发送方 = {sender} / {mac(data[8:14])}",
                       f"目标 = {target} / {mac(data[18:24])}"))
        operation_name = {1: "请求", 2: "应答"}.get(operation, operation)
        packet.info = f"{operation_name}  {sender} → {target}"
    packet.sections.append(("ARP", fields))


def decode_ipv4(packet, data):
    packet.network = "IPv4"
    if len(data) < 20 or data[0] >> 4 != 4:
        raise ValueError("无效的 IPv4 基本头部")
    header_length = (data[0] & 15) * 4
    total, identification, fragment = struct.unpack_from("!HHH", data, 2)
    if header_length < 20 or header_length > len(data) or total < header_length:
        raise ValueError("无效的 IPv4 头部长度或总长度")
    protocol = data[9]
    offset = (fragment & 0x1FFF) * 8
    packet.source = str(ipaddress.IPv4Address(data[12:16]))
    packet.destination = str(ipaddress.IPv4Address(data[16:20]))
    packet.sections.append(("IPv4", [
        f"源地址 = {packet.source}", f"目标地址 = {packet.destination}",
        f"头部长度 = {header_length} 字节", f"总长度 = {total} 字节", f"TTL = {data[8]}",
        f"上层协议编号 = {protocol}", f"标识 = 0x{identification:04X}",
        f"分片偏移 = {offset} 字节", f"后续分片 = {'是' if fragment & 0x2000 else '否'}",
    ]))
    decode_transport(packet, protocol, data[header_length:total], offset)


def decode_ipv6(packet, data):
    packet.network = "IPv6"
    if len(data) < 40 or data[0] >> 4 != 6:
        raise ValueError("无效的 IPv6 基本头部")
    payload_length, next_header, hop_limit = struct.unpack_from("!HBB", data, 4)
    packet.source = str(ipaddress.IPv6Address(data[8:24]))
    packet.destination = str(ipaddress.IPv6Address(data[24:40]))
    fields = [f"源地址 = {packet.source}", f"目标地址 = {packet.destination}",
              f"有效载荷长度 = {payload_length} 字节", f"下一头部 = {next_header}",
              f"跳数限制 = {hop_limit}"]
    packet.sections.append(("IPv6", fields))
    payload = memoryview(data)[40:40 + payload_length]
    offset = 0
    while next_header in (0, 43, 44, 51, 60):
        old_header = next_header
        next_header, length_code = struct.unpack_from("!BB", payload)
        if old_header == 44:
            length = 8
            fragment, identification = struct.unpack_from("!HI", payload, 2)
            offset = fragment & 0xFFF8
            fields.append(f"分片标识 = 0x{identification:08X}，分片偏移 = {offset} 字节")
        elif old_header == 51:
            length = (length_code + 2) * 4
        else:
            length = (length_code + 1) * 8
        if length > len(payload):
            raise ValueError("IPv6 扩展头被截断")
        fields.append(f"扩展头 {old_header}，长度 {length} 字节")
        payload = payload[length:]
        if offset:
            break
    decode_transport(packet, next_header, bytes(payload), offset)


def decode_transport(packet, protocol, payload, offset):
    packet.transport = {6: "TCP", 17: "UDP"}.get(protocol, "")
    if protocol == 1 and packet.network == "IPv4":
        packet.transport = "ICMP"
    elif protocol == 58 and packet.network == "IPv6":
        packet.transport = "ICMPv6"
    if offset:
        packet.info = f"分片偏移 {offset} 字节"
        return
    if packet.transport == "TCP":
        decode_tcp(packet, payload)
    elif packet.transport == "UDP":
        source, target, length, checksum = struct.unpack_from("!HHHH", payload)
        if length < 8:
            raise ValueError("无效的 UDP 长度")
        packet.info = f"{source} → {target}  长度 {length}"
        packet.sections.append(("UDP", [f"源端口 = {source}", f"目标端口 = {target}",
                                        f"报文长度 = {length} 字节", f"校验和 = 0x{checksum:04X}"]))
    elif packet.transport:
        kind, code, checksum = struct.unpack_from("!BBH", payload)
        names = {0: "回显应答", 3: "目标不可达", 8: "回显请求", 11: "超时"}
        if packet.transport == "ICMPv6":
            names = {1: "目标不可达", 2: "包太大", 3: "超时", 128: "回显请求", 129: "回显应答"}
        packet.info = f"{names.get(kind, '控制报文')}  Type {kind}, Code {code}"
        packet.sections.append((packet.transport, [f"类型 = {kind}", f"代码 = {code}",
                                                   f"校验和 = 0x{checksum:04X}"]))
    else:
        packet.info = f"IP 上层协议编号 {protocol}"


def decode_tcp(packet, payload):
    source, target, sequence, acknowledge, header_flags, window, checksum, urgent = struct.unpack_from(
        "!HHIIHHHH", payload)
    header_length = (header_flags >> 12) * 4
    if not 20 <= header_length <= len(payload):
        raise ValueError("无效的 TCP 头部长度")
    packet.tcp = TcpHeader(source, target, sequence, header_flags & 0x1FF)
    flags = ", ".join(name for bit, name in enumerate(("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"))
                      if header_flags & (1 << bit)) or "无"
    packet.info = f"{source} → {target}  [{flags}]"
    packet.sections.append(("TCP", [
        f"源端口 = {source}", f"目标端口 = {target}", f"序号 = {sequence}",
        f"确认号 = {acknowledge}", f"头部长度 = {header_length} 字节", f"标志 = {flags}",
        f"窗口 = {window}", f"校验和 = 0x{checksum:04X}", f"紧急指针 = {urgent}",
    ]))
    http_lines = payload[header_length:header_length + 8192].split(b"\r\n")
    if len(http_lines) < 2 or not HTTP_START.fullmatch(http_lines[0]):
        return
    packet.application = "HTTP"
    packet.info = http_lines[0].decode("ascii", errors="replace")
    headers = [f"起始行 = {packet.info}"]
    # The final part may be partial unless it was followed by CRLF.
    for line in http_lines[1:-1]:
        if not line:
            break
        headers.append(line.decode("latin-1"))
    packet.sections.append(("HTTP", headers))


def hex_dump(data, limit=4096):
    preview = memoryview(data)[:limit]
    rows = []
    for offset in range(0, len(preview), 16):
        part = bytes(preview[offset:offset + 16])
        printable = "".join(chr(value) if 32 <= value <= 126 else "." for value in part)
        rows.append(f"{offset:04X}  {part.hex(' ').upper():47s}  {printable}")
    if len(data) > limit:
        rows.append(f"\n仅预览前 {limit} 字节，已捕获 {len(data)} 字节。")
    return "\n".join(rows)
