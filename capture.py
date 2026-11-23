"""Read live frames through Npcap, or read a classic PCAP file offline."""

import ctypes as ct
import os
import struct
from dataclasses import dataclass
from pathlib import Path


LINK_TYPES = {0: "回环", 1: "以太网"}
SNAPLEN = 65535
ERROR_SIZE = 256


class CaptureError(Exception):
    pass


@dataclass(frozen=True)
class Frame:
    timestamp: float
    wire_length: int
    link_type: int
    data: bytes


@dataclass(frozen=True)
class Adapter:
    name: bytes
    description: str
    loopback: bool


class PcapInterface(ct.Structure):
    pass


InterfacePtr = ct.POINTER(PcapInterface)
PcapInterface._fields_ = [
    ("next", InterfacePtr),
    ("name", ct.c_char_p),
    ("description", ct.c_char_p),
    ("addresses", ct.c_void_p),
    ("flags", ct.c_uint32),
]


class PcapHeader(ct.Structure):
    _fields_ = [
        ("seconds", ct.c_int32),
        ("microseconds", ct.c_int32),
        ("captured", ct.c_uint32),
        ("original", ct.c_uint32),
    ]


def decode_message(value):
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return value.decode("mbcs", errors="replace")


class Npcap:
    def __init__(self):
        if os.name != "nt":
            raise CaptureError("实时抓包需要 Windows 和 Npcap。")
        system = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
        candidates = [system / "Npcap" / "wpcap.dll", system / "wpcap.dll"]
        dll = next((file for file in candidates if file.is_file()), None)
        if dll is None:
            raise CaptureError("未检测到 Npcap。安装驱动后可刷新网卡，也可先载入示例。")
        try:
            self.api = ct.CDLL(str(dll))
            self._declare_api()
        except (OSError, AttributeError) as error:
            raise CaptureError(f"无法加载 Npcap，请检查驱动和 Python 的位数。{error}") from error

    def _declare_api(self):
        error_buffer = ct.POINTER(ct.c_char)
        signatures = {
            "pcap_findalldevs": (ct.c_int, ct.POINTER(InterfacePtr), error_buffer),
            "pcap_freealldevs": (None, InterfacePtr),
            "pcap_open_live": (ct.c_void_p, ct.c_char_p, ct.c_int, ct.c_int, ct.c_int, error_buffer),
            "pcap_setnonblock": (ct.c_int, ct.c_void_p, ct.c_int, error_buffer),
            "pcap_datalink": (ct.c_int, ct.c_void_p),
            "pcap_next_ex": (ct.c_int, ct.c_void_p, ct.POINTER(ct.POINTER(PcapHeader)),
                             ct.POINTER(ct.POINTER(ct.c_ubyte))),
            "pcap_geterr": (ct.c_char_p, ct.c_void_p),
            "pcap_close": (None, ct.c_void_p),
        }
        for name, (result, *arguments) in signatures.items():
            function = getattr(self.api, name)
            function.restype = result
            function.argtypes = arguments

    def adapters(self):
        head = InterfacePtr()
        error = ct.create_string_buffer(ERROR_SIZE)
        if self.api.pcap_findalldevs(ct.byref(head), error) != 0:
            raise CaptureError(decode_message(error.value))
        devices = []
        current = head
        try:
            while current:
                item = current.contents
                if item.name:
                    devices.append(Adapter(
                        item.name,
                        decode_message(item.description or item.name),
                        bool(item.flags & 1),
                    ))
                current = item.next
        finally:
            if head:
                self.api.pcap_freealldevs(head)
        return devices

    def frames(self, adapter, stop):
        error = ct.create_string_buffer(ERROR_SIZE)
        # Capture traffic visible to the adapter in its normal mode.
        handle = self.api.pcap_open_live(adapter.name, SNAPLEN, 0, 100, error)
        if not handle:
            raise CaptureError(decode_message(error.value))
        try:
            link_type = self.api.pcap_datalink(handle)
            require_link_type(link_type)
            if self.api.pcap_setnonblock(handle, 1, error) != 0:
                raise CaptureError(decode_message(error.value))
            header = ct.POINTER(PcapHeader)()
            data = ct.POINTER(ct.c_ubyte)()
            while not stop.is_set():
                result = self.api.pcap_next_ex(handle, ct.byref(header), ct.byref(data))
                if result == 0:
                    stop.wait(0.025)
                    continue
                if result < 0:
                    message = self.api.pcap_geterr(handle)
                    raise CaptureError(decode_message(message or b"Capture ended unexpectedly."))
                record = header.contents
                yield Frame(record.seconds + record.microseconds / 1_000_000,
                            record.original, link_type, ct.string_at(data, record.captured))
        finally:
            self.api.pcap_close(handle)


def require_link_type(link_type):
    if link_type not in LINK_TYPES:
        raise CaptureError(f"不支持的链路类型 {link_type}，请选择以太网或回环数据。")


def pcap_frames(path, stop):
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    with path.open("rb") as source:
        magic = source.read(4)
        if magic not in formats:
            raise CaptureError("请选择经典 PCAP 文件。可以用 Wireshark 将 PCAPNG 另存为 PCAP。")
        order, units = formats[magic]
        global_header = source.read(20)
        if len(global_header) != 20:
            raise CaptureError("PCAP 文件头不完整。")
        major, minor, _, _, snaplen, network = struct.unpack(order + "HHIIII", global_header)
        if (major, minor) != (2, 4) or snaplen == 0:
            raise CaptureError("PCAP 文件头的版本或捕获长度无效。")
        link_type = network & 0xFFFF
        require_link_type(link_type)
        while not stop.is_set():
            record = source.read(16)
            if not record:
                return
            if len(record) != 16:
                raise CaptureError("PCAP 数据包的记录头不完整。")
            seconds, fraction, captured, original = struct.unpack(order + "IIII", record)
            if captured > min(snaplen, original, 16 * 1024 * 1024) or fraction >= units:
                raise CaptureError("PCAP 数据包的长度或时间戳无效。")
            amount = min(captured, SNAPLEN)
            payload = source.read(amount)
            if len(payload) != amount:
                raise CaptureError("PCAP 数据包被截断。")
            # Validate the tail before yielding even if it exceeds the display limit.
            if captured > amount and len(source.read(captured - amount)) != captured - amount:
                raise CaptureError("PCAP 数据包被截断。")
            yield Frame(seconds + fraction / units, original, link_type, payload)
