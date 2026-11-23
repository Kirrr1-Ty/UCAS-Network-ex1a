"""Sample the local Windows TCP tables while a live capture is running."""

import ctypes as ct
import ipaddress
import os
import socket
import struct
from collections import defaultdict
from ctypes import wintypes as wt
from threading import Thread
from time import time

from flows import ProcessOwner, endpoint_pair


TCP_TABLE_OWNER_PID_CONNECTIONS = 4
ERROR_INSUFFICIENT_BUFFER = 122
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TCP4_ROW = struct.Struct("<I4s4s4s4sI")
TCP6_ROW = struct.Struct("<16sI4s16sI4sII")


def address_text(raw):
    address = ipaddress.ip_address(raw)
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address)


def table_connections(raw, row_format):
    count = struct.unpack_from("<I", raw)[0]
    rows = raw[4:4 + count * row_format.size]
    if len(rows) != count * row_format.size:
        raise OSError("Windows TCP 连接表返回了不完整的数据。")
    for row in row_format.iter_unpack(rows):
        if row_format == TCP4_ROW:
            _, local, local_port, remote, remote_port, pid = row
            local_scope = remote_scope = 0
        else:
            local, local_scope, local_port, remote, remote_scope, remote_port, _, pid = row
        remote_port = int.from_bytes(remote_port[:2], "big")
        if pid and remote_port and any(remote):
            source = (address_text(local), int.from_bytes(local_port[:2], "big"))
            destination = (address_text(remote), remote_port)
            scopes = (local_scope, remote_scope) if source <= destination else (remote_scope, local_scope)
            yield endpoint_pair(source, destination), scopes, pid


class WindowsTcpOwners:
    def __init__(self):
        if os.name != "nt":
            raise OSError("进程追踪需要 Windows TCP 连接表。")
        self.table_api = ct.WinDLL("iphlpapi", use_last_error=True).GetExtendedTcpTable
        self.table_api.argtypes = [ct.c_void_p, ct.POINTER(wt.DWORD), wt.BOOL, wt.ULONG, ct.c_int, wt.ULONG]
        self.table_api.restype = wt.DWORD
        kernel = ct.WinDLL("kernel32", use_last_error=True)
        self.open_process = kernel.OpenProcess
        self.open_process.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        self.open_process.restype = wt.HANDLE
        self.close_handle = kernel.CloseHandle
        self.close_handle.argtypes = [wt.HANDLE]
        self.close_handle.restype = wt.BOOL
        self.image_name = kernel.QueryFullProcessImageNameW
        self.image_name.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ct.POINTER(wt.DWORD)]
        self.image_name.restype = wt.BOOL
        self.process_times = kernel.GetProcessTimes
        self.process_times.argtypes = [wt.HANDLE] + [ct.POINTER(wt.FILETIME)] * 4
        self.process_times.restype = wt.BOOL
        self.process_cache = {}

    def _table(self, family):
        size = wt.DWORD(0)
        buffer = None
        for _ in range(5):
            result = self.table_api(buffer, ct.byref(size), False, family, TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
            if result == 0:
                return buffer.raw if buffer else bytes(4)
            if result != ERROR_INSUFFICIENT_BUFFER:
                raise ct.WinError(result)
            buffer = ct.create_string_buffer(size.value)
        raise OSError("Windows TCP 连接表变化过快，请稍后重试。")

    def _owner(self, pid):
        handle = self.open_process(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return ProcessOwner(pid, "")
        try:
            created, exited, kernel, user = (wt.FILETIME() for _ in range(4))
            creation_time = 0
            if self.process_times(handle, ct.byref(created), ct.byref(exited), ct.byref(kernel), ct.byref(user)):
                creation_time = (created.dwHighDateTime << 32) | created.dwLowDateTime
            cached = self.process_cache.get(pid)
            if cached and creation_time and cached.creation_time == creation_time:
                return cached
            path = ct.create_unicode_buffer(32768)
            length = wt.DWORD(len(path))
            name = os.path.basename(path.value) if self.image_name(handle, 0, path, ct.byref(length)) else ""
            return ProcessOwner(pid, name, creation_time)
        finally:
            self.close_handle(handle)

    def snapshot(self):
        groups = defaultdict(dict)
        pids = set()
        for family, row_format in ((socket.AF_INET, TCP4_ROW), (socket.AF_INET6, TCP6_ROW)):
            for pair, scopes, pid in table_connections(self._table(family), row_format):
                groups[pair].setdefault(scopes, set()).add(pid)
                pids.add(pid)
        self.process_cache = {pid: self._owner(pid) for pid in pids}
        # Link-local IPv6 addresses may be repeated across interfaces. The packet
        # itself doesn't carry the scope, so skip ambiguous owner matches.
        return {pair: frozenset(self.process_cache[pid] for pid in next(iter(scoped.values())))
                for pair, scoped in groups.items() if len(scoped) == 1}


class TcpOwnerMonitor:
    def __init__(self, stop):
        self.stop = stop
        self.latest = None
        self.error = ""
        self.thread = Thread(target=self._sample, daemon=True)
        self.thread.start()

    def _sample(self):
        try:
            windows = WindowsTcpOwners()
        except (AttributeError, OSError) as error:
            self.error = str(error)
            return
        while not self.stop.is_set():
            timestamp = time()
            try:
                self.latest = (timestamp, windows.snapshot())
                self.error = ""
            except OSError as error:
                self.error = str(error)
            self.stop.wait(0.15)
