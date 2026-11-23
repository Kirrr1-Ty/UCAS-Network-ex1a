"""Tkinter entry point for the experiment 1A packet viewer."""

import tkinter as tk
from collections import Counter
from contextlib import closing
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Thread
from tkinter import filedialog, ttk

from capture import CaptureError, Npcap, pcap_frames
from flows import FlowTracker, format_endpoint
from packets import FILTERS, decode_frame, hex_dump
from tcp_owners import TcpOwnerMonitor


SAMPLE = Path(__file__).with_name("sample.pcap")
PACKET_LIMIT = 1500


class PacketFeed:
    """Move capture work off the GUI thread and bound the pending queue."""

    def __init__(self, source, live):
        self.live = live
        self.pending = Queue(maxsize=256)
        self.stop = Event()
        self.received = 0
        self.dropped = 0
        self.error = ""
        self.thread = Thread(target=self._read, args=(source,), daemon=True)
        self.thread.start()

    def _read(self, source):
        try:
            with closing(source(self.stop)) as stream:
                for frame in stream:
                    if self.stop.is_set():
                        break
                    self.received += 1
                    entry = (self.received, frame)
                    if self.live:
                        try:
                            self.pending.put_nowait(entry)
                        except Full:
                            self.dropped += 1
                        continue
                    while not self.stop.is_set():
                        try:
                            self.pending.put(entry, timeout=0.05)
                            break
                        except Full:
                            continue
        except (CaptureError, OSError) as error:
            self.error = str(error)


class SnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("实验 1A · 网络嗅探器")
        self.root.geometry("1100x720")
        self.root.minsize(820, 560)
        self.root.configure(background="#f1f5f9")
        self.adapter_choice = tk.StringVar()
        self.filter_choice = tk.StringVar(value=FILTERS[0])
        self.process_choice = tk.StringVar()
        self.tracking_status = tk.StringVar()
        self.status = tk.StringVar(value="正在检查网卡…")
        self.counts = tk.StringVar()
        self.packets = {}
        self.tracker = FlowTracker()
        self.followed_flow = None
        self.followed_process = None
        self.processes = [None]
        self.flow_window = None
        self.owner_monitor = None
        self.adapters = []
        self.npcap = None
        self.feed = None
        self.received = self.dropped = self.visible = 0
        self._build()
        self._sync_processes()
        self.refilter()
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(0, self.refresh_adapters)
        root.after(40, self.poll)

    def _build(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TFrame", background="#f1f5f9")
        style.configure("TLabel", background="#f1f5f9", foreground="#24364a", font=("Microsoft YaHei UI", 10))
        style.configure("Title.TLabel", foreground="#11253c", font=("Microsoft YaHei UI", 21, "bold"))
        style.configure("TButton", padding=(10, 6), font=("Microsoft YaHei UI", 9))
        style.configure("Start.TButton", background="#17645e", foreground="white")
        style.map("Start.TButton", background=[("disabled", "#dce3ea"), ("active", "#0d514c")],
                  foreground=[("disabled", "#576675")])
        style.configure("Treeview", background="white", fieldbackground="white", foreground="#1d3045",
                        font=("Microsoft YaHei UI", 9), rowheight=26, borderwidth=0)
        style.configure("Treeview.Heading", background="#e2ebf4", foreground="#24364a",
                        font=("Microsoft YaHei UI", 9, "bold"), padding=(5, 6))
        style.map("Treeview", background=[("selected", "#17645e")], foreground=[("selected", "white")])

        toolbar = ttk.Frame(self.root, padding=(16, 12, 16, 8))
        toolbar.pack(fill="x")
        ttk.Label(toolbar, text="网络嗅探器", style="Title.TLabel").pack(anchor="w", pady=(0, 10))
        capture_row = ttk.Frame(toolbar)
        capture_row.pack(fill="x")
        ttk.Label(capture_row, text="网卡").pack(side="left", padx=(0, 6))
        self.interfaces = ttk.Combobox(capture_row, state="readonly", textvariable=self.adapter_choice)
        self.interfaces.pack(side="left", fill="x", expand=True, padx=(0, 7))
        self.interfaces.bind("<<ComboboxSelected>>", lambda _: self._buttons())
        self.refresh_button = self._button(capture_row, "刷新", self.refresh_adapters)
        self.start_button = self._button(capture_row, "开始抓包", self.start_live, style="Start.TButton")
        self.stop_button = self._button(capture_row, "停止", self.stop_feed)

        file_row = ttk.Frame(toolbar)
        file_row.pack(fill="x", pady=(8, 0))
        ttk.Label(file_row, text="协议筛选").pack(side="left", padx=(0, 6))
        filter_list = ttk.Combobox(file_row, state="readonly", width=9,
                                   textvariable=self.filter_choice, values=FILTERS)
        filter_list.pack(side="left", padx=(0, 12))
        filter_list.bind("<<ComboboxSelected>>", lambda _: self.refilter())
        self.open_button = self._button(file_row, "打开 PCAP", self.open_file)
        self.sample_button = self._button(file_row, "载入示例", lambda: self.start_file(SAMPLE))
        self.clear_button = self._button(file_row, "清空", self.clear)

        trace_row = ttk.Frame(toolbar)
        trace_row.pack(fill="x", pady=(8, 0))
        self._button(trace_row, "TCP 流列表", self.show_flows)
        ttk.Label(trace_row, text="进程").pack(side="left", padx=(6, 6))
        self.process_list = ttk.Combobox(trace_row, state="readonly", width=25, textvariable=self.process_choice)
        self.process_list.pack(side="left", padx=(0, 6))
        self.process_list.bind("<<ComboboxSelected>>", self.select_process)
        self.unfollow_button = self._button(trace_row, "取消追踪", self.unfollow)
        ttk.Label(toolbar, textvariable=self.tracking_status, wraplength=760).pack(anchor="w", pady=(5, 0))

        footer = ttk.Frame(self.root, padding=(16, 8))
        footer.pack(side="bottom", fill="x")
        ttk.Label(footer, textvariable=self.counts).pack(side="right", padx=(12, 0))
        ttk.Label(footer, textvariable=self.status, wraplength=480).pack(side="left", fill="x", expand=True)

        panes = ttk.Panedwindow(self.root, orient="vertical")
        panes.pack(fill="both", expand=True, padx=16)
        table = ttk.Frame(panes)
        panes.add(table, weight=3)
        fields = ("序号", "时间", "源地址", "目标地址", "协议", "字节", "摘要")
        widths = (56, 110, 150, 150, 76, 64, 360)
        self.table = ttk.Treeview(table, columns=fields, show="headings", selectmode="browse", height=11)
        for label, width in zip(fields, widths):
            self.table.heading(label, text=label, anchor="w")
            self.table.column(label, width=width, minwidth=45,
                              stretch=label in ("源地址", "目标地址", "摘要"))
        self.table.tag_configure("odd", background="#f6f9fc")
        self.table.bind("<<TreeviewSelect>>", self.show_selection)
        self.table.bind("<Button-3>", self.show_packet_menu)
        self.packet_menu = tk.Menu(self.root, tearoff=False)
        self.packet_menu.add_command(label="追踪此 TCP 流", command=self.follow_selected)
        self._scrollable(table, self.table, True)

        inspection = ttk.Panedwindow(panes, orient="horizontal")
        panes.add(inspection, weight=2)
        self.details = self._text_panel(inspection, "协议字段", ("Microsoft YaHei UI", 10))
        self.raw = self._text_panel(inspection, "十六进制与 ASCII", ("Consolas", 10))
        self.details.tag_configure("heading", foreground="#135c55", font=("Microsoft YaHei UI", 10, "bold"))
        self._buttons()

    @staticmethod
    def _button(parent, title, callback, **options):
        button = ttk.Button(parent, text=title, command=callback, **options)
        button.pack(side="left", padx=(0, 6))
        return button

    @staticmethod
    def _scrollable(parent, widget, horizontal):
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
        widget.grid(row=0, column=0, sticky="nsew")
        vertical = ttk.Scrollbar(parent, orient="vertical", command=widget.yview)
        vertical.grid(row=0, column=1, sticky="ns")
        widget.configure(yscrollcommand=vertical.set)
        if horizontal:
            bar = ttk.Scrollbar(parent, orient="horizontal", command=widget.xview)
            bar.grid(row=1, column=0, sticky="ew")
            widget.configure(xscrollcommand=bar.set)

    def _text_panel(self, panes, title, font):
        panel = ttk.Frame(panes, padding=(0, 5, 4, 0))
        panes.add(panel, weight=1)
        ttk.Label(panel, text=title).pack(anchor="w", pady=(0, 5))
        body = ttk.Frame(panel)
        body.pack(fill="both", expand=True)
        text = tk.Text(body, height=8, width=40, font=font, background="white", foreground="#24364a",
                       wrap="none", state="disabled", borderwidth=0, padx=9, pady=7)
        self._scrollable(body, text, True)
        return text

    def _buttons(self):
        active = self.feed is not None
        for button in (self.refresh_button, self.open_button, self.sample_button, self.clear_button):
            button.configure(state="disabled" if active else "normal")
        self.interfaces.configure(state="disabled" if active else "readonly")
        self.start_button.configure(state="normal" if not active and self.interfaces.current() >= 0 else "disabled")
        self.stop_button.configure(state="normal" if active and not self.feed.stop.is_set() else "disabled")

    def refresh_adapters(self):
        self.adapters = []
        self.npcap = None
        self.adapter_choice.set("")
        try:
            self.npcap = Npcap()
            self.adapters = self.npcap.adapters()
        except CaptureError as error:
            self.status.set(str(error))
        else:
            self.status.set("选择网卡后开始抓包，也可以载入离线示例。" if self.adapters else "未找到可用网卡。")
        self.interfaces.configure(values=[f"{i}. {device.description}" for i, device in enumerate(self.adapters, 1)])
        if self.adapters:
            index = next((i for i, device in enumerate(self.adapters) if not device.loopback), 0)
            self.interfaces.current(index)
        self._buttons()

    def start_live(self):
        index = self.interfaces.current()
        if self.feed is None and self.npcap is not None and index >= 0:
            adapter = self.adapters[index]
            self._start(lambda stop: self.npcap.frames(adapter, stop), True, adapter.description)

    def open_file(self):
        name = filedialog.askopenfilename(parent=self.root, title="选择 PCAP 文件",
                                          filetypes=[("PCAP 抓包文件", "*.pcap *.cap"), ("所有文件", "*")])
        if name:
            self.start_file(Path(name))

    def start_file(self, path):
        if self.feed is None:
            self._start(lambda stop: pcap_frames(path, stop), False, path.name)

    def _start(self, source, live, name):
        self.clear()
        self.feed = PacketFeed(source, live)
        if live:
            self.owner_monitor = TcpOwnerMonitor(self.feed.stop)
            self._tracking_status()
        self.status.set(f"正在{'抓包' if live else '读取'} · {name}")
        self._buttons()

    def stop_feed(self):
        if self.feed:
            self.feed.stop.set()
            self.status.set("正在停止…")
            self._buttons()

    def clear(self):
        self.packets.clear()
        self.tracker = FlowTracker()
        self.followed_flow = None
        self.followed_process = None
        self.owner_monitor = None
        self.received = self.dropped = 0
        self._sync_processes()
        self.refilter()

    def _selected_packet(self):
        selection = self.table.selection()
        return self.packets.get(int(selection[0])) if selection else None

    def show_packet_menu(self, event):
        row = self.table.identify_row(event.y)
        if not row:
            return
        self.table.selection_set(row)
        self.table.focus(row)
        packet = self._selected_packet()
        self.packet_menu.entryconfigure(0, state="normal" if packet and packet.flow_id else "disabled")
        try:
            self.packet_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.packet_menu.grab_release()

    def follow_selected(self):
        packet = self._selected_packet()
        if packet and packet.flow_id is not None:
            self.follow_flow(packet.flow_id)

    def follow_flow(self, number):
        if number not in self.tracker.flows:
            return
        self._set_flow(number)
        self._sync_processes()
        self.filter_choice.set(FILTERS[0])
        self.refilter()

    def _set_flow(self, number):
        previous = self.followed_flow
        self.followed_flow = number
        if previous != number:
            self.tracker.release(previous)

    def select_process(self, _event=None):
        index = self.process_list.current()
        if index < 0:
            return
        self.followed_process = self.processes[index]
        self._set_flow(None)
        self._sync_processes()
        if self.followed_process:
            self.filter_choice.set(FILTERS[0])
        self.refilter()

    def unfollow(self):
        self._set_flow(None)
        self.followed_process = None
        self._sync_processes()
        self.refilter()

    def _sync_processes(self):
        owners = {owner for flow in self.tracker.flows.values() for owner in flow.owners}
        if self.followed_process:
            owners.add(self.followed_process)
        self.processes = [None, *sorted(owners, key=lambda owner: (owner.name.casefold(), owner.pid, owner.creation_time))]
        labels = [owner.label for owner in self.processes[1:]]
        counts = Counter(labels)
        labels = [f"{label} · {index}" if counts[label] > 1 else label for index, label in enumerate(labels, 1)]
        self.process_list.configure(values=["全部进程", *labels], state="readonly" if owners else "disabled")
        self.process_list.current(self.processes.index(self.followed_process))

    def _tracking_status(self):
        flow = self.tracker.flows.get(self.followed_flow)
        if flow and self.followed_process:
            self.tracking_status.set(f"{self.followed_process.label} · {flow.label}")
        elif flow:
            self.tracking_status.set(flow.label)
        elif self.followed_process:
            self.tracking_status.set(f"正在查看 {self.followed_process.label} 的全部已捕获 TCP 流")
        elif self.owner_monitor and self.owner_monitor.error:
            self.tracking_status.set(f"进程匹配失败 · {self.owner_monitor.error}")
        elif self.owner_monitor:
            self.tracking_status.set("进程下拉框显示实时抓包中已匹配的进程。")
        else:
            self.tracking_status.set("右键 TCP 包可追踪。进程匹配在实时抓包时进行。")
        self.unfollow_button.configure(state="normal" if flow or self.followed_process else "disabled")

    def _matches(self, packet, protocol):
        if self.followed_flow is not None and packet.flow_id != self.followed_flow:
            return False
        if self.followed_process:
            flow = self.tracker.flows.get(packet.flow_id)
            if flow is None or self.followed_process not in flow.owners:
                return False
        return packet.matches(protocol)

    def show_flows(self):
        if self.flow_window is not None:
            self.flow_window.lift()
            return
        self.flow_window = tk.Toplevel(self.root)
        self.flow_window.title("TCP 流列表")
        self.flow_window.geometry("930x380")
        self.flow_window.transient(self.root)
        self.flow_window.protocol("WM_DELETE_WINDOW", self._close_flows)
        panel = ttk.Frame(self.flow_window, padding=10)
        panel.pack(fill="both", expand=True)
        fields = ("流号", "端点 A", "端点 B", "本机进程", "保留包数")
        self.flow_table = ttk.Treeview(panel, columns=fields, show="headings", selectmode="browse")
        for field, width in zip(fields, (55, 205, 205, 300, 85)):
            self.flow_table.heading(field, text=field, anchor="w")
            self.flow_table.column(field, width=width, minwidth=50)
        self._scrollable(panel, self.flow_table, True)
        self.flow_hint = tk.StringVar()
        ttk.Label(self.flow_window, textvariable=self.flow_hint, padding=(10, 0, 10, 10)).pack(anchor="w")
        self.flow_table.bind("<Double-1>", self._follow_flow_row)
        self._refresh_flows()

    def _refresh_flows(self):
        owner = self.followed_process
        self.flow_window.title(f"TCP 流列表 · {owner.label}" if owner else "TCP 流列表")
        table = self.flow_table
        rows = table.get_children()
        remaining = set(rows)
        no_owner = "未匹配" if self.owner_monitor else "离线无 PID"
        for flow in self.tracker.flows.values():
            if owner and owner not in flow.owners:
                continue
            key = str(flow.number)
            names = ", ".join(sorted(process.label for process in flow.owners)) or no_owner
            values = (flow.number, format_endpoint(flow.source), format_endpoint(flow.destination), names,
                      flow.packet_count)
            if key in remaining:
                table.item(key, values=values)
                remaining.remove(key)
            else:
                table.insert("", "end", iid=key, values=values)
        if remaining:
            table.delete(*remaining)
        self.flow_hint.set(f"{len(table.get_children())} 条流 · 双击可查看双向数据包")
        self.flow_refresh = self.root.after(350, self._refresh_flows)

    def _follow_flow_row(self, event):
        row = self.flow_table.identify_row(event.y)
        if row:
            self.follow_flow(int(row))
            self._close_flows()

    def _close_flows(self):
        self.root.after_cancel(self.flow_refresh)
        self.flow_window.destroy()
        self.flow_window = None

    def _counts(self):
        self.counts.set(f"读取 {self.received:,}  ·  保留 {len(self.packets):,}  ·  显示 {self.visible:,}"
                        f"  ·  队列丢弃 {self.dropped:,}")

    def _insert(self, packet):
        self.table.insert("", "end", iid=str(packet.number), tags=("odd",) if packet.number % 2 else (),
                          values=(packet.number, packet.time, packet.source, packet.destination,
                                  packet.protocol, packet.frame.wire_length, packet.info))
        self.visible += 1

    def refilter(self):
        selected = self.table.selection()
        self.table.delete(*self.table.get_children())
        self.visible = 0
        protocol = self.filter_choice.get()
        for packet in self.packets.values():
            if self._matches(packet, protocol):
                self._insert(packet)
        if selected and self.table.exists(selected[0]):
            self.table.selection_set(selected[0])
            self.table.see(selected[0])
        self.show_selection()
        self._counts()
        self._tracking_status()

    def poll(self):
        feed = self.feed
        if feed:
            protocol = self.filter_choice.get()
            owners_evicted = False
            for _ in range(120):
                try:
                    number, frame = feed.pending.get_nowait()
                except Empty:
                    break
                packet = decode_frame(number, frame)
                self.tracker.add(packet)
                self.packets[number] = packet
                if self._matches(packet, protocol):
                    self._insert(packet)
                if len(self.packets) > PACKET_LIMIT:
                    oldest = next(iter(self.packets))
                    evicted = self.packets.pop(oldest)
                    old_flow = self.tracker.flows.get(evicted.flow_id)
                    self.tracker.forget(evicted, self.followed_flow)
                    if old_flow and old_flow.owners and old_flow.number not in self.tracker.flows:
                        owners_evicted = True
                    if self.table.exists(str(oldest)):
                        self.table.delete(str(oldest))
                        self.visible -= 1
            monitor = self.owner_monitor
            snapshot = monitor.latest if monitor else None
            owners_changed = snapshot is not None and self.tracker.assign_owners(snapshot)
            if owners_changed or owners_evicted:
                self._sync_processes()
            if owners_changed:
                if self.followed_process:
                    self.refilter()
                else:
                    self.show_selection()
            self._tracking_status()
            self.received, self.dropped = feed.received, feed.dropped
            self._counts()
            if not feed.thread.is_alive() and feed.pending.empty():
                self.feed = None
                stopped = feed.stop.is_set()
                feed.stop.set()
                if feed.error:
                    self.status.set(f"{'抓包' if feed.live else '读取'}失败 · {feed.error}")
                else:
                    self.status.set("已停止。" if stopped or feed.live else "PCAP 读取完成。")
                self._buttons()
        self.root.after(40, self.poll)

    def show_selection(self, _event=None):
        packet = self._selected_packet()
        flow = self.tracker.flows.get(packet.flow_id) if packet else None
        for widget in (self.details, self.raw):
            widget.configure(state="normal")
            widget.delete("1.0", "end")
        if packet:
            self.details.insert("end", f"第 {packet.number} 包 · {len(packet.frame.data)} 字节已捕获\n\n", "heading")
            if flow:
                self.details.insert("end", flow.label + "\n", "heading")
                if flow.owners:
                    self.details.insert("end", "本机进程 = " + ", ".join(sorted(owner.label for owner in flow.owners)) + "\n")
                self.details.insert("end", "\n")
            for title, lines in packet.sections:
                self.details.insert("end", title + "\n", "heading")
                self.details.insert("end", "\n".join(lines) + "\n\n")
            self.raw.insert("1.0", hex_dump(packet.frame.data))
        for widget in (self.details, self.raw):
            widget.configure(state="disabled")

    def close(self):
        if self.flow_window is not None:
            self._close_flows()
        if self.feed:
            self.feed.stop.set()
            self.feed.thread.join(timeout=0.25)
        self.root.destroy()


if __name__ == "__main__":
    window = tk.Tk()
    SnifferApp(window)
    window.mainloop()
