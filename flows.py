"""Track both directions of captured TCP connections and associate their owners."""

from dataclasses import dataclass, field


Endpoint = tuple[str, int]
EndpointPair = tuple[Endpoint, Endpoint]


def endpoint_pair(source, destination):
    return (source, destination) if source <= destination else (destination, source)


def format_endpoint(endpoint):
    address, port = endpoint
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


@dataclass(frozen=True)
class ProcessOwner:
    pid: int
    name: str
    creation_time: int = 0

    @property
    def label(self):
        return f"{self.name} (PID {self.pid})" if self.name else f"PID {self.pid}"


@dataclass
class TcpFlow:
    number: int
    source: Endpoint
    destination: Endpoint
    first_timestamp: float
    last_timestamp: float
    start_syn: tuple[Endpoint, int] | None
    packet_count: int = 0
    owners: set[ProcessOwner] = field(default_factory=set)
    finished_senders: set[Endpoint] = field(default_factory=set)
    reset: bool = False

    @property
    def label(self):
        return f"流 #{self.number} · {format_endpoint(self.source)} ↔ {format_endpoint(self.destination)}"


class FlowTracker:
    def __init__(self):
        self.flows: dict[int, TcpFlow] = {}
        self.latest: dict[EndpointPair, TcpFlow] = {}
        self.next_number = 1

    def add(self, packet):
        tcp = packet.tcp
        if tcp is None:
            return
        source = (packet.source, tcp.source_port)
        destination = (packet.destination, tcp.destination_port)
        pair = endpoint_pair(source, destination)
        timestamp = packet.frame.timestamp
        syn = (source, tcp.sequence) if tcp.flags & 0x12 == 0x02 else None
        flow = self.latest.get(pair)
        # A retransmitted opening SYN belongs to its existing connection.
        if flow is None or (syn and (syn != flow.start_syn or flow.reset or len(flow.finished_senders) == 2)):
            flow = TcpFlow(self.next_number, source, destination, timestamp, timestamp, syn)
            self.next_number += 1
            self.flows[flow.number] = flow
            self.latest[pair] = flow
        flow.packet_count += 1
        flow.last_timestamp = max(flow.last_timestamp, timestamp)
        if tcp.flags & 0x01:
            flow.finished_senders.add(source)
        if tcp.flags & 0x04:
            flow.reset = True
        packet.flow_id = flow.number

    def forget(self, packet, followed=None):
        if packet.flow_id is None:
            return
        flow = self.flows[packet.flow_id]
        flow.packet_count -= 1
        if flow.number != followed:
            self.release(flow.number)

    def release(self, number):
        flow = self.flows.get(number)
        if flow and flow.packet_count == 0:
            del self.flows[flow.number]
            pair = endpoint_pair(flow.source, flow.destination)
            if self.latest.get(pair) is flow:
                del self.latest[pair]

    def assign_owners(self, snapshot):
        timestamp, owners_by_pair = snapshot
        changed = False
        for pair, flow in self.latest.items():
            if timestamp < flow.first_timestamp or timestamp - flow.last_timestamp > 0.75:
                continue
            for owner in owners_by_pair.get(pair, ()):
                if owner not in flow.owners:
                    flow.owners.add(owner)
                    changed = True
        return changed
