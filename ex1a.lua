-- Dissector for the EX1A UDP echo protocol used in the accompanying capture.
local protocol = Proto("ex1a", "EX1A Lab Echo")
local port = 49001
local header_length = 10
local message_types = { [1] = "Request", [2] = "Reply" }

local fields = {
    magic = ProtoField.string("ex1a.magic", "Magic"),
    version = ProtoField.uint8("ex1a.version", "Version", base.DEC),
    kind = ProtoField.uint8("ex1a.type", "Message Type", base.DEC, message_types),
    exchange_id = ProtoField.uint16("ex1a.id", "Exchange ID", base.DEC),
    payload_length = ProtoField.uint16("ex1a.length", "Declared Payload Length", base.DEC),
    payload = ProtoField.string("ex1a.payload", "Payload"),
}
protocol.fields = { fields.magic, fields.version, fields.kind, fields.exchange_id, fields.payload_length, fields.payload }

local malformed = ProtoExpert.new("ex1a.bad_length", "Invalid EX1A length",
    expert.group.MALFORMED, expert.severity.ERROR)
local unsupported_version = ProtoExpert.new("ex1a.unsupported_version", "Unsupported EX1A version",
    expert.group.PROTOCOL, expert.severity.WARN)
protocol.experts = { malformed, unsupported_version }

function protocol.dissector(buffer, packet, tree)
    local size = buffer:len()
    if size < 4 or buffer(0, 4):string() ~= "EX1A" then
        return 0
    end

    packet.cols.protocol = "EX1A"
    local header = tree:add(protocol, buffer())
    header:add(fields.magic, buffer(0, 4))
    if size < header_length then
        packet.cols.info = "Truncated EX1A header"
        header:add_proto_expert_info(malformed, "The EX1A header requires 10 bytes.")
        return size
    end

    local version = buffer(4, 1):uint()
    local kind = buffer(5, 1):uint()
    local exchange_id = buffer(6, 2):uint()
    local declared_length = buffer(8, 2):uint()
    header:add(fields.version, buffer(4, 1))
    header:add(fields.kind, buffer(5, 1))
    header:add(fields.exchange_id, buffer(6, 2))
    local length_item = header:add(fields.payload_length, buffer(8, 2))

    packet.cols.info = string.format("%s #%d · %d bytes",
        message_types[kind] or ("Type " .. kind), exchange_id, declared_length)
    if version ~= 1 then
        header:add_proto_expert_info(unsupported_version)
        return size
    end

    local available = size - header_length
    if available ~= declared_length then
        length_item:add_proto_expert_info(malformed,
            string.format("Declared %d bytes, captured %d bytes", declared_length, available))
    end
    local readable = math.min(available, declared_length)
    if readable > 0 then
        header:add(fields.payload, buffer(header_length, readable))
    end
    return size
end

DissectorTable.get("udp.port"):add(port, protocol)
