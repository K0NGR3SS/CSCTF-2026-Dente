import hashlib
import struct
from pathlib import Path
from zipfile import ZipFile

from capture import tcp_packets


with ZipFile(Path(__file__).parent / "files" / "interlock-witness.zip") as archive:
    capture = archive.read("interlock.pcapng")
state = {}
witness = bytearray()
pending = None
targets = unsafe = 0
for _, source, target, _, _, adu in tcp_packets(capture):
    if not adu or 502 not in (source[1], target[1]):
        continue
    transaction, protocol, length, unit = struct.unpack_from("!HHHB", adu)
    if len(adu) != 6 + length or protocol != 0 or unit != 1:
        raise ValueError("Unexpected Modbus/TCP frame")
    pdu = adu[7:]
    if target[1] == 502:
        if pending is not None:
            raise ValueError("Unexpected pipelined request")
        pending = transaction, source, target, pdu
        continue
    if pending is None:
        raise ValueError("Response without request")
    tid, client, controller, request = pending
    pending = None
    if (tid, client, controller) != (transaction, target, source):
        raise ValueError("Mismatched response")
    if pdu[0] == request[0] | 0x80:
        continue
    if pdu[0] != request[0]:
        raise ValueError("Mismatched function code")
    start, count = struct.unpack_from("!HH", request, 1)
    if pdu[0] == 3:
        if len(pdu) != 2 + 2 * count or pdu[1] != 2 * count:
            raise ValueError("Unexpected FC03 byte count")
        data = pdu[2:]
    elif pdu[0] == 16:
        if pdu != request[:5] or request[5] != 2 * count:
            raise ValueError("Unexpected FC16 echo")
        if count == 1 and start in (0x13, 0x14):
            targets += 1
            if any(state.get(register) != 1 for register in (0x0a, 0x0b, 0x0c)):
                unsafe += 1
                witness.extend(request + pdu)
        data = request[6:]
    else:
        raise ValueError("Unexpected function code")
    words = struct.unpack(f"!{count}H", data)
    state.update((start + index, word) for index, word in enumerate(words))
if (targets, unsafe) != (120, 16):
    raise ValueError(f"Unexpected classification counts: {targets}, {unsafe}")
print("CSCTF{" + hashlib.sha256(b"INTERLOCK-WITNESS/1\0" + witness).hexdigest() + "}")
