import argparse
import struct
from pathlib import Path
from zipfile import ZipFile

from pymavlink.dialects.v20 import common


PARAMETERS = ("GF_RADIUS_CM", "GF_ALTMAX_CM", "GF_OFS_E_CM",
              "GF_OFS_N_CM", "GF_MARGIN_PC")
AIRCRAFT = (1, 1)
GROUND = (255, 190)


def mavlink_messages(capture):
    """Read MAVLink from Ethernet/IPv4/UDP enhanced packets in this capture."""
    offset = 0
    while offset < len(capture):
        kind, size = struct.unpack_from("<II", capture, offset)
        if size < 12 or offset + size > len(capture):
            raise ValueError("Invalid pcapng block size")
        if kind == 6:
            captured_size, = struct.unpack_from("<I", capture, offset + 20)
            packet = capture[offset + 28:offset + 28 + captured_size]
            if packet[12:14] == b"\x08\x00" and packet[23] == 17:
                udp = 14 + 4 * (packet[14] & 15)
                length, = struct.unpack_from("!H", packet, udp + 4)
                decoder = common.MAVLink(None)
                yield from decoder.parse_buffer(packet[udp + 8:udp + length]) or ()
        offset += size


def accepts(center, state, command):
    radius, ceiling, east, north, margin = (state[name] for name in PARAMETERS)
    # The FCU rounds signed offsets to the nearest e7 unit, away from zero on ties.
    lat = center[0] + signed_offset(north)
    lon = center[1] + signed_offset(east)
    limit_cm = radius * (100 + margin) // 100
    limit_e7 = (limit_cm * 8983 + 5000) // 10000
    return ((command.x - lat) ** 2 + (command.y - lon) ** 2 <= limit_e7 ** 2
            and int(command.z) * 100 <= ceiling)


def signed_offset(value):
    rounded = (abs(value) * 8983 + 5000) // 10000
    return -rounded if value < 0 else rounded


def solve(capture):
    center = None
    provisioned, active, pending = {}, {}, {}
    active_mask = provisioned_mask = request_count = 0
    for message in mavlink_messages(capture):
        source = message.get_srcSystem(), message.get_srcComponent()
        kind = message.get_type()
        if source == AIRCRAFT and kind == "GLOBAL_POSITION_INT" and center is None:
            center = message.lat, message.lon
        elif source == GROUND and kind == "PARAM_SET":
            target = message.target_system, message.target_component
            if (target == AIRCRAFT and message.param_id in PARAMETERS
                    and message.param_type == common.MAV_PARAM_TYPE_REAL32):
                pending[message.param_id] = message.param_value
        elif source == AIRCRAFT and kind == "PARAM_VALUE":
            name = message.param_id
            if (name not in PARAMETERS or message.param_count != len(PARAMETERS)
                    or message.param_index != PARAMETERS.index(name)
                    or message.param_type != common.MAV_PARAM_TYPE_REAL32):
                continue
            value = int(message.param_value)
            if value != message.param_value:
                raise ValueError(f"Non-integral value for {name}")
            if name not in provisioned:
                provisioned[name] = active[name] = value
            elif pending.get(name) == value:
                active[name] = value
                del pending[name]
        elif source == GROUND and kind == "COMMAND_INT":
            if message.command != common.MAV_CMD_DO_REPOSITION:
                continue
            if (center is None or len(provisioned) != len(PARAMETERS)
                    or message.frame != common.MAV_FRAME_GLOBAL
                    or int(message.z) != message.z):
                raise ValueError("Unexpected reposition or missing initial state")
            active_mask |= accepts(center, active, message) << request_count
            provisioned_mask |= accepts(center, provisioned, message) << request_count
            request_count += 1
    if request_count != 22:
        raise ValueError(f"Expected 22 reposition requests, got {request_count}")
    return f"CSCTF{{active_{active_mask:06x}_provisioned_{provisioned_mask:06x}}}"


def main():
    parser = argparse.ArgumentParser(description="Reconstruct both FCU geofence masks")
    parser.add_argument("archive", nargs="?", type=Path,
                        default=Path(__file__).parent / "files" / "fence-shift.zip")
    with ZipFile(parser.parse_args().archive) as archive:
        print(solve(archive.read("mission.pcapng")))


if __name__ == "__main__":
    main()
