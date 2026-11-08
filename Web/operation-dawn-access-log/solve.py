import re
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


log = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("files") / "access.log"
request = re.compile(r'^(\S+).*?"GET (\S+) HTTP/[\d.]+" (\d{3}) .* rt=([\d.]+)$')
probe = re.compile(r"SUBSTR\(token,(\d+),1\)='(.)',SLEEP\(2\)", re.IGNORECASE)
statuses = defaultdict(set)
injectors = set()
hits = defaultdict(lambda: defaultdict(set))

for line in log.read_text(encoding="ascii").splitlines():
    match = request.match(line)
    if not match:
        continue
    address, target, status, elapsed = match.groups()
    statuses[address].add(int(status))
    for value in parse_qs(urlsplit(target).query).get("unit", []):
        test = probe.search(value)
        if test:
            injectors.add(address)
            if float(elapsed) >= 1.0:
                position, character = test.groups()
                hits[address][int(position)].add(character)

eligible = [address for address in injectors if statuses[address] == {200}]
if len(eligible) != 1:
    raise ValueError("Expected exactly one injector with only HTTP 200 responses")
positions = hits[eligible[0]]
if not positions or sorted(positions) != list(range(1, max(positions) + 1)):
    raise ValueError("The delayed requests do not cover consecutive positions")
if any(len(chars) != 1 for chars in positions.values()):
    raise ValueError("Conflicting characters for a token position")
flag = "".join(next(iter(positions[i])) for i in range(1, max(positions) + 1))
if not flag.startswith("CSCTF{") or not flag.endswith("}"):
    raise ValueError("Recovered token is not a complete flag")
print(flag)
