from Evtx.Evtx import Evtx
from pathlib import Path
import sys

if len(sys.argv) != 2:
    print("Usage: python3 scripts/parse_evtx.py <file.evtx>")
    sys.exit(1)

evtx_file = Path(sys.argv[1])

with Evtx(str(evtx_file)) as log:
    for record in log.records():
        print(record.xml())