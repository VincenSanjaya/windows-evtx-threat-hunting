from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
import sys

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}

if len(sys.argv) != 2:
    print("Usage: python3 scripts/parse_sysmon_process.py <file.evtx>")
    sys.exit(1)

evtx_file = sys.argv[1]

print("Time | EventID | Image | CommandLine | ParentImage | ParentCommandLine | User")
print("-" * 180)

with Evtx(evtx_file) as log:
    for record in log.records():
        root = ET.fromstring(record.xml())

        event_id = root.find("e:System/e:EventID", NS)

        if event_id is None or event_id.text != "1":
            continue

        time_node = root.find("e:System/e:TimeCreated", NS)
        timestamp = time_node.attrib.get("SystemTime", "-") if time_node is not None else "-"

        data = {}

        for item in root.findall("e:EventData/e:Data", NS):
            name = item.attrib.get("Name")
            value = item.text or ""
            data[name] = value

        image = data.get("Image", "-")
        command_line = data.get("CommandLine", "-")
        parent_image = data.get("ParentImage", "-")
        parent_command_line = data.get("ParentCommandLine", "-")
        user = data.get("User", "-")

        print(
            f"{timestamp} | 1 | {image} | {command_line} | "
            f"{parent_image} | {parent_command_line} | {user}"
        )