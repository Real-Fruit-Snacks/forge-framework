"""Workspace reporting: export hosts/services/creds/loot as Markdown or JSON.

Pure rendering functions so tests need no console. `collect` pulls the
current workspace from a Store; `render_markdown` / `render_json` format it.
"""

import json
import time
from typing import Dict

from core.store import Store


def collect(store: Store) -> Dict:
    return {
        "workspace": store.workspace,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "hosts": [dict(h) for h in store.hosts()],
        "services": [dict(s) for s in store.services()],
        "creds": [dict(c) for c in store.creds()],
        "loot": [dict(l) for l in store.loot()],
    }


def render_json(data: Dict) -> str:
    return json.dumps(data, indent=2)


def _table(headers, rows):
    rows = [[str(c) for c in row] for row in rows]
    out = ["| " + " | ".join(headers) + " |",
           "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(row) + " |" for row in rows]
    return out


def render_markdown(data: Dict) -> str:
    lines = [
        f"# Forge report: {data['workspace']}",
        "",
        f"Generated: {data['generated']}",
        "",
    ]

    services_by_host: Dict[str, list] = {}
    for s in data["services"]:
        services_by_host.setdefault(s["address"], []).append(s)

    lines.append(f"## Hosts ({len(data['hosts'])})")
    lines.append("")
    if data["hosts"]:
        for host in data["hosts"]:
            name = f" ({host['name']})" if host["name"] else ""
            lines.append(f"### {host['address']}{name}")
            services = services_by_host.get(host["address"], [])
            if services:
                lines += _table(
                    ["Port", "Proto", "Name", "Info"],
                    [(s["port"], s["proto"], s["name"], s["info"]) for s in services],
                )
            else:
                lines.append("No services recorded.")
            lines.append("")
    else:
        lines += ["None recorded.", ""]

    lines.append(f"## Credentials ({len(data['creds'])})")
    lines.append("")
    if data["creds"]:
        lines += _table(
            ["Host", "Service", "Username", "Password", "Source"],
            [(c["address"], c["service"], c["username"], c["password"], c["source"])
             for c in data["creds"]],
        )
    else:
        lines.append("None recorded.")
    lines.append("")

    lines.append(f"## Loot ({len(data['loot'])})")
    lines.append("")
    if data["loot"]:
        for entry in data["loot"]:
            host = f" @ {entry['address']}" if entry["address"] else ""
            lines.append(f"### #{entry['id']} {entry['label']} ({entry['type']}{host})")
            lines += ["", "```", entry["content"], "```", ""]
    else:
        lines.append("None recorded.")

    return "\n".join(lines)
