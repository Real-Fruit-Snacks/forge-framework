"""Import an nmap -oX XML report into the workspace store.

Does not wrap nmap; it consumes the artifact nmap already produced and
lands hosts, services, and the raw XML in the persistent workspace so
other modules can act on the findings.
"""

import xml.etree.ElementTree as ET
from pathlib import Path

from core.module import AuxiliaryModule
from core.options import OptBool, OptString


def parse_nmap_xml(xml_text):
    """Return a list of (address, hostname, services, os_matches, scripts)
    tuples from nmap XML.

    services is a list of (proto, port, name, info).
    os_matches is a list of (name, accuracy) strings from -O detection.
    scripts is a list of (target, script_id, output) for NSE output, where
    target is 'host' or '<proto>/<port>'.
    """
    results = []
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        address = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                address = addr.get("addr", "")
                break
        if not address:
            continue

        hostname = ""
        hostnames = host.find("hostnames")
        if hostnames is not None:
            for hn in hostnames.findall("hostname"):
                if hn.get("name"):
                    hostname = hn.get("name")
                    break

        services = []
        scripts = []
        ports = host.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                proto = port.get("protocol", "tcp")
                portid = int(port.get("portid", 0))
                svc = port.find("service")
                name = ""
                info_parts = []
                if svc is not None:
                    name = svc.get("name", "")
                    product = svc.get("product", "")
                    version = svc.get("version", "")
                    extra = svc.get("extrainfo", "")
                    if product:
                        info_parts.append(product)
                    if version:
                        info_parts.append(version)
                    if extra:
                        info_parts.append(extra)
                info = " ".join(info_parts)
                services.append((proto, portid, name, info))

                target = f"{proto}/{portid}"
                for script in port.findall("script"):
                    script_id = script.get("id", "")
                    output = script.get("output", "")
                    if script_id:
                        scripts.append((target, script_id, output))

        os_matches = []
        os_elem = host.find("os")
        if os_elem is not None:
            for match in os_elem.findall("osmatch"):
                name = match.get("name", "")
                accuracy = match.get("accuracy", "")
                if name:
                    os_matches.append((name, accuracy))

        hostscripts = host.find("hostscript")
        if hostscripts is not None:
            for script in hostscripts.findall("script"):
                script_id = script.get("id", "")
                output = script.get("output", "")
                if script_id:
                    scripts.append(("host", script_id, output))

        results.append((address, hostname, services, os_matches, scripts))
    return results


def _import_results(store, results, source=""):
    """Write parsed nmap results into hosts/services tables and OS/script
    details into loot."""
    hosts_added = 0
    services_added = 0
    loot_added = 0
    for address, hostname, services, os_matches, scripts in results:
        store.add_host(address, hostname)
        hosts_added += 1
        for proto, port, name, info in services:
            store.add_service(address, port, proto=proto, name=name, info=info)
            services_added += 1
        for name, accuracy in os_matches:
            label = f"{address} os"
            content = f"{name} (accuracy {accuracy}%)"
            store.add_loot("nmap-os", label, content, address=address)
            loot_added += 1
        for target, script_id, output in scripts:
            label = f"{address} {target} {script_id}"
            store.add_loot("nmap-script", label, output, address=address)
            loot_added += 1
    return hosts_added, services_added, loot_added


class NmapImport(AuxiliaryModule):
    name = "nmap XML Import"
    description = """
        Reads an nmap -oX XML file and imports live hosts, hostnames, and
        open services into the workspace store. OS detection (-O) and NSE
        script output (-sC / -A) are saved as loot (types nmap-os and
        nmap-script). The raw XML can also be saved as loot for evidence.
        This does not run nmap; use nmap_scan for that, or run nmap
        yourself and import the XML here.
    """
    authors = ["you"]

    def register_options(self):
        self.options.add(OptString("FILE", required=True,
                                   description="Path to nmap -oX XML file"))
        self.options.add(OptBool("SAVE_LOOT", default=True,
                                 description="Store the raw XML as loot"))

    def run(self):
        path = Path(str(self.get_option("FILE")))
        if not path.is_file():
            self.print_error(f"File not found: {path}")
            return

        try:
            xml_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            self.print_error(f"Failed to read {path}: {e}")
            return

        try:
            results = parse_nmap_xml(xml_text)
        except ET.ParseError as e:
            self.print_error(f"Invalid nmap XML: {e}")
            return

        store = getattr(self.framework, "store", None)
        if store is None:
            self.print_error("No workspace store available")
            return

        hosts_added, services_added, loot_added = _import_results(store, results)

        if self.get_option("SAVE_LOOT"):
            try:
                store.add_loot_file("nmap", path.name, path)
                self.print_status(f"Raw XML saved to loot ({path.name})")
                loot_added += 1
            except ValueError:
                # Store has no loot_dir; store content inline instead.
                store.add_loot("nmap", path.name, xml_text, address="")
                self.print_status(f"Raw XML saved to loot ({path.name}, inline)")
                loot_added += 1

        self.print_good(
            f"Imported {hosts_added} host(s), {services_added} service(s), "
            f"and {loot_added} nmap detail loot item(s) from nmap XML"
        )
