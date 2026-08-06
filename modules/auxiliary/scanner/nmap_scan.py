"""Run nmap and import its XML findings into the workspace store.

This module shells out to an existing nmap binary; it does not try to
replace nmap. The value is persistence: open ports, service guesses, and
the raw XML all land in the workspace so later modules can read them via
self.framework.store.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path

from core.module import AuxiliaryModule
from core.options import OptBool, OptInt, OptString

from modules.auxiliary.scanner.nmap_import import _import_results, parse_nmap_xml


class NmapScan(AuxiliaryModule):
    name = "nmap Scan + Import"
    description = """
        Runs nmap against the target spec and imports the XML results into
        the workspace store. Open services, OS detection (-O), and NSE
        script output (-sC / -A) are imported. Requires the nmap binary on
        PATH. Default args are -sS -sV; adjust with NMAP_ARGS. The raw XML
        is saved as loot for evidence.
    """
    authors = ["you"]

    def register_options(self):
        self.options.add(OptString("RHOSTS", required=True,
                                   description="nmap target spec "
                                               "(CIDR, range, hostname)"))
        self.options.add(OptString("NMAP_ARGS", default="-sS -sV",
                                   description="Extra nmap arguments"))
        self.options.add(OptInt("TIMEOUT", default=300,
                                description="Seconds to wait for nmap"))
        self.options.add(OptBool("SAVE_LOOT", default=True,
                                 description="Store the raw XML as loot"))

    def run(self):
        if not shutil.which("nmap"):
            self.print_error("nmap binary not found on PATH")
            return

        targets = str(self.get_option("RHOSTS")).strip()
        extra = str(self.get_option("NMAP_ARGS") or "").strip()
        timeout = int(self.get_option("TIMEOUT"))

        cmd = ["nmap", "-oX", "-"]
        if extra:
            cmd.extend(extra.split())
        cmd.extend(targets.split())

        self.print_status(f"Running: {' '.join(cmd)}")
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            self.print_error(f"nmap timed out after {timeout}s")
            return
        except subprocess.SubprocessError as e:
            self.print_error(f"nmap failed: {e}")
            return

        if proc.returncode != 0:
            self.print_error(f"nmap exited {proc.returncode}: {proc.stderr}")
            return

        xml_text = proc.stdout
        if not xml_text or "<nmaprun" not in xml_text:
            self.print_error("nmap produced no XML output")
            return

        try:
            results = parse_nmap_xml(xml_text)
        except Exception as e:
            self.print_error(f"Failed to parse nmap XML: {e}")
            return

        store = getattr(self.framework, "store", None)
        if store is None:
            self.print_error("No workspace store available")
            return

        hosts_added, services_added, loot_added = _import_results(store, results)

        if self.get_option("SAVE_LOOT"):
            try:
                with tempfile.NamedTemporaryFile(
                        mode="w", suffix=".xml", delete=False) as tmp:
                    tmp.write(xml_text)
                    tmp_path = Path(tmp.name)
                store.add_loot_file("nmap", "nmap-scan.xml", tmp_path)
                tmp_path.unlink(missing_ok=True)
                self.print_status("Raw XML saved to loot (nmap-scan.xml)")
            except ValueError:
                store.add_loot("nmap", "nmap-scan.xml", xml_text, address="")
                self.print_status("Raw XML saved to loot (nmap-scan.xml, inline)")

        self.print_good(
            f"Imported {hosts_added} host(s), {services_added} service(s), "
            f"and {loot_added} nmap detail loot item(s) from nmap"
        )
