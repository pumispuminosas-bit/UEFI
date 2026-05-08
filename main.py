import argparse
import os
import json
import logging
import yara
from datetime import datetime
from pathlib import Path

try:
    import PyPDF2
except ImportError:
    PyPDF2 = None

try:
    import yaml
except ImportError:
    yaml = None

from unpacker import VendorUnpacker
from spoofer import SpooferEngine
from stripper import FfsNetworkStripper
from cleaner import FirmwareCleaner
from rebuilder import FirmwareRebuilder

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)
logger = logging.getLogger(__name__)

def build_parser():
    parser = argparse.ArgumentParser(
        description="Universal UEFI Sanitizer - Complete firmware analysis, detection, and remediation platform.",
        epilog="For detailed documentation, see README.md and CERTIFICATE_STEGANOGRAPHY.md"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ANALYZE command - comprehensive threat analysis
    analyze = subparsers.add_parser(
        "analyze",
        help="Comprehensive UEFI firmware threat analysis with YARA + forensic detection"
    )
    analyze.add_argument("input", help="Path to firmware image or vendor package")
    analyze.add_argument("--output-report", help="Path to write JSON threat report")
    analyze.add_argument("--yara-rules", default="implant_rules.yar", help="Path to YARA rules file")
    analyze.add_argument("--include-pdfs", action="store_true", help="Include forensic PDF reports in analysis")
    analyze.add_argument("--pdf-dir", default=".", help="Directory to search for PDF reports when --include-pdfs is enabled")
    analyze.add_argument("--vendor", default="generic", help="Vendor-specific configuration (lenovo, hp, dell, asus, generic)")
    analyze.add_argument("--verbose", action="store_true", help="Verbose threat analysis output")

    # UNPACK command
    unpack = subparsers.add_parser("unpack", help="Unpack a vendor firmware package into a raw BIOS/ROM image.")
    unpack.add_argument("input", help="Path to the vendor firmware package (.cap, .exe, .bin, .rom)")
    unpack.add_argument("output", help="Path to output raw firmware file or directory")

    # SPOOF command
    spoof = subparsers.add_parser("spoof", help="Generate spoofed identifiers for MAC, UUID, and serial numbers.")
    spoof.add_argument("--oui", help="Optional OUI prefix for generated MAC address (format 00:11:22)")
    spoof.add_argument("--fake-serial", action="store_true", help="Generate a fake serial number")

    # STRIP command - enhanced with certificate steganography
    strip_cmd = subparsers.add_parser(
        "strip",
        help="Scan and strip network-related DXE/PE modules, detect SCS implants and certificate steganography"
    )
    strip_cmd.add_argument("input", help="Path to firmware image")
    strip_cmd.add_argument("output", help="Path to write stripped firmware image")
    strip_cmd.add_argument("--threat-report", help="Path to write threat detection report (JSON)")
    strip_cmd.add_argument("--preserve-cert-chain", action="store_true", help="Attempt to preserve certificate chain")

    # CLEAN command
    clean = subparsers.add_parser("clean", help="Neutralize Intel ME or AMD PSP firmware components.")
    clean.add_argument("input", help="Path to firmware image")
    clean.add_argument("output", help="Path to write cleaned firmware image")
    clean.add_argument("--platform", choices=["intel", "amd"], required=True, help="Target platform for cleaning")

    # REBUILD command
    rebuild = subparsers.add_parser("rebuild", help="Rebuild a firmware image and recalculate checksums.")
    rebuild.add_argument("input", help="Path to the firmware image to rebuild")
    rebuild.add_argument("--output", help="Path to write rebuilt firmware image (default: final_<input>)")

    # SCAN-YARA command - dedicated YARA scanning
    yara_scan = subparsers.add_parser(
        "scan-yara",
        help="Scan firmware with YARA rules for known implant patterns"
    )
    yara_scan.add_argument("input", help="Path to firmware image")
    yara_scan.add_argument("--rules", default="implant_rules.yar", help="Path to YARA rules")
    yara_scan.add_argument("--output-json", help="Output results as JSON")

    # UNIVERSAL SANITIZE command - complete workflow
    universal = subparsers.add_parser(
        "universal-sanitize",
        help="Complete universal UEFI firmware sanitization workflow (unpack -> spoof -> strip -> clean -> rebuild)"
    )
    universal.add_argument("input", help="Path to vendor firmware package (.cap, .exe, .bin, .rom)")
    universal.add_argument("--output-dir", default="sanitized_output", help="Output directory for all results")
    universal.add_argument("--vendor", default="generic", help="Vendor configuration (lenovo, hp, dell, asus, generic)")
    universal.add_argument("--platform", choices=["intel", "amd"], help="Platform for ME/PSP cleaning (auto-detect if not specified)")
    universal.add_argument("--keep-serial", action="store_true", help="Keep original serial numbers instead of spoofing")
    universal.add_argument("--no-clean", action="store_true", help="Skip ME/PSP cleaning step")
    universal.add_argument("--flashrom-only", action="store_true", help="Only generate flashrom command, don't flash")

    return parser


class ThreatAnalyzer:
    """Comprehensive UEFI firmware threat analysis engine."""
    
    def __init__(self, firmware_path, yara_rules_path=None, vendor="generic"):
        self.firmware_path = firmware_path
        self.yara_rules_path = yara_rules_path or "implant_rules.yar"
        self.vendor = vendor
        self.firmware_data = None
        self.threats = []
        self.pdf_reports = []
        self.vendor_config = self._load_vendor_config()
        self.load_firmware()
    
    def _load_vendor_config(self):
        """Load vendor-specific configuration."""
        if yaml is None:
            logger.warning("PyYAML not installed, using default configuration")
            return {}
        
        config_path = "vendor_config.yaml"
        if not os.path.exists(config_path):
            logger.warning(f"Vendor config file {config_path} not found, using defaults")
            return {}
        
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            vendor_config = config.get('vendors', {}).get(self.vendor, {})
            logger.info(f"Loaded vendor config for {self.vendor}: {vendor_config.get('description', 'No description')}")
            return vendor_config
        except Exception as e:
            logger.error(f"Failed to load vendor config: {e}")
            return {}
    
    def load_firmware(self):
        """Load firmware binary."""
        with open(self.firmware_path, 'rb') as f:
            self.firmware_data = f.read()
        logger.info(f"Loaded firmware: {len(self.firmware_data)} bytes")
    
    def analyze_yara(self):
        """Run YARA rules against firmware."""
        try:
            rules = yara.compile(filepath=self.yara_rules_path)
            matches = rules.match(data=self.firmware_data)
            
            for match in matches:
                for string in match.strings:
                    if hasattr(string, 'instances'):
                        for instance in string.instances:
                            if isinstance(instance, tuple):
                                offset, _, value = instance
                            else:
                                offset = getattr(instance, 'offset', 0)
                                value = getattr(instance, 'data', getattr(instance, 'value', None))

                            threat = {
                                "type": "YARA",
                                "rule": match.rule,
                                "offset": hex(offset),
                                "value": str(value)
                            }
                            self.threats.append(threat)
                            logger.warning(f"YARA Match: {match.rule} at {hex(offset)}")
                    elif hasattr(string, 'offset'):
                        offset = string.offset
                        value = getattr(string, 'data', getattr(string, 'value', None))
                        threat = {
                            "type": "YARA",
                            "rule": match.rule,
                            "offset": hex(offset),
                            "value": str(value)
                        }
                        self.threats.append(threat)
                        logger.warning(f"YARA Match: {match.rule} at {hex(offset)}")
                    else:
                        offset, _, value = string
                        threat = {
                            "type": "YARA",
                            "rule": match.rule,
                            "offset": hex(offset),
                            "value": str(value)
                        }
                        self.threats.append(threat)
                        logger.warning(f"YARA Match: {match.rule} at {hex(offset)}")
            
            return len(matches)
        except Exception as e:
            logger.error(f"YARA analysis failed: {e}")
            return 0
    
    def analyze_known_implants(self):
        """Detect known implant locations."""
        stripper = FfsNetworkStripper(self.firmware_path)
        implants = stripper._scan_known_implant_locations()
        
        # Add vendor-specific known offsets
        vendor_offsets = self.vendor_config.get('known_implant_offsets', [])
        for offset in vendor_offsets:
            # Check if this offset has SCS markers
            try:
                pos = int(offset, 16) if isinstance(offset, str) else offset
                if pos < len(self.firmware_data):
                    chunk = self.firmware_data[pos:pos+0x100]
                    if b'!SCS' in chunk:
                        implants.append((pos, f"Vendor-specific implant at {hex(pos)}"))
            except (ValueError, TypeError):
                pass
        
        for offset, desc in implants:
            threat = {
                "type": "Known Implant",
                "description": desc,
                "offset": hex(offset)
            }
            self.threats.append(threat)
            logger.warning(f"Known implant: {desc} at {hex(offset)}")
        
        return len(implants)
    
    def analyze_certificate_steganography(self):
        """Detect certificate steganography."""
        stripper = FfsNetworkStripper(self.firmware_path)
        certs = stripper._scan_certificates_for_steganography(self.firmware_data)
        
        for offset, desc in certs:
            threat = {
                "type": "Certificate Steganography",
                "description": desc,
                "offset": hex(offset)
            }
            self.threats.append(threat)
        
        return len(certs)
    
    def analyze_apt_indicators(self):
        """Analyze APT-specific indicators from the case study."""
        indicators_found = 0
        
        # Firmware anomalies
        firmware_anomalies = self._check_firmware_anomalies()
        indicators_found += firmware_anomalies
        
        # Hypervisor signs
        hypervisor_signs = self._check_hypervisor_signs()
        indicators_found += hypervisor_signs
        
        # Network anomalies (basic checks)
        network_anomalies = self._check_network_anomalies()
        indicators_found += network_anomalies
        
        # Anti-forensics
        anti_forensics = self._check_anti_forensics()
        indicators_found += anti_forensics
        
        return indicators_found
    
    def _check_firmware_anomalies(self):
        """Check for firmware-level anomalies."""
        count = 0
        
        # Look for EFI PE drivers without imports (like kabini_pe.exe)
        # This is a heuristic: PE files with no imports in firmware
        pe_positions = []
        data = self.firmware_data
        i = 0
        while i < len(data) - 4:
            if data[i:i+2] == b'MZ':
                # Check if it's a PE file
                pe_offset = int.from_bytes(data[i+0x3c:i+0x40], 'little')
                if i + pe_offset + 4 < len(data) and data[i+pe_offset:i+pe_offset+4] == b'PE\x00\x00':
                    # Check for imports
                    import_rva = int.from_bytes(data[i+pe_offset+0x80:i+pe_offset+0x84], 'little')
                    if import_rva == 0:  # No imports
                        threat = {
                            "type": "Firmware Anomaly",
                            "description": "EFI PE driver without imports (potential self-contained malware)",
                            "offset": hex(i)
                        }
                        self.threats.append(threat)
                        count += 1
            i += 1
        
        return count
    
    def _check_hypervisor_signs(self):
        """Check for hypervisor-related indicators."""
        count = 0
        
        # Look for virtualization-related strings
        virt_strings = [b'hypervisor', b'virtualization', b'paravirtual', b'e820', b'acpi']
        for s in virt_strings:
            if s in self.firmware_data.lower():
                threat = {
                    "type": "Hypervisor Indicator",
                    "description": f"Virtualization-related string found: {s.decode()}",
                    "offset": hex(self.firmware_data.lower().find(s))
                }
                self.threats.append(threat)
                count += 1
        
        return count
    
    def _check_network_anomalies(self):
        """Check for network-related anomalies."""
        count = 0
        
        # Look for TR-069 related strings
        tr069_strings = [b'tr-069', b'acs', b'cwmp', b'setparameter']
        for s in tr069_strings:
            if s in self.firmware_data.lower():
                threat = {
                    "type": "Network Anomaly",
                    "description": f"TR-069/ACS related string: {s.decode()}",
                    "offset": hex(self.firmware_data.lower().find(s))
                }
                self.threats.append(threat)
                count += 1
        
        return count
    
    def _check_anti_forensics(self):
        """Check for anti-forensic techniques."""
        count = 0
        
        # Look for timestamp manipulation (zero timestamps)
        if b'\x00\x00\x00\x00' in self.firmware_data:
            threat = {
                "type": "Anti-Forensics",
                "description": "Potential timestamp manipulation (zero timestamp found)",
                "offset": hex(self.firmware_data.find(b'\x00\x00\x00\x00'))
            }
            self.threats.append(threat)
            count += 1
        
        return count

    def analyze_pdf_reports(self, pdf_dir="."):
        """Scan PDF reports for forensic keywords and evidence."""
        if PyPDF2 is None:
            logger.warning("PDF analysis skipped because PyPDF2 is not installed.")
            return 0

        pdf_root = Path(pdf_dir)
        if not pdf_root.exists() or not pdf_root.is_dir():
            logger.warning(f"PDF directory does not exist: {pdf_root}")
            return 0

        pdf_files = sorted(pdf_root.glob("*.pdf"))
        if not pdf_files:
            logger.info(f"No PDF reports found in {pdf_root}")
            return 0

        scanned = 0
        for pdf_path in pdf_files:
            try:
                reader = PyPDF2.PdfReader(str(pdf_path))
                extracted_text = []
                for page in reader.pages:
                    extracted_text.append(page.extract_text() or "")

                full_text = " ".join(extracted_text).lower()
                keywords = [
                    "scs", "uefi", "steganography", "certificate", "bootkit", "implant",
                    "rootkit", "pe", "efi", "forensic", "malware", "firmware", "smm"
                ]
                hits = sorted({kw for kw in keywords if kw in full_text})

                report_data = {
                    "file": str(pdf_path),
                    "page_count": len(reader.pages),
                    "keywords": hits,
                }
                self.pdf_reports.append(report_data)

                if hits:
                    threat = {
                        "type": "Forensic PDF Evidence",
                        "description": f"Keywords found in PDF report: {', '.join(hits)}",
                        "file": str(pdf_path)
                    }
                    self.threats.append(threat)

                scanned += 1
            except Exception as e:
                logger.error(f"Failed to parse PDF {pdf_path}: {e}")

        return scanned

    def generate_report(self):
        """Generate comprehensive threat analysis report."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "firmware": os.path.basename(self.firmware_path),
            "firmware_size": len(self.firmware_data),
            "threat_count": len(self.threats),
            "threat_level": self._calculate_threat_level(),
            "threats": self.threats,
            "pdf_reports": self.pdf_reports
        }
        return report
    
    def _calculate_threat_level(self):
        """Calculate overall threat level."""
        threat_counts = {}
        for threat in self.threats:
            threat_type = threat.get("type", "Unknown")
            threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
        
        if len(self.threats) > 100:
            return "CRITICAL"
        elif len(self.threats) > 50:
            return "HIGH"
        elif len(self.threats) > 10:
            return "MEDIUM"
        elif len(self.threats) > 0:
            return "LOW"
        else:
            return "CLEAN"


def universal_sanitize(args):
    """Complete universal UEFI firmware sanitization workflow."""
    from unpacker import FirmwareUnpacker
    from spoofer import HardwareSpoofer
    from stripper import FirmwareStripper
    from cleaner import FirmwareCleaner
    from rebuilder import FirmwareRebuilder
    from hwid_parser import HWIDParser
    import os
    import shutil
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Step 1: Auto-unpack firmware
    print("=== STEP 1: Auto-Unpacking Firmware ===")
    unpacker = FirmwareUnpacker()
    unpacked_path = os.path.join(args.output_dir, "unpacked.bin")
    unpacker.unpack(args.input, unpacked_path, args.vendor)
    
    # Step 2: HWID & NVRAM DMI Parser
    print("=== STEP 2: HWID & NVRAM DMI Parser ===")
    hwid_parser = HWIDParser()
    hwid_data = hwid_parser.parse_hwid(unpacked_path)
    print(f"Extracted HWID data: {hwid_data}")
    
    # Step 3: Spoofing Engine
    print("=== STEP 3: Spoofing Engine ===")
    spoofer = HardwareSpoofer()
    spoofed_path = os.path.join(args.output_dir, "spoofed.bin")
    spoofer.spoof(unpacked_path, spoofed_path, keep_serial=args.keep_serial)
    
    # Step 4: FFS Network & Payload Stripper
    print("=== STEP 4: FFS Network & Payload Stripper ===")
    stripper = FirmwareStripper()
    stripped_path = os.path.join(args.output_dir, "stripped.bin")
    stripper.strip(spoofed_path, stripped_path)
    
    # Step 5: Intel ME / AMD PSP Neutralizer
    if not args.no_clean:
        print("=== STEP 5: Intel ME / AMD PSP Neutralizer ===")
        cleaner = FirmwareCleaner()
        cleaned_path = os.path.join(args.output_dir, "cleaned.bin")
        
        # Auto-detect platform if not specified
        if not args.platform:
            # Simple heuristic: check for ME region signatures
            with open(stripped_path, "rb") as f:
                data = f.read(0x1000)
            if b"$MEI" in data or b"ME:" in data:
                args.platform = "intel"
            elif b"PSP" in data or b"AMD" in data:
                args.platform = "amd"
            else:
                print("Could not auto-detect platform, defaulting to Intel")
                args.platform = "intel"
        
        cleaner.clean(stripped_path, cleaned_path, args.platform)
        rebuild_input = cleaned_path
    else:
        print("=== STEP 5: SKIPPED (ME/PSP Neutralizer) ===")
        rebuild_input = stripped_path
    
    # Step 6: Firmware Rebuilder
    print("=== STEP 6: Firmware Rebuilder ===")
    rebuilder = FirmwareRebuilder()
    final_path = os.path.join(args.output_dir, "sanitized.bin")
    rebuilder.rebuild(rebuild_input, final_path)
    
    print("\n=== SANITIZATION COMPLETE ===")
    print(f"Final sanitized firmware: {final_path}")
    print(f"All intermediate files saved in: {args.output_dir}")
    
    # Copy original for comparison
    backup_path = os.path.join(args.output_dir, "original_backup.bin")
    shutil.copy2(args.input, backup_path)
    print(f"Original backup: {backup_path}")


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "analyze":
        logger.info(f"Starting comprehensive firmware analysis: {args.input}")
        analyzer = ThreatAnalyzer(args.input, args.yara_rules, args.vendor)
        
        logger.info("Running YARA analysis...")
        yara_matches = analyzer.analyze_yara()
        
        logger.info("Scanning for known implants...")
        implant_matches = analyzer.analyze_known_implants()
        
        logger.info("Detecting certificate steganography...")
        cert_matches = analyzer.analyze_certificate_steganography()
        
        logger.info("Analyzing APT-specific indicators...")
        apt_matches = analyzer.analyze_apt_indicators()
        
        pdf_matches = 0
        if args.include_pdfs:
            logger.info("Scanning forensic PDF reports...")
            pdf_matches = analyzer.analyze_pdf_reports(pdf_dir=args.pdf_dir)
        
        report = analyzer.generate_report()
        
        # Display results
        print("\n" + "=" * 70)
        print("UEFI FIRMWARE THREAT ANALYSIS REPORT")
        print("=" * 70)
        print(f"Firmware: {report['firmware']}")
        print(f"Size: {report['firmware_size']} bytes")
        print(f"Threats Found: {report['threat_count']}")
        print(f"Threat Level: {report['threat_level']}")
        print("\nDetection Summary:")
        print(f"  YARA Matches: {yara_matches}")
        print(f"  Known Implants: {implant_matches}")
        print(f"  Certificate Anomalies: {cert_matches}")
        print(f"  APT Indicators: {apt_matches}")
        if args.include_pdfs:
            print(f"  PDF Reports Scanned: {pdf_matches}")
        
        if report['threat_count'] > 0:
            print("\nTop Threats:")
            for threat in report['threats'][:10]:
                print(f"  [{threat['type']}] {threat.get('description', threat.get('rule', 'Unknown'))} @ {threat['offset']}")
        
        print("=" * 70)
        
        # Write JSON report if requested
        if args.output_report:
            with open(args.output_report, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report written to {args.output_report}")

    elif args.command == "unpack":
        unpacker = VendorUnpacker(args.input)
        unpacker.unpack(args.output)

    elif args.command == "spoof":
        spoofer = SpooferEngine()
        mac = spoofer.generate_mac(oui=args.oui)
        uuid_value = spoofer.generate_uuid()
        print(f"Generated MAC: {mac}")
        print(f"Generated UUID: {uuid_value}")
        if args.fake_serial:
            serial = spoofer.generate_fake_serial()
            print(f"Generated fake serial: {serial}")

    elif args.command == "strip":
        logger.info(f"Stripping network modules from {args.input}")
        stripper = FfsNetworkStripper(args.input)
        stripper.strip_network_modules(args.output)
        
        # Generate threat report if requested
        if args.threat_report:
            analyzer = ThreatAnalyzer(args.input)
            report = analyzer.generate_report()
            with open(args.threat_report, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Threat report written to {args.threat_report}")

    elif args.command == "clean":
        cleaner = FirmwareCleaner()
        cleaner.clean(args.input, args.output, platform=args.platform)

    elif args.command == "rebuild":
        rebuilder = FirmwareRebuilder()
        output_path = args.output if hasattr(args, 'output') and args.output else f"final_{os.path.basename(args.input)}"
        rebuilder.rebuild(args.input, output_path)

    elif args.command == "scan-yara":
        logger.info(f"YARA scanning {args.input}")
        try:
            rules = yara.compile(filepath=args.rules)
            with open(args.input, 'rb') as f:
                data = f.read()
            
            matches = rules.match(data=data)
            
            print(f"\nYARA Scan Results: {len(matches)} rule(s) matched")
            print("=" * 70)
            
            results = {}
            for match in matches:
                print(f"\nRule: {match.rule}")
                results[match.rule] = []
                for string in match.strings:
                    if hasattr(string, 'instances'):
                        for instance in string.instances:
                            if isinstance(instance, tuple):
                                offset, _, value = instance
                            else:
                                offset = getattr(instance, 'offset', 0)
                                value = getattr(instance, 'data', getattr(instance, 'value', None))

                            print(f"  Offset: {hex(offset)}, Value: {value}")
                            results[match.rule].append({
                                "offset": hex(offset),
                                "value": str(value)
                            })
                    elif hasattr(string, 'offset'):
                        offset = string.offset
                        value = getattr(string, 'data', getattr(string, 'value', None))
                        print(f"  Offset: {hex(offset)}, Value: {value}")
                        results[match.rule].append({
                            "offset": hex(offset),
                            "value": str(value)
                        })
                    else:
                        offset, _, value = string
                        print(f"  Offset: {hex(offset)}, Value: {value}")
                        results[match.rule].append({
                            "offset": hex(offset),
                            "value": str(value)
                        })
            
            if args.output_json:
                with open(args.output_json, 'w') as f:
                    json.dump(results, f, indent=2)
                logger.info(f"Results written to {args.output_json}")
        
        except Exception as e:
            logger.error(f"YARA scan failed: {e}")

    elif args.command == "verify-hash":
        import hashlib
        with open(args.input, 'rb') as f:
            data = f.read()
        
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        
        print(f"\nFirmware Hash Verification")
        print("=" * 70)
        print(f"File: {args.input}")
        print(f"MD5: {md5}")
        print(f"SHA256: {sha256}")
        
        if args.clean_hash:
            if args.clean_hash.lower() in [md5, sha256]:
                print("\n✓ Firmware matches clean image hash - VERIFIED CLEAN")
            else:
                print(f"\n✗ Firmware DOES NOT match clean image hash")
                print(f"  Expected: {args.clean_hash}")
                print(f"  Got MD5: {md5}")
                print(f"  Got SHA256: {sha256}")
        
        print("=" * 70)

    elif args.command == "universal-sanitize":
        universal_sanitize(args)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
