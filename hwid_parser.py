# hwid_parser.py
import logging
import subprocess
import json

logger = logging.getLogger(__name__)

class HWIDParser:
    """Safe HWID and NVRAM parser using CHIPSEC."""

    def __init__(self):
        self.hwid_data = {}

    def parse_hwid(self):
        """Parse HWID from NVRAM using CHIPSEC."""
        try:
            # Run CHIPSEC to get UEFI variables
            result = subprocess.run([
                "python3", "-m", "chipsec_main", "-m", "common.uefi.list_uefi_variables"
            ], capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                # Parse output for relevant variables
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'SystemUuid' in line:
                        self.hwid_data['uuid'] = self._extract_uuid(line)
                    elif 'OemId' in line:
                        self.hwid_data['oem_id'] = self._extract_value(line)
                    elif 'SerialNumber' in line:
                        self.hwid_data['serial'] = self._extract_value(line)

            # Try to get MAC addresses
            self._parse_mac_addresses()

            logger.info(f"Parsed HWID data: {self.hwid_data}")
            return self.hwid_data

        except subprocess.TimeoutExpired:
            logger.error("CHIPSEC HWID parsing timed out")
            return {}
        except Exception as e:
            logger.error(f"HWID parsing failed: {e}")
            return {}

    def _extract_uuid(self, line):
        """Extract UUID from CHIPSEC output line."""
        # Example: SystemUuid = {12345678-1234-1234-1234-123456789012}
        parts = line.split('=')
        if len(parts) > 1:
            uuid_str = parts[1].strip().strip('{}')
            return uuid_str
        return None

    def _extract_value(self, line):
        """Extract value from CHIPSEC output line."""
        parts = line.split('=')
        if len(parts) > 1:
            return parts[1].strip()
        return None

    def _parse_mac_addresses(self):
        """Parse MAC addresses from system."""
        try:
            # Use CHIPSEC or system commands to get MAC
            result = subprocess.run([
                "python3", "-m", "chipsec_main", "-m", "common.bios_wp"
            ], capture_output=True, text=True, timeout=30)

            # This is a placeholder - actual MAC parsing would need more specific CHIPSEC modules
            self.hwid_data['mac_addresses'] = []
        except Exception as e:
            logger.warning(f"MAC address parsing failed: {e}")