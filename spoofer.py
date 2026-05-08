import random
import uuid
import re
from hwid_parser import HWIDParser

class SpooferEngine:
    """Generates spoofed identifiers for MAC address, UUID, and serial numbers."""

    MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}:){2}[0-9A-Fa-f]{2}$")

    def __init__(self):
        self.hwid_parser = HWIDParser()
        self.current_hwid = {}

    def load_current_hwid(self):
        """Load current HWID data."""
        self.current_hwid = self.hwid_parser.parse_hwid()
        return self.current_hwid

    def generate_mac(self, oui: str | None = None) -> str:
        if oui:
            if not self.MAC_REGEX.match(oui):
                raise ValueError("OUI must be formatted as XX:XX:XX")
            prefix = oui.lower()
        else:
            prefix = ":".join(f"{random.randrange(0, 256):02x}" for _ in range(3))

        mac_bytes = [int(x, 16) for x in prefix.split(":")]
        mac_bytes[0] &= 0xFE
        mac_bytes[0] |= 0x02
        suffix = [random.randrange(0, 256) for _ in range(3)]
        full_mac = mac_bytes + suffix
        return ":".join(f"{b:02x}" for b in full_mac)

    def generate_uuid(self) -> str:
        return str(uuid.uuid4())

    def generate_fake_serial(self) -> str:
        return f"FAKE-{random.randrange(10_000_000, 99_999_999)}"

    def generate_spoofed_hwid(self, keep_serial=False):
        """Generate complete spoofed HWID set."""
        spoofed = {
            'uuid': self.generate_uuid(),
            'mac': self.generate_mac(),
            'serial': self.current_hwid.get('serial') if keep_serial else self.generate_fake_serial(),
            'oem_id': self.current_hwid.get('oem_id', 'SPOOFED')
        }
        return spoofed
