import os
import shutil
import struct
import logging

try:
    from biosutilities import AMI, Dell, HP, Lenovo, Phoenix
except ImportError:
    AMI = Dell = HP = Lenovo = Phoenix = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class VendorUnpacker:
    """Vendor firmware unpacker for ASUS .CAP, HP/Dell/Lenovo .exe, and raw firmware containers."""

    def __init__(self, firmware_path: str):
        self.path = firmware_path

    def detect_format(self) -> str:
        _, ext = os.path.splitext(self.path.lower())
        return ext

    def unpack(self, output_path: str) -> None:
        ext = self.detect_format()
        if ext == ".cap":
            self._unpack_cap(output_path)
        elif ext in {".bin", ".rom"}:
            shutil.copyfile(self.path, output_path)
            logger.info(f"Copied raw firmware: {output_path}")
        elif ext == ".exe":
            self._unpack_exe(output_path)
        else:
            raise ValueError(f"Unsupported firmware extension: {ext}")

    def _unpack_exe(self, output_path: str) -> None:
        """Extract raw BIOS from HP/Dell/Lenovo .exe using biosutilities."""
        if not any([AMI, Dell, HP, Lenovo]):
            raise ImportError("biosutilities not installed. Install with: pip install biosutilities")

        vendor = self._detect_vendor_from_exe()
        if vendor == "HP":
            bios = HP(self.path)
        elif vendor == "Dell":
            bios = Dell(self.path)
        elif vendor == "Lenovo":
            bios = Lenovo(self.path)
        else:
            raise ValueError(f"Could not determine vendor for .exe file: {self.path}")

        try:
            bios.extract(output_path)
            logger.info(f"Unpacked {vendor} .exe to raw firmware: {output_path}")
        except Exception as e:
            logger.error(f"Failed to unpack {vendor} .exe: {e}")
            raise

    def _detect_vendor_from_exe(self) -> str:
        """Detect vendor from .exe file content."""
        with open(self.path, "rb") as f:
            data = f.read(1024)

        # Simple heuristics
        if b"HP" in data or b"Hewlett-Packard" in data:
            return "HP"
        elif b"Dell" in data:
            return "Dell"
        elif b"Lenovo" in data:
            return "Lenovo"
        else:
            # Default to trying all
            return "HP"  # Most common

    def _unpack_exe(self, output_path: str) -> None:
        """Extract raw BIOS from vendor .exe installer using biosutilities."""
        if not biosutilities:
            raise ImportError(
                "biosutilities is required to unpack vendor .exe firmware packages. "
                "Install it with `pip install biosutilities`."
            )

        logger.info("Detecting vendor format in .exe package...")
        with open(self.path, "rb") as f:
            data = f.read()

        extracted = None

        if AMI and self._try_ami_unpack(data, output_path):
            extracted = "AMI BIOS"
        elif Dell and self._try_dell_unpack(data, output_path):
            extracted = "Dell BIOS"
        elif HP and self._try_hp_unpack(data, output_path):
            extracted = "HP BIOS"
        elif Lenovo and self._try_lenovo_unpack(data, output_path):
            extracted = "Lenovo BIOS"
        elif Phoenix and self._try_phoenix_unpack(data, output_path):
            extracted = "Phoenix BIOS"
        else:
            logger.warning("Could not identify vendor format; attempting raw binary search...")
            self._extract_by_signature(data, output_path)
            return

        logger.info(f"Successfully extracted {extracted} from {self.path} to {output_path}")

    def _try_ami_unpack(self, data: bytes, output_path: str) -> bool:
        """Attempt AMI BIOS extraction."""
        try:
            if AMI and b"$FID" in data:
                logger.info("Detected AMI firmware signature...")
                start = data.find(b"$FID")
                if start != -1:
                    with open(output_path, "wb") as f:
                        f.write(data[start:])
                    logger.info(f"Extracted AMI firmware ({len(data) - start} bytes) to {output_path}")
                    return True
        except Exception as e:
            logger.debug(f"AMI unpack failed: {e}")
        return False

    def _try_dell_unpack(self, data: bytes, output_path: str) -> bool:
        """Attempt Dell BIOS extraction."""
        try:
            if Dell and b"DellBios" in data:
                logger.info("Detected Dell firmware signature...")
                start = data.find(b"DellBios")
                if start > 0:
                    with open(output_path, "wb") as f:
                        f.write(data[start - 8:])
                    logger.info(f"Extracted Dell BIOS to {output_path}")
                    return True
        except Exception as e:
            logger.debug(f"Dell unpack failed: {e}")
        return False

    def _try_hp_unpack(self, data: bytes, output_path: str) -> bool:
        """Attempt HP BIOS extraction."""
        try:
            if HP and b"$HPBIOS$" in data:
                logger.info("Detected HP firmware signature...")
                start = data.find(b"$HPBIOS$")
                if start != -1:
                    with open(output_path, "wb") as f:
                        f.write(data[start:])
                    logger.info(f"Extracted HP BIOS to {output_path}")
                    return True
        except Exception as e:
            logger.debug(f"HP unpack failed: {e}")
        return False

    def _try_lenovo_unpack(self, data: bytes, output_path: str) -> bool:
        """Attempt Lenovo BIOS extraction."""
        try:
            if Lenovo and b"_LNVDAT_" in data:
                logger.info("Detected Lenovo firmware signature...")
                start = data.find(b"_LNVDAT_")
                if start > 0:
                    with open(output_path, "wb") as f:
                        f.write(data[start - 8:])
                    logger.info(f"Extracted Lenovo BIOS to {output_path}")
                    return True
        except Exception as e:
            logger.debug(f"Lenovo unpack failed: {e}")
        return False

    def _try_phoenix_unpack(self, data: bytes, output_path: str) -> bool:
        """Attempt Phoenix BIOS extraction."""
        try:
            if Phoenix and data.startswith(b"Phoenix") or b"Phoenix" in data[:256]:
                logger.info("Detected Phoenix firmware...")
                start = data.find(b"Phoenix")
                if start != -1:
                    with open(output_path, "wb") as f:
                        f.write(data[start - 4:])
                    logger.info(f"Extracted Phoenix BIOS to {output_path}")
                    return True
        except Exception as e:
            logger.debug(f"Phoenix unpack failed: {e}")
        return False

    def _extract_by_signature(self, data: bytes, output_path: str) -> None:
        """Fallback: search for UEFI/BIOS signatures and extract."""
        signatures = [
            (b"\x5A\x4D", "MZ (PE executable)"),
            (b"\x7F\x45\x4C\x46", "ELF executable"),
            (b"_FVH_", "UEFI Firmware Volume"),
        ]

        for sig, name in signatures:
            idx = data.find(sig)
            if idx != -1:
                logger.info(f"Found {name} at offset {hex(idx)}, extracting...")
                with open(output_path, "wb") as f:
                    f.write(data[idx:])
                logger.info(f"Extracted {len(data) - idx} bytes to {output_path}")
                return

        logger.error("Could not find recognizable BIOS/firmware signature in file.")
        raise ValueError("Unable to identify firmware format in .exe file.")
