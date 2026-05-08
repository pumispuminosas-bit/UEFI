import os
import struct
import logging
import subprocess

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Intel Flash Descriptor constants
IFD_SIGNATURE = 0x0FF00FF0

# AMD PSP Directory Table signature
PSP_DIR_SIGNATURE = b"\x50\x50\x24\x24"


class FirmwareCleaner:
    """Neutralizes Intel ME or AMD PSP firmware regions in a firmware image."""

    def clean(self, firmware_path: str, output_path: str, platform: str) -> None:
        if platform == "intel":
            self.clean_intel_me(firmware_path, output_path)
        elif platform == "amd":
            self.clean_amd_psp(firmware_path, output_path)
        else:
            raise ValueError("Platform must be either 'intel' or 'amd'.")

    def clean_intel_me(self, firmware_path: str, output_path: str) -> None:
        """Neutralize Intel ME (Management Engine) region using me_cleaner."""
        logger.info(f"Neutralizing Intel ME in {firmware_path}")
        
        try:
            # Use me_cleaner tool
            result = subprocess.run([
                "me_cleaner.py", "-S", "-O", output_path, firmware_path
            ], capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                logger.info("Intel ME successfully neutralized using me_cleaner")
                logger.info(f"Output saved to {output_path}")
            else:
                logger.error(f"me_cleaner failed: {result.stderr}")
                # Fallback to manual method
                self._clean_intel_me_manual(firmware_path, output_path)
                
        except FileNotFoundError:
            logger.warning("me_cleaner not found, using manual ME cleaning")
            self._clean_intel_me_manual(firmware_path, output_path)
        except subprocess.TimeoutExpired:
            logger.error("me_cleaner timed out")
            self._clean_intel_me_manual(firmware_path, output_path)

    def _clean_intel_me_manual(self, firmware_path: str, output_path: str) -> None:
        """Manual Intel ME neutralization fallback."""
        logger.info(f"Loading Intel firmware from {firmware_path}")
        
        with open(firmware_path, "rb") as f:
            firmware = bytearray(f.read())

        # Look for Intel Flash Descriptor (IFD) signature at the start
        ifd_offset = self._find_ifd(firmware)
        if ifd_offset is not None:
            logger.info(f"Found Intel Flash Descriptor at offset {hex(ifd_offset)}")
            self._apply_hap_bit(firmware, ifd_offset)
            self._zero_me_region(firmware, ifd_offset)
        else:
            logger.warning("Intel Flash Descriptor not found; attempting signature-based ME region search...")
            self._find_and_zero_me_by_signature(firmware)

        with open(output_path, "wb") as f:
            f.write(firmware)
        logger.info(f"Wrote neutralized Intel ME firmware to {output_path}")

    def clean_amd_psp(self, firmware_path: str, output_path: str) -> None:
        """Neutralize AMD PSP (Platform Security Processor) region."""
        logger.info(f"Neutralizing AMD PSP in {firmware_path}")
        
        # For AMD PSP, we need to implement basic logic since psp-tool wasn't available
        # This is a simplified implementation
        with open(firmware_path, "rb") as f:
            firmware = bytearray(f.read())

        psp_dir_offset = self._find_psp_directory(firmware)
        if psp_dir_offset is not None:
            logger.info(f"Found AMD PSP Directory at offset {hex(psp_dir_offset)}")
            self._zero_psp_entries(firmware, psp_dir_offset)
        else:
            logger.warning("AMD PSP Directory not found; attempting signature-based PSP region search...")
            self._find_and_zero_psp_by_signature(firmware)

        with open(output_path, "wb") as f:
            f.write(firmware)
        logger.info(f"Wrote neutralized AMD PSP firmware to {output_path}")
        
        with open(firmware_path, "rb") as f:
            firmware = bytearray(f.read())

        # Look for AMD PSP directory signatures
        psp_dirs = self._find_psp_directories(firmware)
        if psp_dirs:
            logger.info(f"Found {len(psp_dirs)} PSP directory entries")
            for psp_offset in psp_dirs:
                self._disable_psp_region(firmware, psp_offset)
        else:
            logger.warning("No PSP directory signatures found; firmware may not be AMD platform.")

        with open(output_path, "wb") as f:
            f.write(firmware)
        logger.info(f"Wrote neutralized AMD PSP firmware to {output_path}")

    def _find_ifd(self, firmware: bytearray) -> int | None:
        """Locate Intel Flash Descriptor in firmware."""
        ifd_sig = struct.pack("<I", IFD_SIGNATURE)
        offset = firmware.find(ifd_sig)
        return offset if offset != -1 else None

    def _apply_hap_bit(self, firmware: bytearray, ifd_offset: int) -> None:
        """Set HAP (Hardware Protection) bit to disable ME."""
        try:
            pchstrap_offset = ifd_offset + 0x18
            if pchstrap_offset + 4 <= len(firmware):
                pchstrap = struct.unpack("<I", firmware[pchstrap_offset : pchstrap_offset + 4])[0]
                pchstrap |= (1 << 16)
                firmware[pchstrap_offset : pchstrap_offset + 4] = struct.pack("<I", pchstrap)
                logger.info("HAP bit set to disable Intel ME")
        except Exception as e:
            logger.warning(f"Could not apply HAP bit: {e}")

    def _zero_me_region(self, firmware: bytearray, ifd_offset: int) -> None:
        """Zero out Intel ME firmware region."""
        try:
            # Read FLMAP0 to find ME region
            flmap0_offset = ifd_offset + 0x14
            if flmap0_offset + 4 <= len(firmware):
                flmap0 = struct.unpack("<I", firmware[flmap0_offset : flmap0_offset + 4])[0]
                me_start = (flmap0 & 0xFF000000) >> 8
                me_end = me_start + 0x1000
                
                if me_end <= len(firmware):
                    logger.info(f"Zeroing ME region: {hex(me_start)} - {hex(me_end)}")
                    for i in range(me_start, me_end):
                        firmware[i] = 0x00
        except Exception as e:
            logger.warning(f"Could not zero ME region: {e}")

    def _find_and_zero_me_by_signature(self, firmware: bytearray) -> None:
        """Fallback: search for Intel ME signatures and zero them out."""
        me_signatures = [b"Intel(R) ME", b"$CPD", b"ME_VERSION"]
        for sig in me_signatures:
            offset = firmware.find(sig)
            if offset != -1:
                logger.warning(f"Found ME signature '{sig.decode('utf-8', errors='ignore')}' at {hex(offset)}")
                start = max(0, offset - 0x1000)
                end = min(len(firmware), offset + 0x10000)
                logger.info(f"Zeroing region {hex(start)} - {hex(end)}")
                for i in range(start, end):
                    firmware[i] = 0x00
                break

    def _find_psp_directories(self, firmware: bytearray) -> list:
        """Locate AMD PSP directory entries."""
        directories = []
        offset = 0
        while offset < len(firmware):
            idx = firmware.find(PSP_DIR_SIGNATURE, offset)
            if idx == -1:
                break
            directories.append(idx)
            offset = idx + 4
        return directories

    def _disable_psp_region(self, firmware: bytearray, psp_offset: int) -> None:
        """Disable PSP region by zeroing sensitive entries."""
        try:
            psp_region_start = max(0, psp_offset - 0x2000)
            psp_region_end = min(len(firmware), psp_offset + 0x5000)
            logger.info(f"Disabling PSP region at {hex(psp_offset)} (range {hex(psp_region_start)}-{hex(psp_region_end)})")
            
            # Zero out non-essential PSP entries, keeping critical ones
            for i in range(psp_region_start, psp_region_end, 4):
                if i + 4 <= len(firmware):
                    entry = struct.unpack("<I", firmware[i : i + 4])[0]
                    # Preserve certain entry types, zero others
                    if (entry & 0xFF) > 0x10:
                        firmware[i : i + 4] = b"\x00\x00\x00\x00"
        except Exception as e:
            logger.warning(f"Could not disable PSP region: {e}")
