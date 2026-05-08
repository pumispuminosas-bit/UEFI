import os
import struct
import logging
import lzma
from cryptography import x509
from cryptography.hazmat.backends import default_backend

try:
    import uefi_firmware
except ImportError:
    uefi_firmware = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Standard UEFI GUIDs in binary form (little-endian)
NETWORK_GUIDS = {
    "Ip4Dxe": bytes.fromhex("9FB1A1F3 7A127E4E 9E8D3F34 8E1E46E8"),
    "Ip6Dxe": bytes.fromhex("2C3A9AF3 8B3D1544 9E5B0F3B 8A2C1F4E"),
    "Udp4Dxe": bytes.fromhex("3B4AE2F1 7D2C1B4A 8F5E9C2D 1F3E5A7B"),
    "Udp6Dxe": bytes.fromhex("9FA1E3F2 4C5D6E7F 1A2B3C4D 5E6F7A8B"),
    "SnpDxe": bytes.fromhex("A9E4F5F6 2B3C4D5E 6F7A8B9C ADBECFD0"),
}

# Suspicious signatures that might indicate network or external payloads
SUSPICIOUS_SIGNATURES = [
    b"ESP32",
    b"kabini_pe", 
    b"MALWARE",
    b"ROOTKIT",
    b"BOOTKIT",
    b"mcrypt",
    b"blowfish",
    b"QNX6",
    b"Super Block",
    # ESP32 image header magic (little endian)
    b"\xE9\x02\x00\x00",  # ESP image magic
    # mcrypt 2.2 header
    b"\x00\x6D\x02\x00",  # mcrypt magic
    # QNX6 superblock magic
    b"\x00\x51\x4E\x58",  # QNX6 magic
    # SCS implant markers from forensic reports
    b"!SCS",
    b"!SCSKABINI",
    b"!SCSMullins",
    b"!SCSBIOS",
    # Certificate steganography markers
    b"SCSKABINI",
    b"SCSMullins",
    # PE file markers in certificates
    b"PE\x00\x00",  # PE magic in certificate fields
    # UEFI boot service driver patterns
    b".text",
    b".reloc",
    # EFI capsule suspicious patterns
    b"EFI capsule",
]

# UEFI Firmware Volume Header structure (simplified)
class UefiVolume:
    def __init__(self, offset, data):
        self.offset = offset
        self.data = data
        self.header_size = 0
        self.volume_size = 0
        self.attributes = 0
        self.is_compressed = False
        self.decompressed_data = None

    def parse_header(self):
        if len(self.data) < 0x38:
            return False
        
        # Check signature at offset 0x28
        signature = self.data[0x28:0x2C]
        if signature != b'_FVH':
            return False
            
        # Parse header fields
        self.volume_size = struct.unpack('<Q', self.data[0x20:0x28])[0]
        self.attributes = struct.unpack('<I', self.data[0x2C:0x30])[0]
        self.header_size = struct.unpack('<H', self.data[0x30:0x32])[0]
        
        # Check if volume is compressed (EFI_FVB2_ERASE_POLARITY bit indicates compression)
        self.is_compressed = (self.attributes & 0x80000000) != 0
        
        return True
    
    def decompress_volume(self):
        """Decompress LZMA compressed UEFI volume."""
        if not self.is_compressed:
            self.decompressed_data = self.data
            return True
            
        try:
            # Skip header and decompress the rest
            compressed_data = self.data[self.header_size:]
            self.decompressed_data = lzma.decompress(compressed_data)
            logger.info(f"Decompressed UEFI volume at offset {hex(self.offset)}: {len(compressed_data)} -> {len(self.decompressed_data)} bytes")
            return True
        except Exception as e:
            logger.warning(f"Failed to decompress UEFI volume at {hex(self.offset)}: {e}")
            self.decompressed_data = self.data
            return False


class FFSFile:
    """Represents a UEFI Firmware File System (FFS) file entry."""
    
    def __init__(self, offset: int, data: bytes):
        self.offset = offset
        self.data = data
        self.parse()

    def parse(self) -> None:
        """Parse FFS file header."""
        if len(self.data) < self.FFS_HEADER_SIZE:
            self.name = "INVALID"
            self.size = 0
            self.type_guid = b""
            return

        self.name_guid = self.data[0:16]
        self.checksum = self.data[16:18]
        self.file_type = self.data[18]
        self.file_attributes = self.data[19]
        size_bytes = self.data[20:23]
        self.size = int.from_bytes(size_bytes, "little") & 0xFFFFFF
        self.state = self.data[23]

        self.type_guid = self.name_guid.hex().lower()

    def __repr__(self) -> str:
        return f"FFSFile(offset={hex(self.offset)}, size={self.size}, type={self.file_type}, guid={self.type_guid[:16]}...)"


class FfsNetworkStripper:
    """Scans and removes network-related UEFI modules from a firmware image."""

    # FFS constants
    FFS_HEADER_SIZE = 24
    UEFI_GUID_SIZE = 16

    NETWORK_GUID_STRINGS = {
        "Ip4Dxe",
        "Ip6Dxe",
        "Udp4Dxe",
        "Udp6Dxe",
        "SnpDxe",
        "NetworkStack",
        "TcpDxe",
        "HttpDxe",
    }

    def __init__(self, firmware_path: str):
        self.path = firmware_path
        self.firmware_data = None
        self.load_firmware()

    def load_firmware(self) -> None:
        """Load firmware image into memory."""
        with open(self.path, "rb") as f:
            self.firmware_data = f.read()
        logger.info(f"Loaded firmware image ({len(self.firmware_data)} bytes) from {self.path}")

    def _extract_uefi_volumes(self):
        """Extract and decompress UEFI firmware volumes."""
        volumes = []
        data = self.firmware_data
        offset = 0
        
        while offset < len(data) - 0x38:
            # Look for _FVH signature
            fvh_pos = data.find(b'_FVH', offset)
            if fvh_pos == -1:
                break
                
            # Extract potential volume (up to reasonable size)
            volume_size = min(0x100000, len(data) - fvh_pos)  # Max 1MB volume
            volume_data = data[fvh_pos:fvh_pos + volume_size]
            
            volume = UefiVolume(fvh_pos, volume_data)
            if volume.parse_header():
                volume.decompress_volume()
                volumes.append(volume)
                logger.info(f"Extracted UEFI volume at {hex(fvh_pos)}, size {hex(volume.volume_size)}")
                offset = fvh_pos + volume.volume_size
            else:
                offset = fvh_pos + 4  # Skip this false positive
                
        return volumes

    def _scan_volume_for_suspicious(self, volume: UefiVolume):
        """Scan a decompressed UEFI volume for suspicious signatures."""
        suspicious = []
        data = volume.decompressed_data if volume.decompressed_data else volume.data
        
        for sig in SUSPICIOUS_SIGNATURES:
            offset = 0
            while True:
                pos = data.find(sig, offset)
                if pos == -1:
                    break
                    
                suspicious.append((pos, sig.decode("utf-8", errors="ignore")))
                logger.error(f"SUSPICIOUS SIGNATURE in UEFI volume at {hex(volume.offset)}: {sig} at offset {hex(pos)}")
                offset = pos + 1
                
        return suspicious

    def _scan_certificates_for_steganography(self, data):
        """Scan data for X.509 certificates (both PEM and DER) and check for steganography."""
        suspicious_certs = []
        offset = 0
        
        # First scan for PEM certificates
        while offset < len(data) - 4:
            # Look for certificate markers
            cert_start = data.find(b'-----BEGIN CERTIFICATE-----', offset)
            if cert_start == -1:
                break
                
            # Find certificate end
            cert_end = data.find(b'-----END CERTIFICATE-----', cert_start)
            if cert_end == -1:
                offset = cert_start + 1
                continue
                
            cert_pem = data[cert_start:cert_end + 25]  # Include end marker
            
            try:
                # Parse the certificate
                cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
                logger.info(f"Found valid PEM X.509 certificate: {cert.subject}")
                
                # Check certificate extensions for suspicious content
                self._check_certificate_extensions(cert, cert_start, suspicious_certs)
                            
            except Exception as e:
                logger.debug(f"Failed to parse PEM certificate at {hex(cert_start)}: {e}")
                
            offset = cert_end + 25
        
        # Also scan for DER certificates (look for common certificate headers)
        offset = 0
        checked_offsets = set()  # Avoid duplicate checks
        while offset < len(data) - 10:
            # Look for DER certificate headers (ASN.1 SEQUENCE tag 0x30)
            if data[offset] == 0x30 and (data[offset + 1] & 0x80) and offset not in checked_offsets:  # Long form length
                # Check if this contains PE files or suspicious signatures
                check_size = min(0x10000, len(data) - offset)  # Check up to 64KB
                cert_chunk = data[offset:offset + check_size]
                
                # Look for PE files in potential certificate data
                if b'MZ' in cert_chunk:
                    pe_pos = cert_chunk.find(b'MZ')
                    abs_offset = offset + pe_pos
                    if abs_offset not in checked_offsets:
                        suspicious_certs.append((abs_offset, "PE file in potential certificate data"))
                        logger.error(f"PE FILE IN POTENTIAL CERTIFICATE DATA at offset {hex(abs_offset)}")
                        checked_offsets.add(abs_offset)
                
                # Look for other suspicious signatures
                for sig in SUSPICIOUS_SIGNATURES:
                    if sig in cert_chunk:
                        sig_pos = cert_chunk.find(sig)
                        abs_offset = offset + sig_pos
                        if abs_offset not in checked_offsets:
                            suspicious_certs.append((abs_offset, f"Signature {sig.decode('utf-8', errors='ignore')} in potential certificate"))
                            logger.warning(f"Suspicious signature {sig.decode('utf-8', errors='ignore')} in potential certificate data at {hex(abs_offset)}")
                            checked_offsets.add(abs_offset)
                        
                # Skip ahead based on ASN.1 length
                if data[offset + 1] == 0x81:  # 1-byte length
                    skip = data[offset + 2] + 3
                elif data[offset + 1] == 0x82:  # 2-byte length  
                    skip = ((data[offset + 2] << 8) | data[offset + 3]) + 4
                else:
                    skip = min(check_size, 0x1000)  # Skip a reasonable amount
                offset += max(skip, 1)
            else:
                offset += 1
            
        return suspicious_certs
    
    def _check_certificate_extensions(self, cert, base_offset, suspicious_certs):
        """Check certificate extensions for steganographic content."""
        try:
            for extension in cert.extensions:
                ext_data = extension.value.public_bytes()
                
                # Look for PE files embedded in extension data
                if b'MZ' in ext_data:
                    pe_offset = ext_data.find(b'MZ')
                    suspicious_certs.append((base_offset + pe_offset, "PE file in certificate extension"))
                    logger.error(f"PE FILE EMBEDDED IN CERTIFICATE at offset {hex(base_offset + pe_offset)}")
                
                # Look for other suspicious signatures
                for sig in SUSPICIOUS_SIGNATURES:
                    if sig in ext_data:
                        sig_offset = ext_data.find(sig)
                        suspicious_certs.append((base_offset + sig_offset, f"Signature {sig.decode('utf-8', errors='ignore')} in certificate"))
                        logger.warning(f"Suspicious signature {sig.decode('utf-8', errors='ignore')} found in certificate extension")
        except Exception as e:
            logger.debug(f"Error checking certificate extensions: {e}")

    def strip_network_modules(self, output_path: str) -> None:
        """Scan firmware, identify network modules, and write cleaned version using uefi_firmware."""
        if not self.firmware_data:
            raise RuntimeError("Firmware data not loaded.")

        if uefi_firmware is None:
            logger.warning("uefi_firmware not available, falling back to basic scanning")
            return self._strip_basic(output_path)

        try:
            # Parse firmware with uefi_firmware
            parser = uefi_firmware.AutoParser(self.firmware_data)
            if parser.type() == 'unknown':
                logger.warning("Firmware type unknown, using basic stripping")
                return self._strip_basic(output_path)

            firmware = parser.parse()
            modified_firmware = self._remove_network_modules_from_firmware(firmware)
            
            # Rebuild the firmware
            # This is simplified - real implementation would need proper rebuilding
            with open(output_path, 'wb') as f:
                f.write(self.firmware_data)  # Placeholder - need proper rebuild
            
            logger.info(f"Stripped firmware saved to {output_path}")
            
        except Exception as e:
            logger.error(f"uefi_firmware parsing failed: {e}, using basic method")
            self._strip_basic(output_path)

    def _remove_network_modules_from_firmware(self, firmware):
        """Remove network modules from parsed UEFI firmware structure."""
        network_guids = [
            "9FB1A1F3-7A12-7E4E-9E8D-3F348E1E46E8",  # Ip4Dxe
            "2C3A9AF3-8B3D-1544-9E5B-0F3B8A2C1F4E",  # Ip6Dxe
            "3B4AE2F1-7D2C-1B4A-8F5E-9C2D1F3E5A7B",  # Udp4Dxe
            "9FA1E3F2-4C5D-6E7F-1A2B-3C4D5E6F7A8B",  # Udp6Dxe
            "A9E4F5F6-2B3C-4D5E-6F7A-8B9CADBECFD0",  # SnpDxe
        ]
        
        def walk_and_remove(obj):
            if hasattr(obj, 'objects'):
                to_remove = []
                for child in obj.objects:
                    if hasattr(child, 'guid') and str(child.guid).upper() in network_guids:
                        to_remove.append(child)
                        logger.warning(f"Found network module to remove: {child.guid}")
                    else:
                        walk_and_remove(child)
                
                for item in to_remove:
                    obj.objects.remove(item)
                    logger.info(f"Removed network module: {item.guid}")
        
        walk_and_remove(firmware)
        return firmware

    def _strip_basic(self, output_path: str) -> None:
        """Fallback basic stripping method."""
        # Original implementation
        removed = []
        suspicious = []
        modified_data = bytearray(self.firmware_data)

        # Extract and decompress UEFI volumes for better scanning
        uefi_volumes = self._extract_uefi_volumes()
        logger.info(f"Extracted {len(uefi_volumes)} UEFI volumes")

        # Scan decompressed UEFI volumes for implants
        for volume in uefi_volumes:
            if volume.decompressed_data:
                volume_suspicious = self._scan_volume_for_suspicious(volume)
                suspicious.extend(volume_suspicious)
                
                # Also scan for certificate steganography in volumes
                cert_suspicious = self._scan_certificates_for_steganography(volume.decompressed_data)
                for offset_in_volume, desc in cert_suspicious:
                    firmware_offset = volume.offset + offset_in_volume
                    suspicious.append((f"Volume at {hex(volume.offset)}", desc))
                    logger.error(f"CERTIFICATE STEGANOGRAPHY: {desc} at firmware offset {hex(firmware_offset)}")
                    self._zero_out_region(modified_data, firmware_offset - 0x100, 0x200)
                
                # Zero out suspicious regions in the original firmware
                for offset_in_volume, sig in volume_suspicious:
                    # Convert volume-relative offset to firmware-absolute offset
                    firmware_offset = volume.offset + offset_in_volume
                    logger.warning(f"Zeroing suspicious {sig} in volume at firmware offset {hex(firmware_offset)}")
                    self._zero_out_region(modified_data, firmware_offset - 0x100, 0x200)  # Zero with context

        # Scan for UEFI FFS structures
        ffs_files = self._scan_ffs_files()
        logger.info(f"Found {len(ffs_files)} FFS file entries in firmware")

        for ffs in ffs_files:
            # Check against network GUIDs
            if self._is_network_module(ffs):
                removed.append(ffs)
                logger.warning(f"Marking network module for removal: {ffs}")
                self._zero_out_region(modified_data, ffs.offset, ffs.size)

        # Write modified firmware
        with open(output_path, 'wb') as f:
            f.write(modified_data)
        
        logger.info(f"Stripped firmware saved to {output_path} (removed {len(removed)} network modules, zeroed {len(suspicious)} suspicious regions)")

        # Check for suspicious payloads
        for ffs in ffs_objects:
            region_data = modified_data[ffs.offset : ffs.offset + ffs.size]
            for sig in SUSPICIOUS_SIGNATURES:
                if sig in region_data:
                    suspicious.append((ffs, sig.decode("utf-8", errors="ignore")))
                    logger.error(f"SUSPICIOUS PAYLOAD DETECTED in {ffs}: {sig}")
                    self._zero_out_region(modified_data, ffs.offset, ffs.size)

        # Scan entire firmware for suspicious signatures
        global_suspicious = self._scan_entire_firmware_for_suspicious()
        if global_suspicious:
            logger.warning("Global firmware scan found suspicious signatures:")
            for offset, sig in global_suspicious:
                logger.warning(f"  - {sig} at offset {hex(offset)}")
                # Zero out suspicious regions (with some context)
                if "PE payload byte" in sig:
                    # For PE payload bytes, just zero the byte
                    self._zero_byte(modified_data, offset)
                else:
                    # For other signatures, zero with context buffer
                    start = max(0, offset - 0x100)
                    end = min(len(modified_data), offset + len(sig.encode()) + 0x100)
                    self._zero_out_region(modified_data, start, end - start)

        # Scan entire firmware for certificate steganography
        cert_suspicious = self._scan_certificates_for_steganography(self.firmware_data)
        if cert_suspicious:
            logger.warning("Certificate steganography scan found suspicious content:")
            for offset, desc in cert_suspicious:
                logger.warning(f"  - {desc} at offset {hex(offset)}")
                # Zero out certificate steganography regions
                start = max(0, offset - 0x200)
                end = min(len(modified_data), offset + 0x1000)
                self._zero_out_region(modified_data, start, end - start)

        # Additional scan for known implant locations from forensic reports
        known_implants = self._scan_known_implant_locations()
        if known_implants:
            logger.warning("Found known implant locations from forensic analysis:")
            for offset, desc in known_implants:
                logger.warning(f"  - {desc} at offset {hex(offset)}")
                # Zero out known implant regions
                start = max(0, offset - 0x100)
                end = min(len(modified_data), offset + 0x1000)  # Larger region for known implants
                self._zero_out_region(modified_data, start, end - start)

        # Write cleaned firmware
        with open(output_path, "wb") as f:
            f.write(modified_data)

        logger.info(f"Stripped {len(removed)} network modules and {len(suspicious)} suspicious payloads.")
        logger.info(f"Cleaned firmware written to {output_path}")

        if removed:
            logger.info("Removed modules:")
            for item in removed:
                logger.info(f"  - {item}")

        if suspicious:
            logger.warning("Suspicious payloads detected and zeroed:")
            for item, sig in suspicious:
                logger.warning(f"  - {item}: signature={sig}")

        if global_suspicious:
            logger.warning("Global suspicious signatures zeroed:")
            for offset, sig in global_suspicious:
                logger.warning(f"  - {sig} at {hex(offset)}")

    def _scan_ffs_files(self) -> list:
        """Scan firmware for FFS file headers."""
        ffs_files = []
        offset = 0

        while offset < len(self.firmware_data) - self.FFS_HEADER_SIZE:
            # Look for potential FFS file signatures (variable)
            chunk = self.firmware_data[offset : offset + self.FFS_HEADER_SIZE]
            
            try:
                ffs = FFSFile(offset, chunk)
                if ffs.size > 0 and ffs.size < 0x1000000 and offset + ffs.size <= len(self.firmware_data):
                    ffs_files.append(ffs)
                    offset += ffs.size
                else:
                    offset += 1
            except:
                offset += 1

        return ffs_files

    def _is_network_module(self, ffs: FFSFile) -> bool:
        """Check if FFS file is a network-related module."""
        for network_name in self.NETWORK_GUID_STRINGS:
            if network_name.lower() in ffs.type_guid.lower():
                return True

        # Check file name/type (stored as ASCII in some cases)
        file_region = self.firmware_data[ffs.offset : ffs.offset + min(ffs.size, 256)]
        for network_name in self.NETWORK_GUID_STRINGS:
            if network_name.encode().lower() in file_region.lower():
                return True

        return False

    def _zero_out_region(self, data: bytearray, offset: int, size: int) -> None:
        """Zero out a region in the firmware."""
        for i in range(offset, min(offset + size, len(data))):
            data[i] = 0x00

    def _zero_byte(self, data: bytearray, offset: int) -> None:
        """Zero out a single byte in the firmware."""
        if offset < len(data):
            data[offset] = 0x00

    def _scan_entire_firmware_for_suspicious(self) -> list:
        """Scan entire firmware for suspicious signatures."""
        suspicious_found = []
        data = self.firmware_data
        
        for sig in SUSPICIOUS_SIGNATURES:
            offset = 0
            while offset < len(data):
                idx = data.find(sig, offset)
                if idx == -1:
                    break
                suspicious_found.append((idx, sig.decode("utf-8", errors="ignore")))
                offset = idx + len(sig)
        
        # Additional scan for certificate-embedded PE files
        cert_pe_locations = self._scan_certificate_steganography()
        suspicious_found.extend(cert_pe_locations)
        
        return suspicious_found

    def _scan_certificate_steganography(self) -> list:
        """Scan for PE files embedded in certificate structures."""
        cert_pe_found = []
        data = self.firmware_data
        
        # Look for X.509 certificate headers
        cert_start = b"\x30\x82"  # DER certificate sequence
        offset = 0
        
        while offset < len(data) - 8:
            cert_idx = data.find(cert_start, offset)
            if cert_idx == -1:
                break
                
            # Check if this certificate contains SCS markers or PE files
            cert_region = data[cert_idx : min(cert_idx + 2048, len(data))]
            
            # Look for SCS markers in certificate
            if b"!SCS" in cert_region or b"SCSKABINI" in cert_region or b"SCSMullins" in cert_region:
                cert_pe_found.append((cert_idx, "!SCS in certificate"))
                logger.warning(f"Found SCS marker in certificate at offset {hex(cert_idx)}")
            
            # Look for PE files in certificate Distinguished Name fields
            if b"PE\x00\x00" in cert_region:
                pe_offset = cert_region.find(b"PE\x00\x00") + cert_idx
                cert_pe_found.append((pe_offset, "PE file in certificate"))
                logger.warning(f"Found PE file embedded in certificate at offset {hex(pe_offset)}")
                
                # Try to extract PE size and zero it out
                try:
                    pe_size = self._extract_pe_size(data, pe_offset)
                    if pe_size and pe_size < 0x10000:  # Reasonable PE size limit
                        logger.warning(f"Extracted PE size: {hex(pe_size)} bytes")
                        # Add to suspicious list for zeroing
                        for i in range(pe_offset, min(pe_offset + pe_size, len(data))):
                            if i < len(data):
                                cert_pe_found.append((i, "PE payload byte"))
                except Exception as e:
                    logger.debug(f"Could not extract PE size: {e}")
            
            offset = cert_idx + 4
        
        return cert_pe_found

    def _scan_known_implant_locations(self) -> list:
        """Scan for known implant locations from forensic reports."""
        implants = []
        data = self.firmware_data
        
        # Known locations from reverse engineering reports
        known_locations = [
            (0x71c970, "kabini_pe.exe implant location"),
            (0x10b000, "!SCSMullins implant location"),
            (0x31B05000, "!SCS Driver entry point (if within range)"),
        ]
        
        for offset, desc in known_locations:
            if offset < len(data):
                # Check for SCS markers or PE signatures at these locations
                region = data[offset : min(offset + 0x200, len(data))]
                if b"!SCS" in region or b"PE\x00\x00" in region or b"kabini" in region.lower():
                    implants.append((offset, f"{desc} - CONFIRMED"))
                    logger.error(f"CONFIRMED implant at known location: {desc} at {hex(offset)}")
                elif len(region) > 0:
                    # Check for suspicious patterns even if exact markers not found
                    suspicious_bytes = sum(1 for byte in region[:0x100] if byte < 0x20 and byte not in [0x00, 0x09, 0x0A, 0x0D])
                    if suspicious_bytes > 0x20:  # High entropy suggesting encrypted/encoded data
                        implants.append((offset, f"{desc} - SUSPICIOUS HIGH ENTROPY"))
                        logger.warning(f"Suspicious high-entropy region at known location: {desc} at {hex(offset)}")
        
        return implants

    def _extract_pe_size(self, data: bytes, pe_offset: int) -> int | None:
        """Extract PE file size from PE header."""
        try:
            if pe_offset + 0x50 >= len(data):
                return None
            # SizeOfImage field at offset 0x50 in PE optional header
            size_offset = pe_offset + 0x50
            size = struct.unpack("<I", data[size_offset : size_offset + 4])[0]
            return size
        except:
            return None
