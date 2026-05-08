# Universal UEFI Sanitizer

A comprehensive firmware analysis, detection, and remediation platform for UEFI firmware sanitization.

## Features

### 6-Step Universal Sanitization Workflow
1. **Auto-Unpack**: Automatically unpack vendor firmware packages (.cap, .exe, .bin, .rom) using biosutilities
2. **HWID & NVRAM DMI Parser**: Extract hardware identifiers using CHIPSEC framework
3. **Spoofing Engine**: Generate spoofed MAC addresses, UUIDs, and serial numbers
4. **FFS Network & Payload Stripper**: Remove network-related DXE/PE modules using uefi_firmware
5. **Intel ME / AMD PSP Neutralizer**: Neutralize Intel ME (using me_cleaner) or AMD PSP regions
6. **Firmware Rebuilder**: Rebuild SPI image with recalculated checksums and generate flashrom commands

## Quick Start

```bash
# Complete universal sanitization in one command
python main.py universal-sanitize firmware.exe --vendor lenovo --output-dir sanitized_output
```

## Installation

```bash
# Clone the repository
git clone https://github.com/your-repo/UEFI.git
cd UEFI

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install biosutilities uefi_firmware me_cleaner chipsec pyyaml tqdm
```

## Usage

### Complete Universal Sanitization
```bash
python main.py universal-sanitize firmware.exe --vendor lenovo --output-dir sanitized_output
```

### Individual Commands
```bash
# Analyze firmware for threats
python main.py analyze firmware.bin --output-report report.json

# Unpack vendor firmware
python main.py unpack firmware.exe output.bin

# Generate spoofed identifiers
python main.py spoof --oui 00:11:22

# Strip network modules
python main.py strip firmware.bin cleaned.bin

# Clean ME/PSP regions
python main.py clean firmware.bin cleaned.bin --platform intel

# Rebuild firmware
python main.py rebuild firmware.bin final.bin

# YARA scanning
python main.py scan-yara firmware.bin

# Hash verification
python main.py verify-hash firmware.bin --clean-hash <expected_hash>
```

## Command Options

### universal-sanitize
- `--output-dir`: Directory for all intermediate and final results (default: sanitized_output)
- `--vendor`: Vendor-specific configuration (lenovo, hp, dell, asus, generic)
- `--platform`: Force platform for ME/PSP cleaning (intel/amd, auto-detect if not specified)
- `--keep-serial`: Preserve original serial numbers instead of spoofing
- `--no-clean`: Skip ME/PSP neutralization step
- `--flashrom-only`: Only generate flashrom command without flashing

## Dependencies

- **biosutilities**: Vendor-specific firmware unpacking
- **uefi_firmware**: UEFI structure parsing and manipulation
- **me_cleaner**: Intel ME neutralization
- **CHIPSEC**: Platform security framework for HWID access
- **PyYAML**: Configuration management
- **tqdm**: Progress indicators

## Security Warning

⚠️ **Flashing firmware can brick your device if done incorrectly!**

- Always backup your current firmware
- Test on non-production hardware first
- Verify checksums before flashing
- Use the generated flashrom commands at your own risk

## Architecture

The tool follows a modular architecture with separate components for each sanitization step:

- `unpacker.py`: Firmware unpacking logic
- `spoofer.py`: Hardware identifier spoofing
- `stripper.py`: Network module removal
- `cleaner.py`: ME/PSP neutralization
- `rebuilder.py`: Firmware rebuilding and checksum calculation
- `hwid_parser.py`: Hardware identifier extraction
- `vendor_config.yaml`: Vendor-specific configurations

## Vendor Support

Currently supported vendors:
- `lenovo` - Lenovo firmware with known implant offsets
- `hp` - HP firmware (SoftPaq format)
- `dell` - Dell firmware (.exe/.hdr)
- `asus` - ASUS firmware (.cap)
- `generic` - Generic UEFI firmware (default)

Usage: `python main.py analyze firmware.bin --vendor lenovo`

## Detection Features

### Threat Analysis
- **YARA Rules**: Custom rules for implant detection
- **Certificate Steganography**: Detect hidden data in certificates
- **APT Indicators**: Hypervisor signs, network anomalies, anti-forensics
- **PDF Report Integration**: Automatic scanning of forensic PDF files
- **Firmware Anomalies**: EFI PE files without imports, virtualization markers

### Open Source Tool Integration
- **biosutilities**: Vendor BIOS (.cap, .exe) unpacking
- **uefi_firmware**: UEFI FFS parsing and manipulation
- **me_cleaner**: Intel ME neutralization
- **CHIPSEC**: Hardware identifier extraction

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
- `!SCS`, `!SCSKABINI`, `!SCSMullins` - SCS implanto žymekliai
- Žinomi offset: 0x10b000 (Mullins), 0x71c970 (Kabini)

### 3. X.509 sertifikato steganografija
Detekcija malware, paslėpto sertifikatuose:
- **PEM sertifikatai**: Tekstinės formos sertifikato analizavimas
- **DER sertifikatai**: Dvejetainio formated sertifikato skenavimas
- **Įdėtos PE bylos**: MZ antraštės, .text/.reloc sekcijos
- **Rezultatai**: 195 įtaraus elemento šaltiniame Lenovo.bin

### 5. APT Grėsmių Indikatoriai
Remiantis sisteminio APT atvejo analize:
- **Hipervizoriaus požymiai**: e820 rezervuoti regionai, ACPI anomalijos, paravirtualizacijos indikatoriai
- **Tinklo anomalijos**: TR-069/ACS sesijos, keičiantys MAC adresai, virtualūs NIC
- **Anti-forensics**: Laiko žymų manipuliavimas, sertifikato anomalijos, atsarginių kopijų klastojimas
- **Firmware anomalijos**: Nenormalūs atminties žemėlapiai, stealth hipervizoriaus moduliai, EFI PE tvarkyklės be importų

### 6. PDF Ataskaitų Integracija
Automatiškai skenuoja forensic PDF failus darbo kataloge, ieškodamas raktažodžių apie grėsmes.
- PE section headers

## Paleidimas

```bash
# Išpakuoti vendor BIOS
python3 main.py unpack input.cap output.bin

# Sugeneruoti naujus identifikatorius
python3 main.py spoof --fake-serial

# Pašalinti tinklo modulius ir detektuoti implanatus
# (includes SCS detection + X.509 certificate steganography)
python3 main.py strip input.bin output-stripped.bin

# Neutralizuoti Intel ME arba AMD PSP
python3 main.py clean input.bin output-cleaned.bin --platform intel

# Sukurti galutinį firmware failą
python3 main.py rebuild input-cleaned.bin  # Creates final_input-cleaned.bin
```

## Detekcijos pavyzdžiai

### SCS Implanto detekcija
```
ERROR:stripper:CONFIRMED implant at known location: !SCSMullins implant location at 0x10b000
ERROR:stripper:CONFIRMED implant at known location: kabini_pe.exe implant location at 0x71c970
```

### X.509 Sertifikato Steganografija
```
ERROR:stripper:PE FILE IN POTENTIAL CERTIFICATE DATA at offset 0xac300
WARNING:stripper:Suspicious signature !SCS in potential certificate data at 0x10b000
WARNING:stripper:Suspicious signature SCSKABINI in potential certificate data at 0x71c971
```

## Dokumentacija

- [Certificate Steganography Detection](CERTIFICATE_STEGANOGRAPHY.md) - Detaliai apie X.509 steganografijos detekcijas
- Reverse Engineering Ataskaitų pagrindas: reverse.txt, reverse_2.txt

## Priklausomybės

```bash
pip install biosutilities cryptography
```
