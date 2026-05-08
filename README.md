# Universal UEFI Sanitizer

A professional firmware sanitization toolkit for UEFI BIOS images, combining vendor unpacking, HWID/NVRAM analysis, spoofing, network payload stripping, ME/PSP neutralization, and firmware rebuilding.

## Why this tool?

This repository is designed for security analysts, incident responders, and firmware engineers who need a fast, repeatable UEFI sanitization workflow with:

- Vendor-specific unpacking for HP/Dell/Lenovo/ASUS firmware
- UEFI FFS payload and network module stripping
- Hardware identifier spoofing and NVRAM metadata extraction
- Intel ME / AMD PSP neutralization support
- Rebuild and checksum-aware firmware output

## Quick Start

```bash
./setup.sh
source venv/bin/activate
./run.sh universal-sanitize firmware.bin --vendor lenovo --output-dir sanitized_output
```

## Setup

### Prerequisites

- Python 3.11+ installed
- `git` installed
- Linux / macOS recommended for firmware tooling

### One-step setup

```bash
chmod +x setup.sh run.sh
./setup.sh
```

This script will:

- create a Python virtual environment in `venv`
- install all Python dependencies from `requirements.txt`
- clone `me_cleaner` to `./me_cleaner`
- prepare the repository for quick execution

## Run the tool

After setup, use the wrapper script:

```bash
source venv/bin/activate
./run.sh universal-sanitize firmware.bin --vendor lenovo --output-dir sanitized_output
```

Or run any supported command:

```bash
./run.sh analyze firmware.bin --output-report report.json
./run.sh unpack firmware.exe raw.bin
./run.sh spoof --oui 00:11:22 --fake-serial
./run.sh strip raw.bin stripped.bin
./run.sh clean stripped.bin cleaned.bin --platform intel
./run.sh rebuild cleaned.bin final.bin
./run.sh scan-yara raw.bin --rules implant_rules.yar --output-json yara_report.json
./run.sh verify-hash final.bin --clean-hash <expected_hash>
```

## CLI Reference

### universal-sanitize
- `--output-dir`: Directory for intermediate and final artifacts (default: `sanitized_output`)
- `--vendor`: Vendor configuration (`lenovo`, `hp`, `dell`, `asus`, `generic`)
- `--platform`: Force `intel` or `amd` for ME/PSP cleaning
- `--keep-serial`: Preserve original serial numbers instead of spoofing
- `--no-clean`: Skip the ME/PSP neutralization step
- `--flashrom-only`: Generate flashrom command only, do not flash

## Repository Contents

- `main.py` — CLI entry point and workflow orchestration
- `unpacker.py` — vendor firmware unpacking
- `spoofer.py` — MAC/UUID/serial spoofing
- `stripper.py` — UEFI FFS network/payload stripping
- `cleaner.py` — Intel ME / AMD PSP neutralization
- `rebuilder.py` — firmware rebuild and checksum handling
- `hwid_parser.py` — NVRAM and HWID extraction
- `vendor_config.yaml` — vendor-specific firmware rules
- `requirements.txt` — Python dependency list
- `setup.sh` — automated environment and dependency setup
- `run.sh` — launcher wrapper for the virtual environment
- `LICENSE` — MIT license for the repository

## Dependencies

Install tools automatically via `./setup.sh`, or manually with:

```bash
python3 -m pip install -r requirements.txt
```

Required Python packages:

- `biosutilities`
- `uefi_firmware`
- `chipsec`
- `PyYAML`
- `tqdm`
- `yara-python`
- `PyPDF2`

## Notes on me_cleaner

The setup script clones `me_cleaner` into `./me_cleaner` and the tool uses that local copy when available. This ensures Intel ME neutralization works even when the tool is not installed system-wide.

## Security Warning

⚠️ Flashing firmware is dangerous.

- Always back up your original firmware
- Use non-production hardware first
- Confirm checksums before flashing
- Review generated flashrom commands carefully

## License

This project is licensed under the MIT License. See `LICENSE` for details.
