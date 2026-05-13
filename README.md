# recovery

**Zero-dependency Rust CLI tool** that scans raw disk partitions for deleted files and restores them. Supports **FAT32**, **exFAT**, **NTFS**, and **ext4**.

## Features

- Scans raw volume/partition for deleted file entries
- Recovers original filenames (LFN on FAT32, UTF-16 on exFAT/NTFS)
- Recursive directory traversal on all supported filesystems
- **Restore** deleted files (FAT32, exFAT, NTFS) — writes recovered data to a file
- **Search** by filename substring (`--search <NAME>`)
- **Physical disk scanning** (`\\.\PhysicalDriveN` on Windows, `/dev/sdX` on Linux) — probes MBR and GPT partition tables and scans all partitions
- **Zero external dependencies** — pure Rust standard library only
- Cross-platform: **Windows** (raw volume handles `\\.\D:`) and **Linux** (`/dev/sdb1`)

## Usage

```
recovery <PATH> [OPTIONS]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<PATH>` | Device or volume path |

| Windows volume | `\\.\D:` or `D:` or `D:\path` |
| Windows disk   | `\\.\PhysicalDrive0` |
| Linux          | `/dev/sdb1` |

### Options

| Option | Description |
|--------|-------------|
| `--restore <INDEX>` | Restore file at INDEX from the scan results |
| `--output <PATH>`   | Target path for the restored file |
| `--search <NAME>`   | Filter deleted files by name (case-insensitive, partial match) |
| `--help, -h`        | Print help |

### Examples

```sh
# Scan a volume
recovery \\.\E:

# Scan with a search filter
recovery D: --search .docx

# Restore a deleted file (use the index from the scan table)
recovery \\.\E: --restore 0 --output recovered_file.mp4

# Scan a physical disk (requires admin/root)
recovery \\.\PhysicalDrive0
recovery /dev/sdb
```

## Requirements

- **Windows**: Administrator privileges (for raw device access)
- **Linux**: root / sudo (for block device access)

### Important Windows Notes

- The **system drive (C:)** cannot be opened for raw access while Windows is running. Boot from a Linux Live USB or connect the drive externally via USB.
- When passing paths on Windows, use `\\.\E:` or simply `E:` — avoid `"E:\"` as the trailing backslash escapes the closing quote in cmd.exe's argument parser.
- Volume handles require sector-aligned reads (handled automatically by the tool).

## Supported Filesystems

| Filesystem | Scan | Restore | Notes |
|------------|------|---------|-------|
| FAT32      | ✅   | ✅      | VFAT LFN support, cluster chain following |
| exFAT      | ✅   | ✅      | UTF-16 filenames, FAT chain following |
| NTFS       | ✅   | ✅      | MFT walk, `$FILE_NAME` + `$DATA` attributes, resident data support |
| ext4       | ✅   | ❌      | Inode pointer cleared on deletion |

### Known Limitations

- NTFS restore reads clusters sequentially from the first data run. Fragmented files with multiple data runs may produce incorrect data after the first fragment boundary.
- ext4 restore is not possible (inode data pointers are zeroed on deletion).
- `\\.\PhysicalDriveN` restore is not supported directly — scan to identify the right partition, then use the volume path.

## Build

```sh
cargo build --release
```

The binary will be at `target/release/recovery` (or `target/release/recovery.exe` on Windows).

## How It Works

1. Opens the raw device in read-only mode
2. Reads the boot sector (first 512 bytes)
3. Probes for filesystem type (FAT32 → exFAT → NTFS → ext4)
4. Walks the filesystem's directory structures looking for deleted entries
5. Displays a table of recoverable files
6. On `--restore`, reads the original clusters (following FAT chains on FAT/exFAT, data runs on NTFS) and writes them to the output file

## License

GNU General Public License v3.0
