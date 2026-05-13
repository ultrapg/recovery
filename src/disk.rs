use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use crate::types::DeletedFile;
use crate::fat;
use crate::ntfs;
use crate::ext;

pub const MBR_SIGNATURE: u16 = 0xAA55;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Partition {
    pub start_lba: u64,
    pub num_sectors: u64,
    pub fs_type_byte: u8,
    pub label: String,
}

pub fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

pub fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

pub fn parse_mbr(buf: &[u8; 512]) -> Vec<Partition> {
    let mut parts = Vec::new();
    if read_u16_le(buf, 510) != MBR_SIGNATURE {
        return parts;
    }
    for i in 0..4 {
        let off = 446 + i * 16;
        let fs_type = buf[off + 4];
        let start_lba = read_u32_le(buf, off + 8) as u64;
        let num_sectors = read_u32_le(buf, off + 12) as u64;
        if fs_type == 0 || num_sectors == 0 {
            continue;
        }
        let label = match fs_type {
            0x01 => "FAT12",
            0x04 => "FAT16",
            0x06 => "FAT16B",
            0x07 => "NTFS/exFAT",
            0x0B => "FAT32",
            0x0C => "FAT32 (LBA)",
            0x0E => "FAT16B (LBA)",
            0x0F => "Extended (LBA)",
            0x82 => "Linux swap",
            0x83 => "Linux ext",
            0x8E => "Linux LVM",
            0xEE => "GPT protective",
            _ => "Unknown",
        };
        parts.push(Partition {
            start_lba,
            num_sectors,
            fs_type_byte: fs_type,
            label: format!("Partition {}: {} (LBA {}, {} sectors, type 0x{:02X})",
                i + 1, label, start_lba, num_sectors, fs_type),
        });
    }
    parts
}

pub fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off], buf[off + 1], buf[off + 2], buf[off + 3],
        buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7],
    ])
}

fn read_at(file: &mut File, offset: u64, buf: &mut [u8]) -> bool {
    file.seek(SeekFrom::Start(offset)).is_ok() && file.read_exact(buf).is_ok()
}

fn read_boot_sector_at(file: &mut File, lba: u64, buf: &mut [u8; 512]) -> bool {
    read_at(file, lba * 512, buf)
}

fn guid_to_string(buf: &[u8], off: usize) -> String {
    if off + 16 > buf.len() { return String::new(); }
    let time_low = read_u32_le(buf, off);
    let time_mid = read_u16_le(buf, off + 4);
    let time_hi_and_version = read_u16_le(buf, off + 6);
    let clock_seq_hi = buf[off + 8];
    let clock_seq_low = buf[off + 9];
    let node = &buf[off + 10..off + 16];
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        time_low, time_mid, time_hi_and_version,
        clock_seq_hi, clock_seq_low,
        node[0], node[1], node[2], node[3], node[4], node[5],
    )
}

const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";

fn read_gpt_partition_name(buf: &[u8], off: usize) -> String {
    let mut name_utf16 = Vec::new();
    for i in (0..72).step_by(2) {
        let ch = u16::from_le_bytes([buf[off + i], buf[off + i + 1]]);
        if ch == 0 { break; }
        name_utf16.push(ch);
    }
    String::from_utf16_lossy(&name_utf16)
}

fn fs_type_from_gpt_guid(guid: &str) -> &'static str {
    match guid.to_uppercase().as_str() {
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" => "Microsoft Basic Data (FAT32/NTFS/exFAT)",
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" => "EFI System (FAT32)",
        "0FC63DAF-8483-4772-8E79-3D69D8477DE4" => "Linux filesystem",
        "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F" => "Linux swap",
        "E6D6D379-F507-44C2-A23C-238F2A3DF928" => "Linux LVM",
        "A19D880F-05FC-4D3B-A006-743F0F84911E" => "Linux RAID",
        "BFC0C1A0-604D-46C1-99EA-097E43B8F539" => "Linux /boot (ext)",
        "933AC7E1-2EB4-4F13-B844-0E14E2AEF915" => "Linux /home (ext)",
        "3B8F8425-20E0-4F3B-907F-1A25A76F98E8" => "Linux /root (ext)",
        "D3BFE2DE-3DAF-11DF-BA40-E3A556D89593" => "Intel Rapid Start",
        "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC" => "Windows Recovery",
        _ => "Unknown",
    }
}

pub fn parse_gpt(file: &mut File) -> Vec<Partition> {
    let mut gpt_hdr = [0u8; 512];
    if !read_at(file, 512, &mut gpt_hdr) {
        eprintln!("Cannot read GPT header at LBA 1");
        return vec![];
    }
    if &gpt_hdr[0..8] != GPT_SIGNATURE {
        eprintln!("No GPT signature found");
        return vec![];
    }

    let partition_entry_lba = read_u64_le(&gpt_hdr, 72);
    let num_entries = read_u32_le(&gpt_hdr, 80) as usize;
    let mut entry_size = read_u32_le(&gpt_hdr, 84) as usize;
    if entry_size == 0 { entry_size = 128; }

    eprintln!("GPT: {} partition entries at LBA {}, entry size {}",
        num_entries, partition_entry_lba, entry_size);

    let mut parts = Vec::new();
    // Read partition entries (usually 128 bytes each, 128 entries = 16 KB max)
    let read_size = num_entries * entry_size;
    let max_read = 65536.min(read_size);
    if max_read == 0 { return vec![]; }

    // We may need multiple sectors to read all entries
    let sectors_needed = (max_read + 511) / 512;
    let mut buf = vec![0u8; sectors_needed * 512];
    if !read_at(file, partition_entry_lba * 512, &mut buf) {
        eprintln!("Cannot read GPT partition entries");
        return vec![];
    }

    for i in 0..num_entries {
        let off = i * entry_size;
        if off + 16 > buf.len() { break; }

        let type_guid = guid_to_string(&buf, off);
        if type_guid == "00000000-0000-0000-0000-000000000000" {
            // Unused entry
            continue;
        }

        let start_lba = read_u64_le(&buf, off + 32);
        let end_lba = read_u64_le(&buf, off + 40);
        let num_sectors = end_lba.saturating_sub(start_lba) + 1;
        let name = read_gpt_partition_name(&buf, off + 56);
        let fs_label = fs_type_from_gpt_guid(&type_guid);

        let label = if name.is_empty() {
            format!("Partition {}: {} (LBA {}..{}, {} sectors)",
                i + 1, fs_label, start_lba, end_lba, num_sectors)
        } else {
            format!("Partition {}: \"{}\" - {} (LBA {}..{}, {} sectors)",
                i + 1, name, fs_label, start_lba, end_lba, num_sectors)
        };

        parts.push(Partition {
            start_lba,
            num_sectors,
            fs_type_byte: 0,
            label,
        });
    }
    parts
}

pub fn scan_partition(
    file: &mut File, partition: &Partition, results: &mut Vec<DeletedFile>,
) {
    let byte_offset = partition.start_lba * 512;
    let mut boot = [0u8; 512];
    if !read_at(file, byte_offset, &mut boot) {
        eprintln!("  Cannot read boot sector for {}", partition.label);
        return;
    }
    if boot[510] != 0x55 || boot[511] != 0xAA {
        eprintln!("  No boot signature for {}", partition.label);
        return;
    }

    let mut partition_results: Vec<DeletedFile> = Vec::new();

    // FAT32
    if let Some(mut info) = fat::probe_fat32_from_buf(&boot) {
        info.partition_offset = byte_offset;
        eprintln!("  FAT32 detected");
        if let Err(e) = fat::scan_fat32(file, &info, &mut partition_results) {
            eprintln!("  FAT32 scan error: {}", e);
        }
        results.append(&mut partition_results);
        return;
    }

    // exFAT (NTFS 0x07 type byte can be either)
    if let Some(mut info) = fat::probe_exfat_from_buf(&boot) {
        info.partition_offset = byte_offset;
        eprintln!("  exFAT detected");
        if let Err(e) = fat::scan_exfat(file, &info, &mut partition_results) {
            eprintln!("  exFAT scan error: {}", e);
        }
        results.append(&mut partition_results);
        return;
    }

    // NTFS
    if let Some(mut info) = ntfs::probe_from_buf(&boot) {
        info.partition_offset = byte_offset;
        eprintln!("  NTFS detected");
        if let Err(e) = ntfs::scan(file, &info, &mut partition_results) {
            eprintln!("  NTFS scan error: {}", e);
        }
        results.append(&mut partition_results);
        return;
    }

    // ext4 (superblock at offset 1024 within partition)
    {
        let mut ext_buf = [0u8; 2048];
        if read_at(file, byte_offset, &mut ext_buf)
            && ext_buf[510] == 0x55 && ext_buf[511] == 0xAA
        {
            let sb_off = 1024usize;
            let magic = u16::from_le_bytes([ext_buf[sb_off + 56], ext_buf[sb_off + 57]]);
            if magic == 0xEF53 {
                if let Some(mut info) = ext::probe_from_buf(&ext_buf) {
                    info.partition_offset = byte_offset;
                    eprintln!("  ext4 detected");
                    if let Err(e) = ext::scan(file, &info, &mut partition_results) {
                        eprintln!("  ext4 scan error: {}", e);
                    }
                    results.append(&mut partition_results);
                    return;
                }
            }
        }
        eprintln!("  Unrecognized filesystem");
    }
}

pub fn scan_disk(file: &mut File, results: &mut Vec<DeletedFile>) {
    let mut mbr = [0u8; 512];
    if !read_boot_sector_at(file, 0, &mut mbr) {
        eprintln!("ERROR: Cannot read MBR");
        return;
    }

    let mbr_parts = parse_mbr(&mbr);

    // Check for GPT protective MBR
    let has_gpt_protective = mbr_parts.iter().any(|p| p.fs_type_byte == 0xEE);

    let partitions = if has_gpt_protective {
        eprintln!("GPT protective MBR detected, parsing GPT table...");
        let gpt_parts = parse_gpt(file);
        if gpt_parts.is_empty() {
            eprintln!("GPT parsing failed, falling back to MBR.");
            mbr_parts
        } else {
            gpt_parts
        }
    } else {
        mbr_parts
    };

    if partitions.is_empty() {
        eprintln!("No partitions found.");
        return;
    }

    let (mbr_label, skip_ext, skip_gpt) = if has_gpt_protective && !partitions.is_empty() && partitions[0].fs_type_byte == 0 {
        ("GPT", false, false)
    } else {
        ("MBR", true, true)
    };

    eprintln!("Found {} {} partition(s):", partitions.len(), mbr_label);
    for p in &partitions {
        eprintln!("  {}", p.label);
    }
    eprintln!();

    for p in &partitions {
        if skip_ext && (p.fs_type_byte == 0x0F || p.fs_type_byte == 0x05 || p.fs_type_byte == 0x85) {
            eprintln!("Skipping extended partition: {}", p.label);
            continue;
        }
        if skip_gpt && p.fs_type_byte == 0xEE {
            eprintln!("Skipping GPT protective MBR entry.");
            continue;
        }
        scan_partition(file, p, results);
    }
}
