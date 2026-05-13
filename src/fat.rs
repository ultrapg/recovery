use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use crate::types::{DeletedFile, is_directory};

const DIR_ENTRY_SIZE: usize = 32;

// FAT32 boot sector offsets
const BS_BYTES_PER_SECTOR: usize = 11;
const BS_SECTORS_PER_CLUSTER: usize = 13;
const BS_RESERVED_SECTORS: usize = 14;
const BS_NUM_FATS: usize = 16;
const BS_ROOT_DIR_ENTRIES: usize = 17;
const BS_TOTAL_SECTORS_16: usize = 19;
const BS_SECTORS_PER_FAT_16: usize = 22;
const BS_TOTAL_SECTORS_32: usize = 32;
const BS_SECTORS_PER_FAT_32: usize = 36;
const BS_ROOT_CLUSTER: usize = 44;
const BS_BOOT_SIGNATURE: usize = 510;

// exFAT boot sector offsets
const EXFAT_OEM_ID: usize = 3;
const EXFAT_BPS_SHIFT: usize = 108;
const EXFAT_SPC_SHIFT: usize = 109;
const EXFAT_FAT_OFFSET: usize = 80;
const EXFAT_CLUSTER_HEAP_OFFSET: usize = 88;
const EXFAT_ROOT_CLUSTER: usize = 96;

// FAT directory entry offsets
const DIR_ATTR: usize = 11;
const DIR_FIRST_CLUSTER_HI: usize = 20;
const DIR_FIRST_CLUSTER_LO: usize = 26;
const DIR_FILE_SIZE: usize = 28;

// FAT entry constants
const FAT_ENTRY_FREE: u32 = 0;
const FAT_ENTRY_END_MIN: u32 = 0x0FFFFFF8;

const FAT_ENTRY_MASK: u32 = 0x0FFFFFFF;

#[derive(Debug, Clone)]
pub struct Fat32Info {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub sectors_per_fat: u32,
    pub root_cluster: u32,
    pub partition_offset: u64,
}

impl Fat32Info {
    pub fn bytes_per_cluster(&self) -> u64 {
        self.bytes_per_sector as u64 * self.sectors_per_cluster as u64
    }
    pub fn data_region_lba(&self) -> u64 {
        self.reserved_sectors as u64 + self.num_fats as u64 * self.sectors_per_fat as u64
    }
    pub fn cluster_to_offset(&self, cluster: u32) -> u64 {
        let lba = self.data_region_lba()
            + (cluster as u64 - 2) * self.sectors_per_cluster as u64;
        self.partition_offset + lba * self.bytes_per_sector as u64
    }
    pub fn fat_entry_offset(&self, cluster: u32) -> u64 {
        self.partition_offset + self.reserved_sectors as u64 * self.bytes_per_sector as u64 + cluster as u64 * 4
    }
}

#[derive(Debug, Clone)]
pub struct ExfatInfo {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u32,
    pub cluster_heap_offset: u32,
    pub root_cluster: u32,
    pub fat_offset: u32,
    pub partition_offset: u64,
}

impl ExfatInfo {
    pub fn bytes_per_cluster(&self) -> u64 {
        self.bytes_per_sector as u64 * self.sectors_per_cluster as u64
    }
    pub fn cluster_to_offset(&self, cluster: u32) -> u64 {
        let lba = self.cluster_heap_offset as u64
            + (cluster as u64 - 2) * self.sectors_per_cluster as u64;
        self.partition_offset + lba * self.bytes_per_sector as u64
    }
    pub fn fat_entry_offset(&self, cluster: u32) -> u64 {
        self.partition_offset + self.fat_offset as u64 * self.bytes_per_sector as u64 + cluster as u64 * 4
    }
}

fn read_bytes(file: &mut File, offset: u64, buf: &mut [u8]) -> Result<(), String> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Seek error at offset {}: {}", offset, e))?;
    file.read_exact(buf)
        .map_err(|e| format!("Read error at offset {}: {}", offset, e))?;
    Ok(())
}

fn extract_83_name(entry: &[u8; 32]) -> String {
    let mut name = String::new();
    let first = entry[0];
    if first == 0x05 {
        name.push(0xE5 as char);
    } else if first == 0xE5 {
        name.push('?');
    } else if first == 0x2E {
        return String::new();
    } else if first < 0x20 || first > 0x7E {
        name.push_str(&format!("[0x{:02X}]", first));
    } else {
        name.push(first as char);
    }
    for i in 1..8 {
        let c = entry[i];
        if c == 0x20 || c == 0x00 { break; }
        if c > 0x20 && c < 0x7F { name.push(c as char); }
        else { name.push_str(&format!("[0x{:02X}]", c)); }
    }
    let mut ext = String::new();
    for i in 8..11 {
        let c = entry[i];
        if c == 0x20 || c == 0x00 { break; }
        if c > 0x20 && c < 0x7F { ext.push(c as char); }
        else { ext.push_str(&format!("[0x{:02X}]", c)); }
    }
    if !ext.is_empty() { name.push('.'); name.push_str(&ext); }
    name
}

fn extract_lfn_utf16(entry: &[u8; 32]) -> Vec<u16> {
    let mut chars = Vec::with_capacity(13);
    for i in 0..5 { chars.push(u16::from_le_bytes([entry[1 + i * 2], entry[2 + i * 2]])); }
    for i in 0..6 { chars.push(u16::from_le_bytes([entry[14 + i * 2], entry[15 + i * 2]])); }
    for i in 0..2 { chars.push(u16::from_le_bytes([entry[28 + i * 2], entry[29 + i * 2]])); }
    chars
}

fn utf16_to_string(chars: &[u16]) -> String {
    let filtered: Vec<u16> = chars.iter().copied()
        .take_while(|&c| c != 0x0000 && c != 0xFFFF).collect();
    String::from_utf16_lossy(&filtered)
}

const LFN_ATTR: u8 = 0x0F;
const DIR_DELETED: u8 = 0xE5;
const DIR_END: u8 = 0x00;
const DIR_DOT: u8 = 0x2E;

fn is_deleted_lfn_entry(entry: &[u8; 32]) -> bool { entry[0] == DIR_DELETED && entry[DIR_ATTR] == LFN_ATTR }
fn is_deleted_short_entry(entry: &[u8; 32]) -> bool { entry[0] == DIR_DELETED && entry[DIR_ATTR] != LFN_ATTR }
fn is_active_lfn_entry(entry: &[u8; 32]) -> bool {
    let first = entry[0]; first != DIR_DELETED && first != DIR_END && entry[DIR_ATTR] == LFN_ATTR
}
fn is_active_short_entry(entry: &[u8; 32]) -> bool {
    let first = entry[0]; first != DIR_DELETED && first != DIR_END && first != DIR_DOT && entry[DIR_ATTR] != LFN_ATTR
}
fn is_end_of_dir(entry: &[u8; 32]) -> bool { entry[0] == DIR_END }
fn get_cluster(entry: &[u8; 32]) -> u32 {
    let low = u16::from_le_bytes([entry[DIR_FIRST_CLUSTER_LO], entry[DIR_FIRST_CLUSTER_LO + 1]]);
    let high = u16::from_le_bytes([entry[DIR_FIRST_CLUSTER_HI], entry[DIR_FIRST_CLUSTER_HI + 1]]);
    (high as u32) << 16 | low as u32
}
fn get_file_size(entry: &[u8; 32]) -> u32 {
    u32::from_le_bytes([entry[DIR_FILE_SIZE], entry[DIR_FILE_SIZE + 1], entry[DIR_FILE_SIZE + 2], entry[DIR_FILE_SIZE + 3]])
}

fn read_cluster_data(
    file: &mut File, fs: &Fat32Info, cluster: u32, buf: &mut Vec<u8>,
) -> Result<(), String> {
    if cluster < 2 { return Err(format!("Invalid cluster: {}", cluster)); }
    let offset = fs.cluster_to_offset(cluster);
    let cluster_size = fs.bytes_per_cluster() as usize;
    if buf.len() < cluster_size { buf.resize(cluster_size, 0); }
    read_bytes(file, offset, &mut buf[..cluster_size])
}

fn scan_directory(
    file: &mut File, fs: &Fat32Info, start_cluster: u32,
    current_path: &str, results: &mut Vec<DeletedFile>,
) -> Result<(), String> {
    let cluster_size = fs.bytes_per_cluster() as usize;
    let mut cluster_buf = vec![0u8; cluster_size];
    let mut cluster = start_cluster;
    let mut visited = std::collections::HashSet::new();
    let mut pending_deleted_lfns: Vec<[u8; 32]> = Vec::new();
    let mut pending_active_lfns: Vec<Vec<u16>> = Vec::new();

    loop {
        if cluster >= FAT_ENTRY_END_MIN || cluster < 2 { break; }
        if !visited.insert(cluster) { break; }
        read_cluster_data(file, fs, cluster, &mut cluster_buf)?;
        let entries_count = cluster_size / DIR_ENTRY_SIZE;

        for i in 0..entries_count {
            let offset = i * DIR_ENTRY_SIZE;
            let mut entry = [0u8; DIR_ENTRY_SIZE];
            entry.copy_from_slice(&cluster_buf[offset..offset + DIR_ENTRY_SIZE]);

            if is_end_of_dir(&entry) { break; }
            if is_deleted_lfn_entry(&entry) { pending_deleted_lfns.push(entry); continue; }

            if is_deleted_short_entry(&entry) {
                let name = if !pending_deleted_lfns.is_empty() {
                    let mut all_chars: Vec<u16> = Vec::new();
                    // LFN entries are stored in reverse order (last entry first in directory)
                    for lfn_entry in pending_deleted_lfns.iter().rev() {
                        all_chars.extend(extract_lfn_utf16(lfn_entry));
                    }
                    let long_name = utf16_to_string(&all_chars);
                    if !long_name.is_empty() { long_name } else { extract_83_name(&entry) }
                } else { extract_83_name(&entry) };

                let size = get_file_size(&entry) as u64;
                let start_cluster = get_cluster(&entry);
                let start_addr = if start_cluster >= 2 {
                    let lba = fs.data_region_lba() + (start_cluster as u64 - 2) * fs.sectors_per_cluster as u64;
                    fs.partition_offset + lba * fs.bytes_per_sector as u64
                } else { 0 };
                let attr = entry[DIR_ATTR];

                results.push(DeletedFile {
                    name, size, start_address: start_addr,
                    fs_type: "FAT32".into(), path: current_path.to_string(),
                    is_directory: is_directory(attr), resident_data: None,
                    data_runs: vec![],
                });
                pending_deleted_lfns.clear(); continue;
            }

            if is_active_lfn_entry(&entry) {
                pending_active_lfns.push(extract_lfn_utf16(&entry));
                pending_deleted_lfns.clear(); continue;
            }

            if is_active_short_entry(&entry) {
                let name = if !pending_active_lfns.is_empty() {
                    // LFN entries stored reversed – iterate backwards
                    let ordered: Vec<u16> = pending_active_lfns.iter().rev()
                        .flat_map(|v| v.iter().copied()).collect();
                    pending_active_lfns.clear();
                    utf16_to_string(&ordered)
                } else { extract_83_name(&entry) };
                pending_active_lfns.clear(); pending_deleted_lfns.clear();

                let attr = entry[DIR_ATTR];
                let entry_cluster = get_cluster(&entry);
                let is_dir = is_directory(attr);

                if is_dir {
                    let first_byte = entry[0];
                    if first_byte == DIR_DOT || entry_cluster == 0 || entry_cluster == start_cluster { continue; }
                    let sub_path = if current_path.is_empty() { name }
                        else { format!("{}/{}", current_path, name) };
                    let _ = scan_directory(file, fs, entry_cluster, &sub_path, results);
                }
                continue;
            }

            pending_deleted_lfns.clear(); pending_active_lfns.clear();
        }

        let mut fat_buf = [0u8; 4];
        read_bytes(file, fs.fat_entry_offset(cluster), &mut fat_buf)?;
        let fat_entry = u32::from_le_bytes(fat_buf) & FAT_ENTRY_MASK;
        if fat_entry >= FAT_ENTRY_END_MIN || fat_entry == FAT_ENTRY_FREE { break; }
        cluster = fat_entry;
    }
    Ok(())
}

fn scan_directory_exfat(
    file: &mut File, fs: &ExfatInfo, start_cluster: u32,
    current_path: &str, results: &mut Vec<DeletedFile>,
) -> Result<(), String> {
    let cluster_size = fs.bytes_per_cluster() as usize;
    let mut cluster_buf = vec![0u8; cluster_size];
    let mut cluster = start_cluster;
    let mut visited = std::collections::HashSet::new();

    loop {
        if cluster < 2 { break; }
        if !visited.insert(cluster) { break; }

        let offset = fs.cluster_to_offset(cluster);
        if read_bytes(file, offset, cluster_buf.as_mut_slice()).is_err() { break; }

        let entries_count = cluster_size / DIR_ENTRY_SIZE;
        let mut i = 0;
        while i < entries_count {
            let off = i * DIR_ENTRY_SIZE;
            let mut entry = [0u8; DIR_ENTRY_SIZE];
            entry.copy_from_slice(&cluster_buf[off..off + DIR_ENTRY_SIZE]);
            let entry_type = entry[0];
            if entry_type == 0x00 { break; }

            if entry_type == 0xE5 {
                // Deleted (primary) file entry – read secondary entries following it
                let mut name = String::new();
                let mut size = 0u64;
                let mut start_cluster_val = 0u32;
                let attr = entry[3];  // exFAT primary entry attribute byte

                let max_secondary = 20.min(entries_count - i - 1);
                let mut secondary_count = 0usize;

                for j in 1..=max_secondary {
                    let s_off = (i + j) * DIR_ENTRY_SIZE;
                    let mut sub = [0u8; DIR_ENTRY_SIZE];
                    sub.copy_from_slice(&cluster_buf[s_off..s_off + DIR_ENTRY_SIZE]);
                    let st = sub[0];

                    if st != 0xE5 { break; }

                    if sub[2] == 0 && sub[3] > 0 {
                        // Stream extension entry
                        size = u64::from_le_bytes([sub[24], sub[25], sub[26], sub[27], 0, 0, 0, 0]);
                        let c = u32::from_le_bytes([sub[20], sub[21], sub[22], sub[23]]);
                        if c >= 2 { start_cluster_val = c; }
                    } else if sub[2] == 0 && sub[3] == 0 {
                        // File name entry
                        let mut name_chars = Vec::new();
                        for k in (4..32).step_by(2) {
                            let ch = u16::from_le_bytes([sub[k], sub[k + 1]]);
                            if ch == 0 || ch == 0xFFFF { break; }
                            name_chars.push(ch);
                        }
                        let part = String::from_utf16_lossy(&name_chars);
                        name.push_str(&part);
                    } else {
                        break;
                    }
                    secondary_count = j;
                }
                i += secondary_count;

                let start_addr = if start_cluster_val >= 2 {
                    let lba = fs.cluster_heap_offset as u64 + (start_cluster_val as u64 - 2) * fs.sectors_per_cluster as u64;
                    fs.partition_offset + lba * fs.bytes_per_sector as u64
                } else { 0 };

                if name.is_empty() {
                    name = format!("DELETED_EXFAT_0x{:08X}", start_cluster_val);
                }

                results.push(DeletedFile {
                    name, size, start_address: start_addr,
                    fs_type: "exFAT".into(), path: current_path.to_string(),
                    is_directory: is_directory(attr), resident_data: None,
                    data_runs: vec![],
                });
            } else if entry_type & 0x01 != 0 && (entry_type & 0x80 == 0 || entry_type == 0x85) {
                // Active primary entry – recurse into subdirectories
                let secondary_count = entry[1] as usize;
                let max_secondary = secondary_count.min(entries_count - i - 1);
                let mut dir_name = String::new();
                let mut sub_cluster = 0u32;
                let attr = entry[3];

                for j in 1..=max_secondary {
                    let s_off = (i + j) * DIR_ENTRY_SIZE;
                    let mut sub = [0u8; DIR_ENTRY_SIZE];
                    sub.copy_from_slice(&cluster_buf[s_off..s_off + DIR_ENTRY_SIZE]);
                    let st = sub[0];

                    if st == 0x00 || (st & 0x80 == 0 && st != 0xE5) { break; }

                    if sub[2] == 0 && sub[3] > 0 {
                        // Stream extension – get first cluster
                        let c = u32::from_le_bytes([sub[20], sub[21], sub[22], sub[23]]);
                        if c >= 2 { sub_cluster = c; }
                    } else if sub[2] == 0 && sub[3] == 0 && sub[4] != 0 {
                        // File name entry
                        let mut name_chars = Vec::new();
                        for k in (4..32).step_by(2) {
                            let ch = u16::from_le_bytes([sub[k], sub[k + 1]]);
                            if ch == 0 || ch == 0xFFFF { break; }
                            name_chars.push(ch);
                        }
                        dir_name.push_str(&String::from_utf16_lossy(&name_chars));
                    }
                }
                i += secondary_count;

                if is_directory(attr) && !dir_name.is_empty() && sub_cluster >= 2 {
                    let sub_path = if current_path.is_empty() { dir_name }
                        else { format!("{}/{}", current_path, dir_name) };
                    let _ = scan_directory_exfat(file, fs, sub_cluster, &sub_path, results);
                }
            }

            i += 1;
        }

        // Follow cluster chain via FAT for next iteration
        let mut fat_buf = [0u8; 4];
        if read_bytes(file, fs.fat_entry_offset(cluster), &mut fat_buf).is_err() { break; }
        let fat_entry = u32::from_le_bytes(fat_buf) & FAT_ENTRY_MASK;
        if fat_entry >= FAT_ENTRY_END_MIN || fat_entry == FAT_ENTRY_FREE { break; }
        cluster = fat_entry;
    }
    Ok(())
}

fn parse_fat32_boot(boot: &[u8; 512]) -> Option<Fat32Info> {
    if boot[BS_BOOT_SIGNATURE] != 0x55 || boot[BS_BOOT_SIGNATURE + 1] != 0xAA { return None; }
    let bytes_per_sector = u16::from_le_bytes([boot[BS_BYTES_PER_SECTOR], boot[BS_BYTES_PER_SECTOR + 1]]);
    if bytes_per_sector < 512 || bytes_per_sector > 4096 || !bytes_per_sector.is_power_of_two() { return None; }
    let sectors_per_cluster = boot[BS_SECTORS_PER_CLUSTER];
    if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() { return None; }
    let reserved_sectors = u16::from_le_bytes([boot[BS_RESERVED_SECTORS], boot[BS_RESERVED_SECTORS + 1]]);
    let num_fats = boot[BS_NUM_FATS];
    if num_fats == 0 { return None; }

    let total_sectors_16 = u16::from_le_bytes([boot[BS_TOTAL_SECTORS_16], boot[BS_TOTAL_SECTORS_16 + 1]]);
    let sectors_per_fat_16 = u16::from_le_bytes([boot[BS_SECTORS_PER_FAT_16], boot[BS_SECTORS_PER_FAT_16 + 1]]);
    let total_sectors_32 = u32::from_le_bytes([boot[BS_TOTAL_SECTORS_32], boot[BS_TOTAL_SECTORS_32 + 1], boot[BS_TOTAL_SECTORS_32 + 2], boot[BS_TOTAL_SECTORS_32 + 3]]);
    let sectors_per_fat_32 = u32::from_le_bytes([boot[BS_SECTORS_PER_FAT_32], boot[BS_SECTORS_PER_FAT_32 + 1], boot[BS_SECTORS_PER_FAT_32 + 2], boot[BS_SECTORS_PER_FAT_32 + 3]]);

    let sectors_per_fat = if sectors_per_fat_16 != 0 { sectors_per_fat_16 as u32 } else { sectors_per_fat_32 };
    let total_sectors = if total_sectors_16 != 0 { total_sectors_16 as u32 } else { total_sectors_32 };
    if sectors_per_fat == 0 || total_sectors == 0 { return None; }

    let root_dir_entries = u16::from_le_bytes([boot[BS_ROOT_DIR_ENTRIES], boot[BS_ROOT_DIR_ENTRIES + 1]]);
    let data_sectors = total_sectors - reserved_sectors as u32 - (num_fats as u32 * sectors_per_fat)
        - (root_dir_entries as u32 * 32 + bytes_per_sector as u32 - 1) / bytes_per_sector as u32;
    let total_clusters = data_sectors / sectors_per_cluster as u32;
    if total_clusters < 65525 { return None; }

    let root_cluster = u32::from_le_bytes([boot[BS_ROOT_CLUSTER], boot[BS_ROOT_CLUSTER + 1], boot[BS_ROOT_CLUSTER + 2], boot[BS_ROOT_CLUSTER + 3]]);
    if root_cluster < 2 { return None; }

    Some(Fat32Info {
        bytes_per_sector, sectors_per_cluster, reserved_sectors, num_fats,
        sectors_per_fat, root_cluster, partition_offset: 0,
    })
}

pub fn probe_fat32_from_buf(buf: &[u8; 512]) -> Option<Fat32Info> {
    parse_fat32_boot(buf)
}

fn parse_exfat_boot(boot: &[u8; 512]) -> Option<ExfatInfo> {
    if boot[BS_BOOT_SIGNATURE] != 0x55 || boot[BS_BOOT_SIGNATURE + 1] != 0xAA { return None; }
    if &boot[EXFAT_OEM_ID..EXFAT_OEM_ID + 8] != b"EXFAT   " { return None; }

    let bps_shift = boot[EXFAT_BPS_SHIFT];
    if bps_shift < 9 || bps_shift > 12 { return None; }
    let bytes_per_sector = (1u16) << bps_shift;

    let spc_shift = boot[EXFAT_SPC_SHIFT] & 0x0F;
    let sectors_per_cluster = (1u32) << spc_shift;
    if sectors_per_cluster == 0 || sectors_per_cluster > 2048 { return None; }

    let fat_offset = u32::from_le_bytes([boot[EXFAT_FAT_OFFSET], boot[EXFAT_FAT_OFFSET + 1], boot[EXFAT_FAT_OFFSET + 2], boot[EXFAT_FAT_OFFSET + 3]]);

    let cluster_heap_offset = u32::from_le_bytes([boot[EXFAT_CLUSTER_HEAP_OFFSET], boot[EXFAT_CLUSTER_HEAP_OFFSET + 1], boot[EXFAT_CLUSTER_HEAP_OFFSET + 2], boot[EXFAT_CLUSTER_HEAP_OFFSET + 3]]);

    let root_cluster = u32::from_le_bytes([boot[EXFAT_ROOT_CLUSTER], boot[EXFAT_ROOT_CLUSTER + 1], boot[EXFAT_ROOT_CLUSTER + 2], boot[EXFAT_ROOT_CLUSTER + 3]]);
    if root_cluster < 2 { return None; }

    Some(ExfatInfo { bytes_per_sector, sectors_per_cluster, cluster_heap_offset, root_cluster, fat_offset, partition_offset: 0 })
}

pub fn probe_exfat_from_buf(buf: &[u8; 512]) -> Option<ExfatInfo> {
    parse_exfat_boot(buf)
}

pub fn scan_fat32(
    file: &mut File, info: &Fat32Info, results: &mut Vec<DeletedFile>,
) -> Result<(), String> {
    scan_directory(file, info, info.root_cluster, "", results)
}

pub fn scan_exfat(
    file: &mut File, info: &ExfatInfo, results: &mut Vec<DeletedFile>,
) -> Result<(), String> {
    scan_directory_exfat(file, info, info.root_cluster, "", results)
}

fn read_fat_entry(file: &mut File, fs: &Fat32Info, cluster: u32) -> Result<u32, String> {
    let mut buf = [0u8; 4];
    read_bytes(file, fs.fat_entry_offset(cluster), &mut buf)?;
    Ok(u32::from_le_bytes(buf) & 0x0FFFFFFF)
}

pub fn restore_fat32(
    file: &mut File, fs: &Fat32Info, entry: &DeletedFile, target_path: &str,
) -> Result<(), String> {
    let data_start = fs.partition_offset + fs.data_region_lba() * fs.bytes_per_sector as u64;
    if entry.start_address < data_start {
        return Err(format!("Invalid start_address 0x{:X} (before data region)", entry.start_address));
    }
    let cluster = (entry.start_address - data_start) / fs.bytes_per_cluster() + 2;
    if cluster < 2 { return Err("Invalid cluster from start_address".into()); }
    let cluster = cluster as u32;

    let cluster_size = fs.bytes_per_cluster() as usize;
    let mut buf = vec![0u8; cluster_size];
    let mut remaining = entry.size as usize;
    let mut current_cluster = cluster;

    let out_path = std::path::Path::new(target_path);
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create output directory: {}", e))?;
    }
    let mut out_file = std::fs::OpenOptions::new()
        .write(true).create(true).truncate(true)
        .open(out_path).map_err(|e| format!("Cannot create output file: {}", e))?;

    while remaining > 0 {
        let offset = fs.cluster_to_offset(current_cluster);
        // Always read full cluster for sector alignment (volume handles require it)
        read_bytes(file, offset, &mut buf)?;
        let to_write = cluster_size.min(remaining);
        out_file.write_all(&buf[..to_write]).map_err(|e| format!("Write error: {}", e))?;
        remaining -= to_write;
        if remaining == 0 { break; }

        // Follow FAT chain (preserved for deleted files on FAT32)
        let fat_entry = read_fat_entry(file, fs, current_cluster)?;
        if fat_entry >= FAT_ENTRY_END_MIN || fat_entry == FAT_ENTRY_FREE {
            eprintln!("  Warning: FAT chain ends at cluster {}", current_cluster);
            break;
        }
        if fat_entry < 2 {
            break;
        }
        current_cluster = fat_entry;
    }
    eprintln!("  Restored {} bytes to '{}'", entry.size - remaining as u64, target_path);
    Ok(())
}

fn read_exfat_fat_entry(file: &mut File, fs: &ExfatInfo, cluster: u32) -> Result<u32, String> {
    let mut buf = [0u8; 4];
    read_bytes(file, fs.fat_entry_offset(cluster), &mut buf)?;
    Ok(u32::from_le_bytes(buf) & 0x0FFFFFFF)
}

pub fn restore_exfat(
    file: &mut File, fs: &ExfatInfo, entry: &DeletedFile, target_path: &str,
) -> Result<(), String> {
    let cluster_size = fs.bytes_per_cluster() as usize;
    let data_start = fs.partition_offset + fs.cluster_heap_offset as u64 * fs.bytes_per_sector as u64;
    if entry.start_address < data_start {
        return Err(format!("Invalid start_address 0x{:X} (before cluster heap)", entry.start_address));
    }
    let mut buf = vec![0u8; cluster_size];
    let mut remaining = entry.size as usize;
    let mut current_cluster = (entry.start_address - data_start) / (cluster_size as u64) + 2;
    if current_cluster < 2 { return Err("Cannot compute exFAT cluster".into()); }

    let out_path = std::path::Path::new(target_path);
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Cannot create output directory: {}", e))?;
    }
    let mut out_file = std::fs::OpenOptions::new()
        .write(true).create(true).truncate(true)
        .open(out_path).map_err(|e| format!("Cannot create output file: {}", e))?;

    while remaining > 0 {
        let offset = fs.cluster_to_offset(current_cluster as u32);
        // Always read full cluster for sector alignment
        read_bytes(file, offset, &mut buf)?;
        let to_write = cluster_size.min(remaining);
        out_file.write_all(&buf[..to_write]).map_err(|e| format!("Write error: {}", e))?;
        remaining -= to_write;
        if remaining == 0 { break; }

        // Follow FAT chain (preserved for deleted files on exFAT)
        let fat_entry = read_exfat_fat_entry(file, fs, current_cluster as u32)?;
        if fat_entry == FAT_ENTRY_FREE || fat_entry >= FAT_ENTRY_END_MIN {
            eprintln!("  Warning: FAT chain ends at cluster {}", current_cluster);
            break;
        }
        if fat_entry < 2 {
            break;
        }
        current_cluster = fat_entry as u64;
    }
    eprintln!("  Restored {} bytes to '{}'", entry.size - remaining as u64, target_path);
    Ok(())
}
