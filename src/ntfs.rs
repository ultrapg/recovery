use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use crate::types::DeletedFile;

const NTFS_FILE_MAGIC: &[u8; 4] = b"FILE";

// MFT attribute types
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;
const ATTR_END: u32 = 0xFFFFFFFF;

// Offsets within MFT record header
const MFT_FLAGS_OFFSET: usize = 0x16;
const MFT_ATTR_OFFSET_OFFSET: usize = 0x14;

// Offsets within $FILE_NAME attribute
const FN_PARENT_REF_OFFSET: usize = 0x00;
const FN_NAME_LENGTH_OFFSET: usize = 0x38;
const FN_NAME_START_OFFSET: usize = 0x3A;

// Offsets within attribute header (resident)
const ATTR_NON_RESIDENT_FLAG: usize = 8;
const ATTR_NAME_LENGTH_OFFSET: usize = 9;
const ATTR_RESIDENT_VALUE_LEN: usize = 0x10;
const ATTR_RESIDENT_VALUE_OFF: usize = 0x14;

// Offsets within attribute header (non-resident)
const ATTR_DATA_RUN_OFFSET: usize = 0x20;
const ATTR_NONRESIDENT_DATA_SIZE: usize = 0x30;

const MFT_ROOT_DIR_RECORD: u64 = 5;

#[derive(Debug, Clone)]
pub struct NtfsInfo {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub mft_start: u64,
    pub mft_record_size: u32,
    pub total_sectors: u64,
    pub partition_offset: u64,
}

fn read_bytes(file: &mut File, offset: u64, buf: &mut [u8]) -> Result<(), String> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Seek error: {}", e))?;
    file.read_exact(buf)
        .map_err(|e| format!("Read error: {}", e))?;
    Ok(())
}

fn parse_ntfs_boot(boot: &[u8; 512]) -> Option<NtfsInfo> {
    if &boot[3..11] != b"NTFS    " { return None; }

    let bytes_per_sector = u16::from_le_bytes([boot[11], boot[12]]);
    if bytes_per_sector < 512 || !bytes_per_sector.is_power_of_two() { return None; }
    let sectors_per_cluster = boot[13];
    if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() { return None; }

    let mft_cluster = u64::from_le_bytes([
        boot[48], boot[49], boot[50], boot[51],
        boot[52], boot[53], boot[54], boot[55],
    ]);
    if mft_cluster == 0 { return None; }

    let mft_record_size_byte = boot[64] as i8;
    let mft_record_size = if mft_record_size_byte >= 0 {
        (mft_record_size_byte as u32) * bytes_per_sector as u32 * sectors_per_cluster as u32
    } else {
        1u32 << (-mft_record_size_byte) as u32
    };
    if mft_record_size < 256 || mft_record_size > 65536 { return None; }

    let mft_start = mft_cluster * bytes_per_sector as u64 * sectors_per_cluster as u64;

    let total_sectors_hi = u64::from_le_bytes([
        boot[40], boot[41], boot[42], boot[43],
        boot[44], boot[45], boot[46], boot[47],
    ]);
    let total_sectors_lo = u32::from_le_bytes([boot[28], boot[29], boot[30], boot[31]]) as u64;
    let total_sectors = if total_sectors_hi != 0 { total_sectors_hi } else { total_sectors_lo };

    Some(NtfsInfo { bytes_per_sector, sectors_per_cluster, mft_start, mft_record_size, total_sectors, partition_offset: 0 })
}

pub fn probe_from_buf(buf: &[u8; 512]) -> Option<NtfsInfo> {
    parse_ntfs_boot(buf)
}

fn parse_attributes(record: &[u8], record_size: usize) -> Vec<(u32, Vec<u8>)> {
    let mut attrs = Vec::new();
    let attr_offset = u16::from_le_bytes([record[MFT_ATTR_OFFSET_OFFSET], record[MFT_ATTR_OFFSET_OFFSET + 1]]) as usize;
    if attr_offset >= record_size { return attrs; }

    let mut offset = attr_offset;
    while offset + 8 <= record_size {
        let attr_type = u32::from_le_bytes([record[offset], record[offset+1], record[offset+2], record[offset+3]]);
        let attr_len = u32::from_le_bytes([record[offset+4], record[offset+5], record[offset+6], record[offset+7]]) as usize;
        if attr_type == ATTR_END || attr_len == 0 || offset + attr_len > record_size { break; }

        let value_end = if offset + attr_len <= record_size { offset + attr_len } else { record_size };
        attrs.push((attr_type, record[offset..value_end].to_vec()));
        offset += attr_len;
    }
    attrs
}

struct FileNameInfo {
    name: String,
    parent_ref: u64,  // MFT record number of parent directory
}

fn extract_file_name_info(attr_data: &[u8]) -> Option<FileNameInfo> {
    if attr_data.len() < 0x18 { return None; }
    let non_resident = attr_data[ATTR_NON_RESIDENT_FLAG];
    if non_resident != 0 { return None; }

    let value_len = u32::from_le_bytes([attr_data[ATTR_RESIDENT_VALUE_LEN], attr_data[ATTR_RESIDENT_VALUE_LEN + 1], attr_data[ATTR_RESIDENT_VALUE_LEN + 2], attr_data[ATTR_RESIDENT_VALUE_LEN + 3]]) as usize;
    let value_offset = u16::from_le_bytes([attr_data[ATTR_RESIDENT_VALUE_OFF], attr_data[ATTR_RESIDENT_VALUE_OFF + 1]]) as usize;
    if value_offset + value_len > attr_data.len() { return None; }

    let parent_ref = u64::from_le_bytes([
        attr_data[value_offset + FN_PARENT_REF_OFFSET], attr_data[value_offset + FN_PARENT_REF_OFFSET + 1],
        attr_data[value_offset + FN_PARENT_REF_OFFSET + 2], attr_data[value_offset + FN_PARENT_REF_OFFSET + 3],
        attr_data[value_offset + FN_PARENT_REF_OFFSET + 4], attr_data[value_offset + FN_PARENT_REF_OFFSET + 5],
        0, 0,
    ]);

    let name_start = value_offset + FN_NAME_START_OFFSET;
    if name_start + 2 > attr_data.len() { return None; }
    let name_len = attr_data[value_offset + FN_NAME_LENGTH_OFFSET] as usize;
    if name_len == 0 || name_len > 255 { return None; }
    if name_start + name_len * 2 > attr_data.len() { return None; }

    let name_utf16: Vec<u16> = attr_data[name_start..name_start + name_len * 2]
        .chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let name = String::from_utf16_lossy(&name_utf16);

    Some(FileNameInfo { name, parent_ref })
}

fn parse_data_runs(attr_data: &[u8], max_clusters: u64) -> Vec<(u64, u64)> {
    if attr_data.len() < 0x40 { return vec![]; }
    let non_resident = attr_data[ATTR_NON_RESIDENT_FLAG];
    if non_resident == 0 { return vec![]; }

    let data_run_offset = u16::from_le_bytes([attr_data[ATTR_DATA_RUN_OFFSET], attr_data[ATTR_DATA_RUN_OFFSET + 1]]) as usize;
    if data_run_offset >= attr_data.len() { return vec![]; }

    let mut runs = Vec::new();
    let mut offset = data_run_offset;
    let mut prev_lcn: i64 = 0;

    while offset < attr_data.len() {
        let dr_byte = attr_data[offset];
        if dr_byte == 0 { break; }
        let count_bytes = (dr_byte & 0x0F) as usize;
        let offset_bytes = ((dr_byte >> 4) & 0x0F) as usize;
        if count_bytes == 0 { break; }
        offset += 1;
        if offset + count_bytes + offset_bytes > attr_data.len() { break; }

        let mut count: u64 = 0;
        for j in 0..count_bytes {
            count |= (attr_data[offset + j] as u64) << (j * 8);
        }
        offset += count_bytes;

        let mut lcn_raw: u64 = 0;
        for j in 0..offset_bytes {
            lcn_raw |= (attr_data[offset + j] as u64) << (j * 8);
        }
        if offset_bytes > 0 && (lcn_raw >> ((offset_bytes * 8) - 1)) != 0 {
            lcn_raw |= !((1u64 << (offset_bytes * 8)) - 1);
        }
        offset += offset_bytes;

        let lcn_offset = lcn_raw as i64;
        prev_lcn = prev_lcn.wrapping_add(lcn_offset);
        if prev_lcn >= 0 {
            let lcn = prev_lcn as u64;
            // Validate LCN against volume size to catch corrupt data runs in deleted files
            if lcn + count <= max_clusters {
                runs.push((lcn, count));
            } else {
                break;
            }
        }
    }
    runs
}

fn extract_data_size(attr_data: &[u8]) -> u64 {
    if attr_data.len() < 0x18 { return 0; }
    let non_resident = attr_data[ATTR_NON_RESIDENT_FLAG];
    if non_resident == 0 {
        u32::from_le_bytes([attr_data[ATTR_RESIDENT_VALUE_LEN], attr_data[ATTR_RESIDENT_VALUE_LEN + 1], attr_data[ATTR_RESIDENT_VALUE_LEN + 2], attr_data[ATTR_RESIDENT_VALUE_LEN + 3]]) as u64
    } else {
        if attr_data.len() < 0x40 { return 0; }
        u64::from_le_bytes([
            attr_data[ATTR_NONRESIDENT_DATA_SIZE], attr_data[ATTR_NONRESIDENT_DATA_SIZE + 1],
            attr_data[ATTR_NONRESIDENT_DATA_SIZE + 2], attr_data[ATTR_NONRESIDENT_DATA_SIZE + 3],
            attr_data[ATTR_NONRESIDENT_DATA_SIZE + 4], attr_data[ATTR_NONRESIDENT_DATA_SIZE + 5],
            attr_data[ATTR_NONRESIDENT_DATA_SIZE + 6], attr_data[ATTR_NONRESIDENT_DATA_SIZE + 7],
        ])
    }
}

fn extract_resident_data(attr_data: &[u8]) -> Option<Vec<u8>> {
    if attr_data.len() < 0x18 { return None; }
    let non_resident = attr_data[ATTR_NON_RESIDENT_FLAG];
    if non_resident != 0 { return None; }
    let value_len = u32::from_le_bytes([attr_data[ATTR_RESIDENT_VALUE_LEN], attr_data[ATTR_RESIDENT_VALUE_LEN + 1], attr_data[ATTR_RESIDENT_VALUE_LEN + 2], attr_data[ATTR_RESIDENT_VALUE_LEN + 3]]) as usize;
    if value_len == 0 { return None; }
    let value_offset = u16::from_le_bytes([attr_data[ATTR_RESIDENT_VALUE_OFF], attr_data[ATTR_RESIDENT_VALUE_OFF + 1]]) as usize;
    if value_offset + value_len > attr_data.len() { return None; }
    Some(attr_data[value_offset..value_offset + value_len].to_vec())
}

fn build_path(parent_map: &std::collections::HashMap<u64, (String, u64)>, mut record: u64) -> String {
    let mut parts = Vec::new();
    let mut visited = std::collections::HashSet::new();
    while record != MFT_ROOT_DIR_RECORD && record != 0 {
        if !visited.insert(record) { break; }
        match parent_map.get(&record) {
            Some((name, parent)) => {
                parts.push(name.clone());
                record = *parent;
            }
            None => break,
        }
    }
    parts.reverse();
    parts.join("/")
}

pub fn scan(file: &mut File, info: &NtfsInfo, results: &mut Vec<DeletedFile>) -> Result<(), String> {
    let record_size = info.mft_record_size as usize;
    let mut record = vec![0u8; record_size];
    let max_records = 100000;
    let base = info.partition_offset;
    let max_clusters = info.total_sectors / info.sectors_per_cluster as u64;

    // First pass: collect all active directories + their names & parent refs
    let mut dir_map: std::collections::HashMap<u64, (String, u64)> = std::collections::HashMap::new();

    for i in 0..max_records {
        let offset = base + info.mft_start + i as u64 * record_size as u64;
        record.fill(0);
        if read_bytes(file, offset, &mut record).is_err() { break; }
        if &record[0..4] != NTFS_FILE_MAGIC { if i > 100 && record.iter().all(|&b| b == 0) { break; } continue; }

        let flags = u16::from_le_bytes([record[MFT_FLAGS_OFFSET], record[MFT_FLAGS_OFFSET + 1]]);
        let in_use = flags & 0x01 != 0;
        let is_dir = flags & 0x02 != 0;

        if !in_use || !is_dir { continue; }

        let attrs = parse_attributes(&record, record_size);
        for (attr_type, attr_data) in &attrs {
            if *attr_type == ATTR_FILE_NAME {
                if let Some(fni) = extract_file_name_info(attr_data) {
                    dir_map.insert(i as u64, (fni.name, fni.parent_ref));
                }
            }
        }
    }

    // Second pass: find deleted records and build paths
    for i in 0..max_records {
        let offset = base + info.mft_start + i as u64 * record_size as u64;
        record.fill(0);
        if read_bytes(file, offset, &mut record).is_err() { break; }
        if &record[0..4] != NTFS_FILE_MAGIC { continue; }

        let flags = u16::from_le_bytes([record[MFT_FLAGS_OFFSET], record[MFT_FLAGS_OFFSET + 1]]);
        let in_use = flags & 0x01 != 0;
        let is_dir = flags & 0x02 != 0;

        if in_use { continue; }

        let attrs = parse_attributes(&record, record_size);
        let mut file_name = None;
        let mut parent_record = MFT_ROOT_DIR_RECORD;
        let mut data_size = 0u64;
        let mut data_runs: Vec<(u64, u64)> = Vec::new();
        let mut resident_data: Option<Vec<u8>> = None;
        let mut has_nameless_data = false;

        for (attr_type, attr_data) in &attrs {
            match *attr_type {
                ATTR_FILE_NAME => {
                    if file_name.is_none() {
                        if let Some(fni) = extract_file_name_info(attr_data) {
                            file_name = Some(fni.name);
                            parent_record = fni.parent_ref;
                        }
                    }
                }
                ATTR_DATA => {
                    let name_len = attr_data.get(ATTR_NAME_LENGTH_OFFSET).copied().unwrap_or(0);
                    let is_nameless = name_len == 0;

                    // Prefer unnamed $DATA attribute; only take named if we have nothing yet
                    if !has_nameless_data || is_nameless {
                        data_size = extract_data_size(attr_data);
                        data_runs = parse_data_runs(attr_data, max_clusters);
                        resident_data = if data_runs.is_empty() && data_size > 0 {
                            extract_resident_data(attr_data)
                        } else {
                            None
                        };
                        if is_nameless {
                            has_nameless_data = true;
                        }
                    }
                }
                _ => {}
            }
        }

        let name = file_name.unwrap_or_else(|| format!("MFT_RECORD_{}", i));
        let start_address = if !data_runs.is_empty() {
            let (lcn, _) = data_runs[0];
            info.partition_offset + lcn * info.bytes_per_sector as u64 * info.sectors_per_cluster as u64
        } else { 0 };

        let path = build_path(&dir_map, parent_record);

        results.push(DeletedFile {
            name, size: data_size, start_address,
            fs_type: "NTFS".into(), path, is_directory: is_dir,
            resident_data, data_runs: data_runs.clone(),
        });
    }

    Ok(())
}

pub fn restore(
    file: &mut File, info: &NtfsInfo, entry: &DeletedFile, target_path: &str,
) -> Result<(), String> {
    let out_path = std::path::Path::new(target_path);
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Cannot create directory: {}", e))?;
    }
    let mut out_file = std::fs::OpenOptions::new()
        .write(true).create(true).truncate(true)
        .open(out_path).map_err(|e| format!("Cannot create output file: {}", e))?;

    // Resident data (stored inline in MFT record)
    if let Some(data) = &entry.resident_data {
        out_file.write_all(data).map_err(|e| format!("Write error: {}", e))?;
        eprintln!("  Restored {} bytes to '{}' (resident)", data.len(), target_path);
        return Ok(());
    }

    let cluster_size = info.bytes_per_sector as u64 * info.sectors_per_cluster as u64;
    let chunk = cluster_size as usize;
    let mut buf = vec![0u8; chunk];
    let mut remaining = entry.size as usize;

    // Follow data runs for correct cluster layout (handles fragmentation)
    for &(lcn, count) in &entry.data_runs {
        let cluster_count = count as usize;
        let mut current_lcn = lcn;
        for _ in 0..cluster_count {
            if remaining == 0 { break; }
            let offset = info.partition_offset + current_lcn * cluster_size;
            // Always read full cluster for sector alignment (volume handles require it)
            read_bytes(file, offset, &mut buf)?;
            let to_write = chunk.min(remaining);
            out_file.write_all(&buf[..to_write]).map_err(|e| format!("Write error: {}", e))?;
            remaining -= to_write;
            current_lcn += 1;
        }
        if remaining == 0 { break; }
    }

    // Fallback: if no data runs (e.g. corrupted) use start_address sequentially
    if entry.data_runs.is_empty() && remaining > 0 {
        let mut current_cluster = entry.start_address / cluster_size;
        while remaining > 0 {
            let offset = info.partition_offset + current_cluster * cluster_size;
            read_bytes(file, offset, &mut buf)?;
            let to_write = chunk.min(remaining);
            out_file.write_all(&buf[..to_write]).map_err(|e| format!("Write error: {}", e))?;
            remaining -= to_write;
            if remaining == 0 { break; }
            current_cluster += 1;
        }
    }

    eprintln!("  Restored {} bytes to '{}'", entry.size - remaining as u64, target_path);
    Ok(())
}
