use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use crate::types::DeletedFile;

const EXT2_MAGIC: u16 = 0xEF53;
const EXT2_ROOT_INODE: u32 = 2;

#[derive(Debug, Clone)]
pub struct ExtInfo {
    pub block_size: u32,
    pub inodes_per_group: u32,
    pub inode_size: u16,
    pub bgdt_block: u64,
    pub partition_offset: u64,
}

fn read_bytes(file: &mut File, offset: u64, buf: &mut [u8]) -> Result<(), String> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Seek error: {}", e))?;
    file.read_exact(buf)
        .map_err(|e| format!("Read error: {}", e))?;
    Ok(())
}

pub fn probe(file: &mut File) -> Option<ExtInfo> {
    let mut buf = [0u8; 2048];
    if read_bytes(file, 0, &mut buf).is_err() { return None; }

    parse_ext_buf(&buf)
}

pub fn probe_from_buf(buf: &[u8; 2048]) -> Option<ExtInfo> {
    parse_ext_buf(buf)
}

fn parse_ext_buf(buf: &[u8; 2048]) -> Option<ExtInfo> {
    let sb_off = 1024usize;
    let magic = u16::from_le_bytes([buf[sb_off + 56], buf[sb_off + 57]]);
    if magic != EXT2_MAGIC { return None; }

    let block_size_shift = u32::from_le_bytes([buf[sb_off + 24], buf[sb_off + 25], buf[sb_off + 26], buf[sb_off + 27]]);
    let block_size = 1024u32 << block_size_shift;
    if block_size < 1024 || block_size > 65536 { return None; }

    let inodes_per_group = u32::from_le_bytes([buf[sb_off + 40], buf[sb_off + 41], buf[sb_off + 42], buf[sb_off + 43]]);
    let inode_size = u16::from_le_bytes([buf[sb_off + 88], buf[sb_off + 89]]);
    if inode_size < 128 || inode_size > 2048 { return None; }

    // BGDT location:
    // If block_size == 1024: superblock is at block 1, BGDT is at block 2
    // If block_size > 1024: superblock is at block 0, BGDT is at block 1
    let bgdt_block = if block_size == 1024 { 2u64 } else { 1u64 };

    Some(ExtInfo {
        block_size, inodes_per_group, inode_size, bgdt_block,
        partition_offset: 0,
    })
}

fn read_inode(file: &mut File, info: &ExtInfo, inode_num: u32) -> Option<Vec<u8>> {
    let group = (inode_num - 1) / info.inodes_per_group;
    let index = (inode_num - 1) % info.inodes_per_group;

    // Read BGDT for this group
    let bgdt_off = info.partition_offset + info.bgdt_block as u64 * info.block_size as u64 + group as u64 * 32;
    let mut bgd = [0u8; 12]; // Just need first 12 bytes (bitmap, inode_table, etc.)
    if read_bytes(file, bgdt_off, &mut bgd).is_err() { return None; }

    let inode_table_block = u32::from_le_bytes([bgd[8], bgd[9], bgd[10], bgd[11]]);
    if inode_table_block == 0 { return None; }

    let inode_offset = info.partition_offset + inode_table_block as u64 * info.block_size as u64 + index as u64 * info.inode_size as u64;
    let mut inode_buf = vec![0u8; info.inode_size as usize];
    if read_bytes(file, inode_offset, &mut inode_buf).is_err() { return None; }
    Some(inode_buf)
}

fn read_block(file: &mut File, info: &ExtInfo, block_num: u64, buf: &mut [u8]) -> Result<(), String> {
    let offset = info.partition_offset + block_num * info.block_size as u64;
    read_bytes(file, offset, buf)
}

fn get_inode_blocks(inode: &[u8]) -> Vec<u64> {
    if inode.len() < 0x64 { return vec![]; }
    let mut blocks = Vec::new();
    // i_block array starts at offset 0x28, has 15 entries
    // For ext4 without 64bit feature, each entry is u32
    for i in 0..15 {
        let off = 0x28 + i * 4;
        if off + 4 > inode.len() { break; }
        let block = u32::from_le_bytes([inode[off], inode[off+1], inode[off+2], inode[off+3]]);
        if block != 0 {
            blocks.push(block as u64);
        }
    }
    blocks
}

fn scan_dir_block(
    file: &mut File, info: &ExtInfo, block_data: &[u8],
    current_path: &str, results: &mut Vec<DeletedFile>,
) {
    let mut pos = 0;
    while pos + 8 <= block_data.len() {
        let inode = u32::from_le_bytes([block_data[pos], block_data[pos+1], block_data[pos+2], block_data[pos+3]]);
        let rec_len = u16::from_le_bytes([block_data[pos+4], block_data[pos+5]]) as usize;
        if rec_len < 8 || pos + rec_len > block_data.len() { break; }
        if rec_len == 0 { break; }

        let name_len = block_data[pos+6] as usize;
        if name_len == 0 || pos + 8 + name_len > block_data.len() { pos += rec_len; continue; }

        let name_bytes = &block_data[pos+8..pos+8+name_len];
        let name = String::from_utf8_lossy(name_bytes).to_string();

        if inode == 0 {
            // Deleted entry
            let name_clean: String = name.chars().filter(|c| c.is_alphanumeric() || c.is_ascii_punctuation() || *c == ' ').collect();
            if name_clean.is_empty() || name_clean == "." || name_clean == ".." { pos += rec_len; continue; }

            results.push(DeletedFile {
                name: name_clean, size: 0, start_address: 0,
                fs_type: "ext4".into(), path: current_path.to_string(),
                is_directory: false, resident_data: None,
                data_runs: vec![],
            });
        } else if name != "." && name != ".." {
            // Active entry - try to recurse if directory
            let file_type = block_data[pos+7]; // 1=regular, 2=dir
            if file_type == 2 {
                let sub_path = if current_path.is_empty() { name.clone() }
                    else { format!("{}/{}", current_path, name) };
                if let Some(inode_data) = read_inode(file, info, inode) {
                    let blocks = get_inode_blocks(&inode_data);
                    for &block in &blocks {
                        let mut dir_buf = vec![0u8; info.block_size as usize];
                        if read_block(file, info, block, &mut dir_buf).is_ok() {
                            scan_dir_block(file, info, &dir_buf, &sub_path, results);
                        }
                    }
                }
            }
        }

        pos += rec_len;
    }
}

pub fn scan(file: &mut File, info: &ExtInfo, results: &mut Vec<DeletedFile>) -> Result<(), String> {
    // Read root directory (inode 2)
    let root_inode = match read_inode(file, info, EXT2_ROOT_INODE) {
        Some(i) => i,
        None => return Err("Cannot read root inode".into()),
    };

    let blocks = get_inode_blocks(&root_inode);
    for &block in &blocks {
        let mut dir_buf = vec![0u8; info.block_size as usize];
        read_block(file, info, block, &mut dir_buf)?;
        scan_dir_block(file, info, &dir_buf, "", results);
    }

    Ok(())
}


