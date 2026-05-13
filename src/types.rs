#[derive(Debug, Clone)]
pub struct DeletedFile {
    pub name: String,
    pub size: u64,
    pub start_address: u64,
    pub fs_type: String,
    pub path: String,
    pub is_directory: bool,
    pub resident_data: Option<Vec<u8>>,
    pub data_runs: Vec<(u64, u64)>,
}

pub fn is_directory(attr: u8) -> bool {
    attr & 0x10 != 0
}


