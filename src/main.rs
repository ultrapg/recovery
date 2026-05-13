mod types;
mod fat;
mod ntfs;
mod ext;
mod disk;

use std::env;
use std::io::{Read, Seek, SeekFrom};
use std::fs::{File, OpenOptions};
use std::path::Path;

#[cfg(target_os = "windows")]
use std::os::windows::fs::OpenOptionsExt;

use types::DeletedFile;

fn open_device(path: &str) -> Result<File, String> {
    #[cfg(target_os = "windows")]
    {
        OpenOptions::new()
            .read(true).write(false).share_mode(0x7)
            .custom_flags(0)
            .open(path)
            .map_err(|e| format!("Cannot open {}. Run as Administrator. Error: {}", path, e))
    }
    #[cfg(not(target_os = "windows"))]
    {
        OpenOptions::new().read(true).open(path)
            .map_err(|e| format!("Cannot open {}. Try with sudo. Error: {}", path, e))
    }
}

fn resolve_path(input: &str) -> (String, String) {
    #[cfg(target_os = "windows")]
    {
        if input.starts_with("\\\\.\\") {
            return (input.to_string(), String::new());
        }

        let p = Path::new(input);

        let drive_letter = p.components().next()
            .and_then(|c| c.as_os_str().to_str())
            .and_then(|s| {
                let s = s.trim_end_matches(':');
                if s.len() == 1 && s.as_bytes()[0].is_ascii_alphabetic() {
                    Some(s.to_ascii_uppercase())
                } else {
                    None
                }
            });

        if let Some(drive) = drive_letter {
            let device = format!("\\\\.\\{}:", drive);

            let filter = p.strip_prefix(format!("{}:", drive))
                .or_else(|_| p.strip_prefix(format!("{}:\\", drive)))
                .ok()
                .and_then(|p| {
                    let s = p.to_str().unwrap_or("");
                    let s = s.replace('\\', "/");
                    let s = s.trim_matches('/').to_string();
                    if s.is_empty() { None } else { Some(s) }
                })
                .unwrap_or_default();

            (device, filter)
        } else {
            (input.to_string(), String::new())
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        (input.to_string(), String::new())
    }
}

fn read_boot_sector(file: &mut File, buf: &mut [u8; 512]) -> bool {
    file.seek(SeekFrom::Start(0)).is_ok() && file.read_exact(buf).is_ok()
}

fn matches_path(path: &str, filter: &str) -> bool {
    if filter.is_empty() { true } else { path == filter || path.starts_with(&format!("{}/", filter)) }
}

fn matches_search(name: &str, search: Option<&str>) -> bool {
    match search {
        None => true,
        Some(pattern) => name.to_lowercase().contains(&pattern.to_lowercase()),
    }
}

fn print_table(results: &[DeletedFile]) {
    if results.is_empty() {
        println!("\nNo deleted files found.");
        return;
    }

    let mut max_name_len = "Name".len();
    let mut max_size_len = "Size".len();
    let mut max_addr_len = "Start Address".len();
    let mut max_path_len = "Path".len();
    let mut max_fs_len = "FS".len();

    for f in results {
        max_name_len = max_name_len.max(f.name.len());
        let size_str = format!("{}", f.size);
        max_size_len = max_size_len.max(size_str.len());
        let addr_str = format!("0x{:08X}", f.start_address);
        max_addr_len = max_addr_len.max(addr_str.len());
        max_path_len = max_path_len.max(f.path.len());
        max_fs_len = max_fs_len.max(f.fs_type.len());
    }

    max_name_len = max_name_len.min(60);
    max_path_len = max_path_len.min(40);

    let status_col = "Status".len().max(12);
    let total_width = status_col + 3 + max_name_len + 3 + max_size_len + 3
        + max_addr_len + 3 + max_path_len + 3 + max_fs_len + 1;
    let _sep = "-".repeat(total_width);

    println!("\nDeleted Files:");
    let hline = |c, n, s, a, f, p| format!("+{0}+{1}+{2}+{3}+{4}+{5}+", c, n, s, a, f, p);
    let h = hline(sep_line(status_col), sep_line(max_name_len), sep_line(max_size_len), sep_line(max_addr_len), sep_line(max_fs_len), sep_line(max_path_len));
    println!("\nDeleted Files:");
    println!("{}", h);
    print!("| {:1$} |", "Status", status_col);
    print!(" {:1$} |", "Name", max_name_len);
    print!(" {:>1$} |", "Size", max_size_len);
    print!(" {:1$} |", "Start Address", max_addr_len);
    print!(" {:1$} |", "FS", max_fs_len);
    println!(" {:1$} |", "Path", max_path_len);
    println!("{}", h);

    for f in results {
        let status = if f.is_directory { "Deleted (Dir)" } else { "Deleted" };

        let name_display = if f.name.len() > max_name_len {
            format!("{}...", &f.name[..max_name_len.saturating_sub(3)])
        } else { f.name.clone() };

        let path_display = if f.path.len() > max_path_len {
            format!("...{}", &f.path[f.path.len().saturating_sub(max_path_len - 3)..])
        } else { f.path.clone() };

        print!("| {:1$} |", status, status_col);
        print!(" {:1$} |", name_display, max_name_len);
        print!(" {:>1$} |", f.size.to_string(), max_size_len);
        print!(" {:1$} |", format!("0x{:08X}", f.start_address), max_addr_len);
        print!(" {:1$} |", f.fs_type, max_fs_len);
        println!(" {:1$} |", path_display, max_path_len);
    }

    println!("{}", h);
    println!("\nFound {} deleted entr{}.", results.len(), if results.len() == 1 { "y" } else { "ies" });
}

fn print_help(exe: &str) {
    eprintln!(
        "USB/Drive Deleted File Recovery Tool\n\
        \n\
        USAGE:\n  {} <PATH> [OPTIONS]\n\
        \n\
        ARGS:\n  <PATH>    Device path, disk path, or directory path\n            Windows volume: \\\\.\\D:  /  C:  /  C:\\Users\\...\n            Windows disk:   \\\\.\\PhysicalDrive0 (scans all partitions)\n            Linux:          /dev/sdb1\n\
        \n\
        SUPPORTED FILESYSTEMS:\n  FAT32 / exFAT / NTFS / ext2/ext3/ext4\n\
        \n\
        NOTES:\n  - C: (system drive) cannot be opened for raw access while Windows runs.\n    Use a Linux Live USB or external USB adapter.\n  - \\\\.\\PhysicalDriveN scans all MBR partitions on the disk (admin required).\n    Restore is not supported from PhysicalDrive paths; use the volume path instead.\n  - ext4 restore is not supported (inode pointer cleared on deletion).\n\
        \n\
        OPTIONS:\n  --restore <INDEX>  Restore file at INDEX\n  --output <PATH>     Target path for restore\n  --search <NAME>     Search deleted files by name (case-insensitive, partial match)\n  --help, -h          Print help\n\
        \n\
        EXAMPLES:\n  {} \\\\.\\E:\n  {} C:\n  {} C:\\Users\\Marvin\\Downloads\n  {} D: --search .docx\n  {} D: --search report --restore 0 --output recovered.docx\n  {} \\\\.\\PhysicalDrive0\n  {} /dev/sdb1\n",
        exe, exe, exe, exe, exe, exe, exe, exe,
    );
}

fn parse_flag_value<T: std::str::FromStr>(args: &[String], flag: &str, desc: &str) -> Option<T> {
    args.iter().position(|a| a == flag).and_then(|i| {
        match args.get(i + 1) {
            None => {
                eprintln!("ERROR: {} requires {} argument", flag, desc);
                std::process::exit(1);
            }
            Some(val) => match val.parse::<T>() {
                Ok(v) => Some(v),
                Err(_) => {
                    eprintln!("ERROR: {} value '{}' is not a valid {}", flag, val, desc);
                    std::process::exit(1);
                }
            },
        }
    })
}

fn sep_line(len: usize) -> String {
    "-".repeat(len + 2)
}

fn parse_flag_str<'a>(args: &'a [String], flag: &str, desc: &str) -> Option<&'a str> {
    args.iter().position(|a| a == flag).and_then(|i| {
        match args.get(i + 1) {
            None => {
                eprintln!("ERROR: {} requires {} argument", flag, desc);
                std::process::exit(1);
            }
            Some(val) => Some(val.as_str()),
        }
    })
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let exe = args.get(0).map(|s| s.as_str()).unwrap_or("recovery");

    if args.len() < 2 || args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        print_help(exe);
        return;
    }

    let input_path = &args[1];
    let restore_index = parse_flag_value::<usize>(&args, "--restore", "numeric INDEX");
    let output_path = parse_flag_str(&args, "--output", "PATH");
    let search_filter = parse_flag_str(&args, "--search", "NAME");

    let (device_path, filter_path) = resolve_path(input_path);

    let mut show_scan = true;

    if device_path != *input_path && Path::new(input_path).is_dir() {
        eprintln!("Scanning volume for deleted files in: {}", filter_path);
        show_scan = false;
    }

    if show_scan {
        eprintln!("Opening device: {} (READ-ONLY mode)", device_path);
    } else {
        eprintln!("Resolved to device: {} (READ-ONLY)", device_path);
    }

    let mut file = match open_device(&device_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("ERROR: {}", e);
            if device_path.to_uppercase().starts_with("\\\\.\\C:") {
                eprintln!();
                eprintln!("C: is the Windows system drive and cannot be opened for raw access while Windows is running.");
                eprintln!("This is an OS-level restriction.");
                eprintln!();
                eprintln!("Possible solutions:");
                eprintln!("  1. Boot from a Linux Live USB and scan C: from there");
                eprintln!("  2. Use a different tool that works via Volume Shadow Copy (VSS)");
                eprintln!("  3. Remove the drive and connect it via a USB adapter, then scan it as D:/E: etc.");
                eprintln!("  4. Use a dedicated recovery tool like Recuva, TestDisk, or PhotoRec");
            } else {
                eprintln!();
                eprintln!("Make sure no other program has the volume locked exclusively.");
                eprintln!("Close any file explorer windows or programs accessing that drive and try again.");
            }
            std::process::exit(1);
        }
    };

    // Disk-level scanning for \\.\PhysicalDriveN
    if device_path.starts_with("\\\\.\\PhysicalDrive") {
        eprintln!("Scanning physical disk for all partitions...\n");
        let mut all: Vec<DeletedFile> = Vec::new();
        disk::scan_disk(&mut file, &mut all);
        let results: Vec<DeletedFile> = all.into_iter()
            .filter(|f| matches_search(&f.name, search_filter))
            .collect();
        if restore_index.is_some() {
            eprintln!("Restore from PhysicalDrive path not supported directly.\nUse the volume path (e.g. \\\\.\\E:) after identifying the right partition.");
        } else {
            print_table(&results);
        }
        return;
    }

    // Read boot sector once and pass buffer to all probes
    let mut boot = [0u8; 512];
    let can_read_boot = read_boot_sector(&mut file, &mut boot);

    eprintln!("Probing filesystem...");

    // Try each filesystem type in order using the shared buffer
    if can_read_boot {
        // FAT32
        if let Some(info) = fat::probe_fat32_from_buf(&boot) {
            eprintln!("Detected: FAT32 (bytes/sector={}, sectors/cluster={}, root cluster={})",
                info.bytes_per_sector, info.sectors_per_cluster, info.root_cluster);
            let mut all: Vec<DeletedFile> = Vec::new();
            if let Err(e) = fat::scan_fat32(&mut file, &info, &mut all) {
                eprintln!("Scan error: {}", e);
            }
            let results: Vec<DeletedFile> = all.into_iter()
                .filter(|f| matches_path(&f.path, &filter_path))
                .filter(|f| matches_search(&f.name, search_filter))
                .collect();
            handle_results(results, restore_index, output_path,
                |entry, target| fat::restore_fat32(&mut file, &info, entry, target));
            return;
        }

        // exFAT
        if let Some(info) = fat::probe_exfat_from_buf(&boot) {
            eprintln!("Detected: exFAT (bytes/sector={}, sectors/cluster={}, root cluster={})",
                info.bytes_per_sector, info.sectors_per_cluster, info.root_cluster);
            let mut all: Vec<DeletedFile> = Vec::new();
            if let Err(e) = fat::scan_exfat(&mut file, &info, &mut all) {
                eprintln!("Scan error: {}", e);
            }
            let results: Vec<DeletedFile> = all.into_iter()
                .filter(|f| matches_path(&f.path, &filter_path))
                .filter(|f| matches_search(&f.name, search_filter))
                .collect();
            handle_results(results, restore_index, output_path,
                |entry, target| fat::restore_exfat(&mut file, &info, entry, target));
            return;
        }

        // NTFS
        if let Some(info) = ntfs::probe_from_buf(&boot) {
            eprintln!("Detected: NTFS (MFT at offset 0x{:X}, record size={})",
                info.mft_start, info.mft_record_size);
            let mut all: Vec<DeletedFile> = Vec::new();
            if let Err(e) = ntfs::scan(&mut file, &info, &mut all) {
                eprintln!("Scan error: {}", e);
            }
            if !filter_path.is_empty() {
                eprintln!("  Note: path filtering not supported for NTFS (showing all results)");
            }
            let results: Vec<DeletedFile> = all.into_iter()
                .filter(|f| matches_search(&f.name, search_filter))
                .collect();
            handle_results(results, restore_index, output_path,
                |entry, target| ntfs::restore(&mut file, &info, entry, target));
            return;
        }
    }

    // ext4 superblock is at offset 1024, not in the first 512 bytes
    if let Some(info) = ext::probe(&mut file) {
        eprintln!("Detected: ext4 (block size={})", info.block_size);
        let mut all: Vec<DeletedFile> = Vec::new();
        if let Err(e) = ext::scan(&mut file, &info, &mut all) {
            eprintln!("Scan error: {}", e);
        }
        let results: Vec<DeletedFile> = all.into_iter()
            .filter(|f| matches_path(&f.path, &filter_path))
            .filter(|f| matches_search(&f.name, search_filter))
            .collect();
        handle_results(results, restore_index, output_path,
            |_, _| Err("ext4 restore not supported".into()));
        return;
    }

    if can_read_boot {
        eprintln!("ERROR: Could not detect filesystem on this volume.");
        eprintln!("Boot sector signature found, but filesystem type not recognized.");
        eprintln!("This tool supports: FAT32, exFAT, NTFS, ext2/ext3/ext4");
    } else {
        eprintln!("ERROR: Cannot read boot sector. Access denied or device not available.");
        if device_path.contains("\\\\.\\C:") {
            eprintln!("C: is the system drive – Windows locks it exclusively.");
            eprintln!("Solution: Boot from a Linux Live USB or remove the drive and scan via USB adapter.");
        } else {
            eprintln!("Try running as Administrator and close any programs accessing the drive.");
        }
    }
    std::process::exit(1);
}

fn handle_results(
    results: Vec<DeletedFile>,
    restore_index: Option<usize>,
    output_path: Option<&str>,
    restore_fn: impl FnOnce(&DeletedFile, &str) -> Result<(), String>,
) {
    if let Some(idx) = restore_index {
        if idx >= results.len() {
            eprintln!("ERROR: Index {} out of range (0-{})", idx, results.len().saturating_sub(1));
            return;
        }
        let target = output_path.unwrap_or("recovered.bin");
        let entry = &results[idx];
        eprintln!("Restoring '{}' ({} bytes, address 0x{:X}) to '{}'...",
            entry.name, entry.size, entry.start_address, target);
        if entry.start_address == 0 && entry.resident_data.is_none() && entry.size > 0 {
            eprintln!("ERROR: Start address is 0 – cannot restore (no resident data).");
            return;
        }
        if entry.size == 0 {
            eprintln!("WARNING: File size is 0, nothing to restore.");
            return;
        }
        if let Err(e) = restore_fn(entry, target) {
            eprintln!("Restore error: {}", e);
        }
    } else {
        print_table(&results);
    }
}
