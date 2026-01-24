use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

fn main() {
    let h_process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, get_pid()) };
    println!("[i] Result of open process: {:?}", h_process);
    println!("SCIL testing payload.. Will see all the SSNs called via Alt Syscalls.");
}

fn get_pid() -> u32 {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 2 {
        panic!("Please specify a pid to open.");
    }

    a[1].parse::<u32>().unwrap()
}