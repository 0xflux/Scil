mod inject_shellcode;

fn main() {
    inject_shellcode::inject_shellcode();
}

// fn get_pid() -> u32 {
//     let a: Vec<String> = std::env::args().collect();
//     if a.len() != 2 {
//         panic!("Please specify a pid to open.");
//     }

//     a[1].parse::<u32>().unwrap()
// }
