fn main() {
    let b = get_box();
    println!("SCIL testing payload.. Will see all the SSNs called via Alt Syscalls. B: {}, addr: {:p}", b, b.as_ptr());
}

fn get_box() -> Box<String> {
    let b = Box::new("Hello".to_string());
    b
}