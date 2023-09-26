use std::error::Error;
use std::fs;

mod abi;
mod elf;
mod parse;
mod to_str;

fn main() -> Result<(), Box<dyn Error>> {
    let file_path = "/Users/boathouse/Projects/questions/static_vars/target/i686-unknown-none/debug/static_vars";
    let buffer = fs::read(file_path)?;
    let elf = parse::parse_elf(&buffer)?;
    elf.print_elf_header();
    println!();
    elf.print_program_header_table(false);
    Ok(())
}
