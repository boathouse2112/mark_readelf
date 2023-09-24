use core::convert::TryInto;
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::{cmp, fs};

use parse::ParseError;

mod abi;
mod parse;
mod to_str;

struct OsAbi(u8);
impl Debug for OsAbi {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let &OsAbi(value) = self;
        let value = to_str::e_osabi_to_str(value).ok_or(std::fmt::Error)?;
        write!(f, "{value}")
    }
}
impl Display for OsAbi {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let &OsAbi(value) = self;
        let value = to_str::e_osabi_to_human_string(value).ok_or(std::fmt::Error)?;
        write!(f, "{value}")
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
enum FileType {
    None,
    // Unknown.
    Rel,
    // Relocatable file.
    Exec,
    // Executable file.
    Dyn,
    // Shared object.
    Core, // Core file -- for core dumps
          // I don't know what the os/processor specific reserved ones are for.
}
impl Display for FileType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let human_str = match self {
            FileType::None => "No file type",
            FileType::Rel => "Relocatable file",
            FileType::Exec => "Executable file",
            FileType::Dyn => "Shared object file",
            FileType::Core => "Core file",
        };
        write!(f, "{human_str}")
    }
}

struct Machine(u16);
impl Debug for Machine {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let &Machine(value) = self;
        let value = to_str::e_machine_to_str(value).ok_or(std::fmt::Error)?;
        write!(f, "{value}")
    }
}
impl Display for Machine {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let &Machine(value) = self;
        let value = to_str::e_machine_to_human_str(value).ok_or(std::fmt::Error)?;
        write!(f, "{value}")
    }
}

/// Header at the start of the ELF file
#[derive(Debug)]
struct ElfHeader32 {
    // Magic number not necessary
    os_abi: OsAbi,
    abi_version: u8,
    file_type: FileType,
    machine: Machine,
    entry: u32,
    program_header_offset: u32,
    section_header_offset: u32,
    elf_header_size: u16,
    program_header_entry_size: u16,
    program_header_entries: u16,
    section_header_entry_size: u16,
    section_header_entries: u16,
    string_table_index: u16,
}

/// Parse ints from a little-endian byte array
struct Parser<'buffer> {
    offset: usize,
    buffer: &'buffer [u8],
}

impl<'buffer> Parser<'buffer> {
    fn new(buffer: &'buffer [u8]) -> Self {
        Self { offset: 0, buffer }
    }

    fn parse_u8(&mut self) -> Result<u8, ParseError> {
        let start = self.offset;
        let end = self.offset + 1;
        let value = self
            .buffer
            .get(start)
            .cloned()
            .ok_or(ParseError::SliceReadError((start, end)))?;
        self.offset = end;
        Ok(value)
    }

    fn parse_u16(&mut self) -> Result<u16, ParseError> {
        let start = self.offset;
        let end = self.offset + 2;
        let slice: &[u8] = self
            .buffer
            .get(start..end)
            .ok_or(ParseError::SliceReadError((start, end)))?;
        let value = u16::from_le_bytes(slice.try_into()?);
        self.offset = end;
        Ok(value)
    }

    fn parse_u32(&mut self) -> Result<u32, ParseError> {
        let start = self.offset;
        let end = self.offset + 4;
        let slice: &[u8] = self
            .buffer
            .get(start..end)
            .ok_or(ParseError::SliceReadError((start, end)))?;
        let value = u32::from_le_bytes(slice.try_into()?);
        self.offset = end;
        Ok(value)
    }

    fn skip_u8(&mut self) {
        self.offset += 1;
    }

    fn skip_u16(&mut self) {
        self.offset += 2;
    }

    fn skip_u32(&mut self) {
        self.offset += 4;
    }
}

/// Verify identification bytes at start of ELF file
fn verify_e_ident(buffer: &[u8]) -> Result<(), ParseError> {
    let magic = buffer.split_at(abi::EI_CLASS).0; // Header has e_ident bytes, then EI_CLASS
    if magic != abi::ELFMAGIC {
        return Err(ParseError::BadMagic([
            magic[0], magic[1], magic[2], magic[3],
        ]));
    }

    // We care only for ELF32,
    // little endian
    let class = buffer[abi::EI_CLASS];
    if class != abi::ELFCLASS32 {
        return Err(ParseError::UnsupportedElfClass(class));
    }
    let endianness = buffer[abi::EI_DATA];
    if endianness != abi::ELFDATA2LSB {
        return Err(ParseError::UnsupportedElfEndianness(endianness));
    }

    // Must be ELF current version
    let specification_version = buffer[abi::EI_VERSION];
    if specification_version != abi::EV_CURRENT {
        return Err(ParseError::UnsupportedVersion((
            specification_version as u64,
            abi::EV_CURRENT as u64,
        )));
    }

    Ok(())
}

/// Parse the interesting data from e_ident. We care about:
/// - OSABI
/// - ABIVERSION
fn parse_e_ident(buffer: &[u8]) -> Result<(OsAbi, u8), ParseError> {
    verify_e_ident(buffer)?;
    let os_abi = buffer[abi::EI_OSABI];
    let abi_version = buffer[abi::EI_ABIVERSION];
    Ok((OsAbi(os_abi), abi_version))
}

fn parse_elf_header_32(buffer: &[u8]) -> Result<ElfHeader32, ParseError> {
    let (os_abi, abi_version) = parse_e_ident(&buffer[..abi::EI_NIDENT])?;

    let mut parser = Parser::new(&buffer[abi::EI_NIDENT..]);

    let file_type = parser.parse_u16()?;
    let file_type = match file_type {
        0 => Ok(FileType::None),
        1 => Ok(FileType::Rel),
        2 => Ok(FileType::Exec),
        3 => Ok(FileType::Dyn),
        4 => Ok(FileType::Core),
        file_type => Err(ParseError::UnsupportedFileType(file_type)),
    }?;
    let machine = parser.parse_u16()?;
    let machine = Machine(machine);
    parser.skip_u32(); // e_version, already checked
    let entry = parser.parse_u32()?;
    let program_header_offset = parser.parse_u32()?;
    let section_header_offset = parser.parse_u32()?;
    parser.skip_u32(); // flags: u32, always 0
    let elf_header_size = parser.parse_u16()?;
    let program_header_entry_size = parser.parse_u16()?;
    let program_header_entries = parser.parse_u16()?;
    let section_header_entry_size = parser.parse_u16()?;
    let section_header_entries = parser.parse_u16()?;
    let string_table_index = parser.parse_u16()?;

    Ok(ElfHeader32 {
        os_abi,
        abi_version,
        file_type,
        machine,
        entry,
        program_header_offset,
        section_header_offset,
        elf_header_size,
        program_header_entry_size,
        program_header_entries,
        section_header_entry_size,
        section_header_entries,
        string_table_index,
    })
}

impl Display for ElfHeader32 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let rows: Vec<(&str, String)> = vec![
            (
                "Magic",
                "7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00".to_string(),
            ),
            ("Class", "ELF32".to_string()),
            ("Data", "2's complement, little endian".to_string()),
            ("Version", "1 (current)".to_string()),
            ("OS/ABI", format!("{}", self.os_abi)),
            ("ABI Version", self.abi_version.to_string()),
            ("Type", format!("{}", self.file_type)),
            ("Machine", format!("{}", self.machine)),
            ("Version", "0x1".to_string()),
            ("Entry point address", self.entry.to_string()),
            (
                "Start of program headers",
                self.program_header_offset.to_string(),
            ),
            (
                "Start of section headers",
                self.section_header_offset.to_string(),
            ),
            ("Flags", "0x0".to_string()),
            (
                "Size of this header",
                format!("{} (bytes)", self.elf_header_size),
            ),
            (
                "Size of program headers",
                format!("{} (bytes)", self.program_header_entry_size),
            ),
            (
                "Number of program headers",
                self.program_header_entries.to_string(),
            ),
            (
                "Size of section headers",
                format!("{} (bytes)", self.section_header_entry_size),
            ),
            (
                "Number of section headers",
                self.section_header_entries.to_string(),
            ),
            (
                "Section header string table index",
                self.string_table_index.to_string(),
            ),
        ];

        let longest_field_length = "Section header string table index: ".len();

        writeln!(f, "ELF Header:")?;
        for (field, value) in rows {
            let padding = cmp::max(longest_field_length - field.len(), 0);
            let padding = " ".repeat(padding);
            writeln!(f, "  {field}:{padding}{value}")?;
        }
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let file_path = "/Users/boathouse/Projects/questions/static_vars/target/i686-unknown-none/debug/static_vars";
    let buffer = fs::read(file_path)?;
    let header = parse_elf_header_32(&buffer)?;
    println!("{header}");
    Ok(())
}
