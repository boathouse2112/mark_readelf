use std::cmp;
use std::fmt::{Debug, Display, Formatter};

use crate::to_str;

pub struct OsAbi(pub u8);

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
pub enum FileType {
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

pub struct Machine(pub u16);

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
pub struct ElfHeader32 {
    // Magic number not necessary
    pub os_abi: OsAbi,
    pub abi_version: u8,
    pub file_type: FileType,
    pub machine: Machine,
    pub entry: u32,
    pub program_header_offset: u32,
    pub section_header_offset: u32,
    pub elf_header_size: u16,
    pub program_header_entry_size: u16,
    pub program_header_entries: u16,
    pub section_header_entry_size: u16,
    pub section_header_entries: u16,
    pub string_table_index: u16,
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
