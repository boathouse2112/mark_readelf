use std::cmp;
use std::fmt::Debug;

use crate::elf::header::ElfHeader;
use crate::elf::program_header::ProgramHeader;

pub mod header;
pub mod program_header;

pub struct Elf {
    pub header: ElfHeader,
    pub program_header_table: Vec<ProgramHeader>,
}

impl Elf {
    fn print_program_header_table_prelude(&self) {
        println!("Elf file type is {0:?}, ({0})", self.header.file_type);
        println!("Entry point {:#X}", self.header.entry);
        println!(
            "There are {} program headers, starting at offset {}",
            self.header.program_header_entries, self.header.program_header_offset
        );
        println!();
    }

    pub fn print_elf_header(&self) {
        println!("{}", self.header);
    }

    pub fn print_program_header_table(&self, include_prelude: bool) {
        if include_prelude {
            self.print_program_header_table_prelude();
        }

        let mut rows = vec![(
            "Type".to_string(),
            "Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align".to_string(),
        )];

        for ph in self.program_header_table.iter() {
            let header_type = format!("{:?}", ph.header_type);
            let data = format!(
                "{:#08X} {:#010X} {:#010X} {:#07X} {:#07X} {:#03X} {:#06X}",
                ph.offset,
                ph.virtual_address,
                ph.physical_address,
                ph.size_in_file,
                ph.size_in_memory,
                ph.flags,
                ph.alignment
            );
            rows.push((header_type, data));
        }

        let header_type_padding = rows
            .iter()
            .map(|(header_type, _)| header_type.len())
            .max()
            .unwrap();
        let header_type_padding = header_type_padding + 6; // Same as GNU readelf

        println!("Program Headers:");
        for (header_type, data) in rows.iter() {
            let padding = cmp::max(header_type_padding - header_type.len(), 0);
            let padding = " ".repeat(padding);
            println!("{header_type}{padding}{data}");
        }
    }
}
