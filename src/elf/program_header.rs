#[derive(Debug)]
pub enum HeaderType {
    Null,
    Load,
    Dynamic,
    Interpreter,
    Note,
    ProgramHeaderTable,
    GnuStack,
}

pub struct ProgramHeader {
    pub header_type: HeaderType, // u32
    pub offset: u32,
    pub virtual_address: u32,
    pub physical_address: u32,
    pub size_in_file: u32,
    pub size_in_memory: u32,
    pub flags: u32,
    pub alignment: u32, // TODO -- RWX bitflags
}
