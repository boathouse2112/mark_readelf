use anyhow::anyhow;

/// Magic number used to identify a file as ELF
const ELF_MAGIC_NUMBER: u32 = 0x7f_45_4c_46; // 0x7F_E_L_F

/// Whether this file is ELF32 or ELF64
/// TODO: This name is tough.
enum Class {
    Elf32 = 1,
    Elf64 = 2,
}

/// Endianness
/// TODO: This name is tougher.
enum Data {
    LittleEndian = 1,
    BigEndian = 2,
}

/// ELF version. There's only one version.
enum Version {
    Current = 1,
}

/// Operating system ABI
enum OsAbi {
    SystemV = 0x00,
    Hpux = 0x01,
    NetBsd = 0x02,
    Linux = 0x03,
    GnuHurd = 0x04,
    Solaris = 0x06,
    AixMonterey = 0x07,
    Irix = 0x08,
    FreeBsd = 0x09,
    Tru64 = 0x0A,
    NovellModesto = 0x0B,
    OpenBsd = 0x0C,
    OpenVms = 0x0D,
    NonStopKernel = 0x0E,
    Aros = 0x0F,
    FenixOs = 0x10,
    NuxiCloudAbi = 0x11,
    StratusTechnologiesOpenVos = 0x12,
}

enum ObjectFileType {
    None = 0x00, // Unknown.
    Rel = 0x01,  // Relocatable file.
    Exec = 0x02, // Executable file.
    Dyn = 0x03,  // Shared object.
    Core = 0x04, // Core file.
                 // I don't know what the os/processor specific reserved ones are for.
}

enum Machine {
    None = 0x00,
    X86 = 0x03,
    PowerPc = 0x14,
    PowerPc64Bit = 0x15,
    Arm = 0x28,
    AmdX86_64 = 0x3E,
    Arm64 = 0xB7,
    RiscV = 0xF3,
}

/// Header at the start of the ELF file
struct ElfHeader32 {
    magic_number: u32,
    class: Class,
    data: Data,
    version: Version,
    os_abi: OsAbi,
    abi_version: u8,
    object_file_type: ObjectFileType,
    machine: Machine,
    entry: u32,
    program_header_offset: u32,
    section_header_offset: u32,
    flags: u32,
    elf_header_size: u16,
    program_header_entry_size: u16,
    program_header_num_entries: u16,
    section_header_entry_size: u16,
    section_header_num_entries: u16,
    section_header_string_index: u16,
}

fn parse_elf_header_32(data: &[u8]) -> anyhow::Result<ElfHeader32> {
    let mut iter = data.iter().cloned();

    // Verify magic number
    let mut magic_number_arr = [0_u8; 4];
    for n in 0..4 {
        let byte = iter.next().ok_or(anyhow!("Byte {n} missing."))?;
        magic_number_arr[n] = byte;
    }
    let magic_number: u32 = u32::from_be_bytes(magic_number_arr);
    if (magic_number != ELF_MAGIC_NUMBER) {
        return Err(anyhow!("Wrong magic number: {:x}", magic_number));
    }

    todo!()
}

fn main() {}
