//! Copied from https://github.com/cole14/rust-elf/tree/master

use crate::abi;
use crate::elf::header::{ElfHeader32, FileType, Machine, OsAbi};

#[derive(Debug)]
pub enum ParseError {
    /// Returned when the ELF File Header's magic bytes weren't ELF's defined
    /// magic bytes
    BadMagic([u8; 4]),
    /// Returned when the ELF File Header's `e_ident[EI_CLASS]` wasn't one of the
    /// defined `ELFCLASS*` constants
    UnsupportedElfClass(u8),
    /// Returned when the ELF File Header's `e_ident[EI_DATA]` wasn't one of the
    /// defined `ELFDATA*` constants
    UnsupportedElfEndianness(u8),
    /// Returned when parsing an ELF struct with a version field whose value wasn't
    /// something we support and know how to parse.
    UnsupportedVersion((u64, u64)),
    /// Bad ELF file type field
    UnsupportedFileType(u16),
    /// Returned when parsing an ELF structure resulted in an offset which fell
    /// out of bounds of the requested structure
    BadOffset(u64),
    /// Returned when parsing a string out of a StringTable failed to find the
    /// terminating NUL byte
    StringTableMissingNul(u64),
    /// Returned when parsing a table of ELF structures and the file specified
    /// an entry size for that table that was different than what we had
    /// expected
    BadEntsize((u64, u64)),
    /// Returned when trying to interpret a section's data as the wrong type.
    /// For example, trying to treat an SHT_PROGBIGS section as a SHT_STRTAB.
    UnexpectedSectionType((u32, u32)),
    /// Returned when trying to interpret a segment's data as the wrong type.
    /// For example, trying to treat an PT_LOAD section as a PT_NOTE.
    UnexpectedSegmentType((u32, u32)),
    /// Returned when a section has a sh_addralign value that was different
    /// than we expected.
    UnexpectedAlignment(usize),
    /// Returned when parsing an ELF structure out of an in-memory `&[u8]`
    /// resulted in a request for a section of file bytes outside the range of
    /// the slice. Commonly caused by truncated file contents.
    SliceReadError((usize, usize)),
    /// Returned when doing math with parsed elf fields that resulted in integer overflow.
    IntegerOverflow,
    /// Returned when parsing a string out of a StringTable that contained
    /// invalid Utf8
    Utf8Error(core::str::Utf8Error),
    /// Returned when parsing an ELF structure and the underlying structure data
    /// was truncated and thus the full structure contents could not be parsed.
    TryFromSliceError(core::array::TryFromSliceError),
    /// Returned when parsing an ELF structure whose on-disk fields were too big
    /// to represent in the native machine's usize type for in-memory processing.
    /// This could be the case when processessing large 64-bit files on a 32-bit machine.
    TryFromIntError(core::num::TryFromIntError),
    /// Returned when parsing an ELF structure out of an io stream encountered
    /// an io error.
    IOError(std::io::Error),
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            ParseError::BadMagic(_) => None,
            ParseError::UnsupportedElfClass(_) => None,
            ParseError::UnsupportedElfEndianness(_) => None,
            ParseError::UnsupportedVersion(_) => None,
            ParseError::UnsupportedFileType(_) => None,
            ParseError::BadOffset(_) => None,
            ParseError::StringTableMissingNul(_) => None,
            ParseError::BadEntsize(_) => None,
            ParseError::UnexpectedSectionType(_) => None,
            ParseError::UnexpectedSegmentType(_) => None,
            ParseError::UnexpectedAlignment(_) => None,
            ParseError::SliceReadError(_) => None,
            ParseError::IntegerOverflow => None,
            ParseError::Utf8Error(ref err) => Some(err),
            ParseError::TryFromSliceError(ref err) => Some(err),
            ParseError::TryFromIntError(ref err) => Some(err),
            ParseError::IOError(ref err) => Some(err),
        }
    }
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            ParseError::BadMagic(ref magic) => {
                write!(f, "Invalid Magic Bytes: {magic:X?}")
            }
            ParseError::UnsupportedElfClass(class) => {
                write!(f, "Unsupported ELF Class: {class}")
            }
            ParseError::UnsupportedElfEndianness(endianness) => {
                write!(f, "Unsupported ELF Endianness: {endianness}")
            }
            ParseError::UnsupportedVersion((found, expected)) => {
                write!(
                    f,
                    "Unsupported ELF Version field found: {found} expected: {expected}"
                )
            }
            ParseError::UnsupportedFileType(file_type) => {
                write!(f, "Unsupported ELF File Type: {file_type}")
            }
            ParseError::BadOffset(offset) => {
                write!(f, "Bad offset: {offset:#X}")
            }
            ParseError::StringTableMissingNul(offset) => {
                write!(
                    f,
                    "Could not find terminating NUL byte starting at offset: {offset:#X}"
                )
            }
            ParseError::BadEntsize((found, expected)) => {
                write!(
                    f,
                    "Invalid entsize. Expected: {expected:#X}, Found: {found:#X}"
                )
            }
            ParseError::UnexpectedSectionType((found, expected)) => {
                write!(
                    f,
                    "Could not interpret section of type {found} as type {expected}"
                )
            }
            ParseError::UnexpectedSegmentType((found, expected)) => {
                write!(
                    f,
                    "Could not interpret section of type {found} as type {expected}"
                )
            }
            ParseError::UnexpectedAlignment(align) => {
                write!(
                    f,
                    "Could not interpret section with unexpected alignment of {align}"
                )
            }
            ParseError::SliceReadError((start, end)) => {
                write!(f, "Could not read bytes in range [{start:#X}, {end:#X})")
            }
            ParseError::IntegerOverflow => {
                write!(f, "Integer overflow detected")
            }
            ParseError::Utf8Error(ref err) => err.fmt(f),
            ParseError::TryFromSliceError(ref err) => err.fmt(f),
            ParseError::TryFromIntError(ref err) => err.fmt(f),
            ParseError::IOError(ref err) => err.fmt(f),
        }
    }
}

impl From<core::str::Utf8Error> for ParseError {
    fn from(err: core::str::Utf8Error) -> Self {
        ParseError::Utf8Error(err)
    }
}

impl From<core::array::TryFromSliceError> for ParseError {
    fn from(err: core::array::TryFromSliceError) -> Self {
        ParseError::TryFromSliceError(err)
    }
}

impl From<core::num::TryFromIntError> for ParseError {
    fn from(err: core::num::TryFromIntError) -> Self {
        ParseError::TryFromIntError(err)
    }
}

impl From<std::io::Error> for ParseError {
    fn from(err: std::io::Error) -> ParseError {
        ParseError::IOError(err)
    }
}

/// Parse ints from a little-endian byte array
pub struct Parser<'buffer> {
    offset: usize,
    buffer: &'buffer [u8],
}

impl<'buffer> Parser<'buffer> {
    pub fn new(buffer: &'buffer [u8]) -> Self {
        Self { offset: 0, buffer }
    }

    pub fn parse_u8(&mut self) -> Result<u8, ParseError> {
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

    pub fn parse_u16(&mut self) -> Result<u16, ParseError> {
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

    pub fn parse_u32(&mut self) -> Result<u32, ParseError> {
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

    pub fn skip_u8(&mut self) {
        self.offset += 1;
    }

    pub fn skip_u16(&mut self) {
        self.offset += 2;
    }

    pub fn skip_u32(&mut self) {
        self.offset += 4;
    }
}

/// Verify identification bytes at start of ELF file
pub fn verify_e_ident(buffer: &[u8]) -> Result<(), ParseError> {
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
pub fn parse_e_ident(buffer: &[u8]) -> Result<(OsAbi, u8), ParseError> {
    verify_e_ident(buffer)?;
    let os_abi = buffer[abi::EI_OSABI];
    let abi_version = buffer[abi::EI_ABIVERSION];
    Ok((OsAbi(os_abi), abi_version))
}

pub fn parse_elf_header_32(buffer: &[u8]) -> Result<ElfHeader32, ParseError> {
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
