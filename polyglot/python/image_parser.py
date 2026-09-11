"""
polyglot/python/image_parser.py

Image parser for filecarve — parse disk images and memory dumps by signature.
Fast, dependency-light, self-contained.

Supported formats:
  - Raw (no magic, just size)
  - E01 (EnCase)
  - AFF4
  - Mach-O (macOS)
  - ELF (Linux)
  - PE (Windows)
  - Raw memory (generic)
"""

import struct
import sys
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Optional, BinaryIO, Tuple, Dict, Any

# =============================================================================
# Enums and Constants
# =============================================================================

class ImageFormat(Enum):
    RAW = auto()
    E01 = auto()
    AFF4 = auto()
    MACH_O = auto()
    ELF = auto()
    PE = auto()
    GENERIC = auto()

# Magic bytes for detection
MACH_O_MAGIC = {
    "Mach-O LE": b"\xfe\xed\xfa\xce",
    "Mach-O BE": b"\xce\xfa\xed\xfe",
}

ELF_MAGIC = b"\x7fELF"

E01_MAGIC = b"E01"

AFF4_MAGIC = b"AFF4"

# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class PartitionInfo:
    """Represents a partition within an image."""
    offset: int
    size: int
    fs_type: str
    label: Optional[str] = None

@dataclass
class ImageMetadata:
    """Metadata extracted from an image file."""
    path: Path
    format: ImageFormat
    size: int
    raw_size: int  # Actual bytes read
    partitions: list[PartitionInfo]
    magic_bytes: bytes
    extra: Dict[str, Any] = None

    def __post_init__(self):
        if self.extra is None:
            self.extra = {}

# =============================================================================
# Core Parser Logic
# =============================================================================

def _read_bytes(f: BinaryIO, n: int) -> bytes:
    """Read exactly n bytes from a file-like object."""
    data = f.read(n)
    if len(data) < n:
        raise EOFError(f"Expected {n} bytes, got {len(data)}")
    return data

def _detect_mach_o(f: BinaryIO) -> Optional[ImageMetadata]:
    """Detect Mach-O format (macOS images)."""
    magic = f.read(4)
    if magic == MACH_O_MAGIC["Mach-O LE"]:
        f.seek(0)
        header = _read_bytes(f, 20)
        endian = "<"  # Little-endian for LE
        # Parse header fields
        magic = struct.unpack(endian, header[0:4])[0]
        cputype = struct.unpack(endian, header[4:8])[0]
        cpusubtype = struct.unpack(endian, header[8:12])[0]
        filetype = struct.unpack(endian, header[12:16])[0]
        ncmds = struct.unpack(endian, header[16:20])[0]
        
        # Filetype: 1 = MH_OBJECT (executable), 2 = MH_EXECUTE
        filetype_names = {1: "MH_OBJECT", 2: "MH_EXECUTE"}
        ftype_name = filetype_names.get(filetype, f"UNKNOWN({filetype})")
        
        return ImageMetadata(
            path=Path(f.name),
            format=ImageFormat.MACH_O,
            size=f.seek(0, 2),  # Seek to end to get size
            raw_size=20,
            partitions=[],
            magic_bytes=header,
            extra={
                "cputype": cputype,
                "cpusubtype": cpusubtype,
                "filetype": filetype,
                "filetype_name": ftype_name,
                "ncmds": ncmds,
            }
        )
    elif magic == MACH_O_MAGIC["Mach-O BE"]:
        f.seek(0)
        header = _read_bytes(f, 20)
        endian = ">"  # Big-endian for BE
        magic = struct.unpack(endian, header[0:4])[0]
        cputype = struct.unpack(endian, header[4:8])[0]
        cpusubtype = struct.unpack(endian, header[8:12])[0]
        filetype = struct.unpack(endian, header[12:16])[0]
        ncmds = struct.unpack(endian, header[16:20])[0]
        
        filetype_names = {1: "MH_OBJECT", 2: "MH_EXECUTE"}
        ftype_name = filetype_names.get(filetype, f"UNKNOWN({filetype})")
        
        return ImageMetadata(
            path=Path(f.name),
            format=ImageFormat.MACH_O,
            size=f.seek(0, 2),
            raw_size=20,
            partitions=[],
            magic_bytes=header,
            extra={
                "cputype": cputype,
                "cpusubtype": cpusubtype,
                "filetype": filetype,
                "filetype_name": ftype_name,
                "ncmds": ncmds,
            }
        )
    f.seek(0)
    return None

def _detect_elf(f: BinaryIO) -> Optional[ImageMetadata]:
    """Detect ELF format (Linux images)."""
    magic = f.read(4)
    if magic == ELF_MAGIC:
        f.seek(0)
        header = _read_bytes(f, 52)
        endian = "<" if header[4] == 1 else ">"
        class_ = header[5]
        version = header[6]
        osabi = header[7]
        abi_version = header[8]
        elf_type = header[16]
        elf_machine = header[18]
        entry_point = struct.unpack(endian, header[24:32])[0]
        phoff = struct.unpack(endian, header[32:40])[0]
        shoff = struct.unpack(endian, header[40:48])[0]
        
        # ELF types
        elf_type_names = {
            0: "ET_NONE", 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN",
            4: "ET_CORE", 5: "ET_LOOS", 6: "ET_HIOS", 7: "ET_LOPROC", 8: "ET_HIPROC"
        }
        type_name = elf_type_names.get(elf_type, f"UNKNOWN({elf_type})")
        
        # ELF machines
        elf_machine_names = {
            0: "EM_NONE", 1: "EM_SPARC", 2: "EM_386", 3: "EM_I386",
            4: "EM_I860", 5: "EM_MIPS", 6: "EM_PARISC", 7: "EM_VPP500",
            8: "EM_AWE686", 9: "EM_HPPA", 10: "EM_MIPS_RS3_LE",
            11: "EM_ALPHA", 12: "EM_PPC", 13: "EM_PPC64", 14: "EM_SPARC32PLUS",
            15: "EM_SPARC64", 16: "EM_IA_64", 17: "EM_X86_64",
        }
        machine_name = elf_machine_names.get(elf_machine, f"UNKNOWN({elf_machine})")
        
        return ImageMetadata(
            path=Path(f.name),
            format=ImageFormat.ELF,
            size=f.seek(0, 2),
            raw_size=52,
            partitions=[],
            magic_bytes=header,
            extra={
                "endian": endian,
                "class": class_,
                "version": version,
                "osabi": osabi,
                "abi_version": abi_version,
                "elf_type": elf_type,
                "elf_type_name": type_name,
                "elf_machine": elf_machine,
                "elf_machine_name": machine_name,
                "entry_point": entry_point,
                "phoff": phoff,
                "shoff": shoff,
            }
        )
    f.seek(0)
    return None

def _detect_pe(f: BinaryIO) -> Optional[ImageMetadata]:
    """Detect PE format (Windows images)."""
    magic = f.read(2)
    if magic == b"MZ":
        f.seek(0)
        header = _read_bytes(f, 64)
        # PE header fields
        machine = struct.unpack("<H", header[2:4])[0]
        number_of_sections = struct.unpack("<H", header[4:6])[0]
        time_date_stamp = struct.unpack("<I", header[6:10])[0]
        pointer_to_symbol_table = struct.unpack("<I", header[10:14])[0]
        number_of_symbols = struct.unpack("<I", header[14:18])[0]
        size_of_optional_header = struct.unpack("<H", header[18:20])[0]
        characteristics = struct.unpack("<H", header[20:22])[0]
        
        # Machine types
        machine_names = {
            0: "MACHINE_UNKNOWN", 1: "MACHINE_I386", 2: "MACHINE_MIPS",
            3: "MACHINE_ARM", 4: "MACHINE_ALPHA", 5: "MACHINE_PPC",
            6: "MACHINE_PPC64", 7: "MACHINE_IA64", 8: "MACHINE_AMD64",
            9: "MACHINE_ARM64", 10: "MACHINE_ARM64EC", 11: "MACHINE_RISCV64",
        }
        machine_name = machine_names.get(machine, f"UNKNOWN({machine})")
        
        # Characteristics
        characteristics_names = {
            0x0001: "IMAGE_FILE_RELOCS_STRIPPED",
            0x0002: "IMAGE_FILE_EXECUTABLE_IMAGE",
            0x0004: "IMAGE_FILE_LINE_NUMS_STRIPPED",
            0x0008: "IMAGE_FILE_LOCAL_SYMS_STRIPPED",
            0x0010: "IMAGE_FILE_AGGRESIVE_WS_TRIM",
            0x0020: "IMAGE_FILE_32BIT_MACHINE",
            0x0040: "IMAGE_FILE_LARGE_ADDRESS_AWARE",
            0x0080: "IMAGE_FILE_BYTES_REVERSED_LO",
            0x0100: "IMAGE_FILE_16BIT_MACHINE",
            0x0200: "IMAGE_FILE_DLL",
            0x0400: "IMAGE_FILE_SYSTEM",
            0x0800: "IMAGE_FILE_DLL",
            0x1000: "IMAGE_FILE_32BIT_MACHINE",
            0x2000: "IMAGE_FILE_LARGE_ADDRESS_AWARE",
            0x4000: "IMAGE_FILE_BYTES_REVERSED_HI",
        }
        char_names = []
        for flag, name in characteristics_names.items():
            if characteristics & flag:
                char_names.append(name)
        
        return ImageMetadata(
            path=Path(f.name),
            format=ImageFormat.PE,
            size=f.seek(0, 2),
            raw_size=64,
            partitions=[],
            magic_bytes=header,
            extra={
                "machine": machine,
                "machine_name": machine_name,
                "number_of_sections": number_of_sections,
                "time_date_stamp": time_date_stamp,
                "pointer_to_symbol_table": pointer_to_symbol_table,
                "number_of_symbols": number_of_symbols,
                "size_of_optional_header": size_of_optional_header,
                "characteristics": characteristics,
                "characteristics_names": char_names,
            }
        )
    f.seek(0)
    return None

def _detect_e01(f: BinaryIO) -> Optional[ImageMetadata]:
    """Detect E01 format (EnCase)."""
    magic = f.read(4)
    if magic == E01_MAGIC:
        f.seek(0)
        header = _read_bytes(f, 52)
        # E01 header fields
        endian = "<" if header[52] == 0 else ">"
        magic = struct.unpack(endian, header[0:4])[0]
        version = struct.unpack(endian, header[4:8])[0]
        image_size = struct.unpack(endian, header[8:16])[0]
        raw_size = struct.unpack(endian, header[16:24])[0]
        partition_table_offset = struct.unpack(endian, header[24:32])[0]
        partition_table_size = struct.unpack(endian, header[32:40])[0]
        file_system_offset = struct.unpack(endian, header[40:48])[0]
        file_system_size = struct.unpack(endian, header[48:52])[0]
        
        # Version info
        version_info = {
            1: "E01 1.0",
            2: "E01 2.0",
            3: "E01 3.0",
            4: "E01 4.0",
            5: "E01 5.0",
            6: "E01 6.0",
            7: "E01 7.0",
            8: "E01 8.0",
            9: "E01 9.0",
            10: "E01 10.0",
        }
        version_name = version_info.get(version, f"UNKNOWN({version})")
        
        return ImageMetadata(
            path=Path(f.name),
            format=ImageFormat.E01,
            size=image_size,
            raw_size=raw_size,
            partitions=[],
            magic_bytes=header,
            extra={
                "endian": endian,
                "magic": magic,
                "version": version,
                "version_name": version_name,
                "image_size": image_size,
                "raw_size": raw_size,
                "partition_table_offset": partition_table_offset,
                "partition_table_size": partition_table_size,
                "file_system_offset": file_system_offset,
                "file_system_size": file_system_size,
            }
        )
    f.seek(0)
    return None

def _detect_aff4(f: BinaryIO) -> Optional[ImageMetadata]:
    """Detect AFF4 format."""
    magic = f.read(4)
    if magic == AFF4_MAGIC:
        f.seek(0)
        header = _read_bytes(f, 52)
        # AFF4 header fields
        endian = "<" if header[52] == 0 else ">"
        magic = struct.unpack(endian, header[0:4])[0]
        version = struct.unpack(endian, header[4:8])[0]
        image_size = struct.unpack(endian, header[8:16])[0]
        raw_size = struct.unpack(endian, header[16:24])[0]
        partition_table_offset = struct.unpack(endian, header[24:32])[0]
        partition_table_size = struct.unpack(endian, header[32:40])[0]
        file_system_offset = struct.unpack(endian, header[40:48])[0]
        file_system_size = struct.unpack(endian, header[48:52])[0]
        
        version_info = {
            1: "AFF4 1.0",
            2: "AFF4 2.0",
            3: "AFF4 3.0",
            4: "AFF4 4.0",
            5: "AFF4 5.0",
            6: "AFF4 6.0",
            7: "AFF4 7.0",
            8: "AFF4 8.0",
            9: "AFF4 9.0",
            10: "AFF4 10.0",
        }
        version_name = version_info.get(version, f"UNKNOWN({version