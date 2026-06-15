"""
PE validation primitives shared across application and infrastructure layers.

Both the download use case and the file repository need to detect PE DLL
architectures and validate PE image layouts.  Centralising that logic here
prevents the two implementations from drifting apart.
"""

from ..entities.dll_file import Architecture


class PEDllInspection:
    """Result of inspecting PE content for DLL architecture."""

    __slots__ = ("architecture", "unsupported_machine", "is_pe_not_dll")

    def __init__(
        self,
        architecture: Architecture | None = None,
        unsupported_machine: int | None = None,
        is_pe_not_dll: bool = False,
    ) -> None:
        self.architecture = architecture
        self.unsupported_machine = unsupported_machine
        self.is_pe_not_dll = is_pe_not_dll

    @property
    def is_valid_dll(self) -> bool:
        return self.architecture is not None

    @property
    def is_unsupported_machine(self) -> bool:
        return self.unsupported_machine is not None


_PE_POINTER_OFFSET = 0x3C
_PE_SIGNATURE = b"PE\x00\x00"
_PE_MIN_PE_OFFSET = 0x40
_PE_COFF_HEADER_SIZE = 20
_PE_NUMBER_OF_SECTIONS_OFFSET_FROM_MACHINE = 2
_PE_SIZE_OF_OPTIONAL_HEADER_OFFSET_FROM_MACHINE = 16
_PE_CHARACTERISTICS_OFFSET_FROM_MACHINE = 18
_PE_DLL_CHARACTERISTIC = 0x2000
_PE_OPTIONAL_HEADER_MAGIC_PE32 = 0x10B
_PE_OPTIONAL_HEADER_MAGIC_PE32_PLUS = 0x20B
_PE_MAX_OPTIONAL_HEADER_SIZE = 240
_PE_SECTION_HEADER_SIZE = 40
_PE_SECTION_NAME_SIZE = 8
_PE_SECTION_VIRTUAL_SIZE_OFFSET = 8
_PE_SECTION_RAW_SIZE_OFFSET = 16
_PE_SECTION_RAW_POINTER_OFFSET = 20
_PE_MAX_SECTIONS = 96
_PE_MACHINE_ARCHITECTURES: dict[int, Architecture] = {
    0x014C: Architecture.X86,
    0x8664: Architecture.X64,
    0x01C0: Architecture.ARM,
    0x01C2: Architecture.ARM,
    0x01C4: Architecture.ARM,
    0xAA64: Architecture.ARM64,
}


def detect_pe_dll_architecture(content: bytes) -> Architecture | None:
    """Return the concrete architecture when *content* is a PE DLL, or ``None``."""
    return inspect_pe_dll_architecture(content).architecture


def inspect_pe_dll_architecture(content: bytes) -> PEDllInspection:
    """Inspect PE content and return detailed architecture information.

    Unlike :func:`detect_pe_dll_architecture`, this distinguishes between
    "not a PE DLL at all" and "valid PE with an unsupported machine type".
    """
    if not content.startswith(b"MZ"):
        return PEDllInspection()
    if len(content) < _PE_POINTER_OFFSET + 4:
        return PEDllInspection()

    pe_offset = int.from_bytes(
        content[_PE_POINTER_OFFSET : _PE_POINTER_OFFSET + 4],
        "little",
    )
    if pe_offset < _PE_MIN_PE_OFFSET or pe_offset > len(content) - 4:
        return PEDllInspection()
    machine_offset = pe_offset + len(_PE_SIGNATURE)
    if (
        len(content) < machine_offset + _PE_COFF_HEADER_SIZE
        or content[pe_offset:machine_offset] != _PE_SIGNATURE
    ):
        return PEDllInspection()

    machine = int.from_bytes(content[machine_offset : machine_offset + 2], "little")
    architecture = _PE_MACHINE_ARCHITECTURES.get(machine)
    if architecture is None:
        return PEDllInspection(unsupported_machine=machine)
    if not pe_image_layout_is_valid(content, machine_offset, architecture):
        return PEDllInspection(architecture=None)

    # The COFF-header bounds check above already guarantees the characteristics
    # field (machine_offset + 18..20) is within range.
    characteristics_offset = machine_offset + _PE_CHARACTERISTICS_OFFSET_FROM_MACHINE
    characteristics = int.from_bytes(
        content[characteristics_offset : characteristics_offset + 2],
        "little",
    )
    if characteristics & _PE_DLL_CHARACTERISTIC == 0:
        return PEDllInspection(is_pe_not_dll=True)
    return PEDllInspection(architecture=architecture)


def pe_image_layout_is_valid(
    content: bytes,
    machine_offset: int,
    architecture: Architecture,
) -> bool:
    """Return ``True`` when the PE header has a valid optional header and sections."""
    section_count = int.from_bytes(
        content[
            machine_offset + _PE_NUMBER_OF_SECTIONS_OFFSET_FROM_MACHINE : machine_offset
            + _PE_NUMBER_OF_SECTIONS_OFFSET_FROM_MACHINE
            + 2
        ],
        "little",
    )
    if section_count < 1 or section_count > _PE_MAX_SECTIONS:
        return False

    optional_header_size = int.from_bytes(
        content[
            machine_offset
            + _PE_SIZE_OF_OPTIONAL_HEADER_OFFSET_FROM_MACHINE : machine_offset
            + _PE_SIZE_OF_OPTIONAL_HEADER_OFFSET_FROM_MACHINE
            + 2
        ],
        "little",
    )
    if optional_header_size < 2 or optional_header_size > _PE_MAX_OPTIONAL_HEADER_SIZE:
        return False
    optional_header_offset = machine_offset + _PE_COFF_HEADER_SIZE

    section_table_offset = optional_header_offset + optional_header_size
    if len(content) < section_table_offset:
        return False

    optional_magic = int.from_bytes(
        content[optional_header_offset : optional_header_offset + 2],
        "little",
    )
    if optional_magic != expected_optional_magic(architecture):
        return False

    section_table_size = section_count * _PE_SECTION_HEADER_SIZE
    if len(content) < section_table_offset + section_table_size:
        return False

    return has_loadable_section(content, section_table_offset, section_count)


def has_loadable_section(
    content: bytes,
    section_table_offset: int,
    section_count: int,
) -> bool:
    """Return ``True`` when at least one PE section has on-disk data."""
    minimum_raw_pointer = section_table_offset + (
        section_count * _PE_SECTION_HEADER_SIZE
    )
    for index in range(section_count):
        section_offset = section_table_offset + (index * _PE_SECTION_HEADER_SIZE)
        section_header = content[
            section_offset : section_offset + _PE_SECTION_HEADER_SIZE
        ]

        virtual_size = int.from_bytes(
            section_header[
                _PE_SECTION_VIRTUAL_SIZE_OFFSET : _PE_SECTION_VIRTUAL_SIZE_OFFSET + 4
            ],
            "little",
        )
        raw_size = int.from_bytes(
            section_header[
                _PE_SECTION_RAW_SIZE_OFFSET : _PE_SECTION_RAW_SIZE_OFFSET + 4
            ],
            "little",
        )
        raw_pointer = int.from_bytes(
            section_header[
                _PE_SECTION_RAW_POINTER_OFFSET : _PE_SECTION_RAW_POINTER_OFFSET + 4
            ],
            "little",
        )
        if virtual_size == 0 and raw_size == 0:
            continue
        if (
            raw_size > 0
            and raw_pointer >= minimum_raw_pointer
            and raw_pointer + raw_size <= len(content)
        ):
            return True
    return False


def expected_optional_magic(architecture: Architecture) -> int:
    """Return the PE optional-header magic number for *architecture*."""
    if architecture in (Architecture.X64, Architecture.ARM64):
        return _PE_OPTIONAL_HEADER_MAGIC_PE32_PLUS
    return _PE_OPTIONAL_HEADER_MAGIC_PE32
