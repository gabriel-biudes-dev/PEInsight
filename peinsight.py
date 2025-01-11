import argparse
import pefile
import datetime
import hashlib
import json

def load_config(config_file):
    """
    Loads a configuration file in JSON format.

    Args:
        config_file (str): Path to the configuration file.

    Returns:
        dict: Configuration settings loaded from the JSON file.
    """
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
        return config
    except Exception as e:
        print(f"Error loading config file: {e}")
        return {}

def print_pe_header(pe, config):
    """
    Prints the header information of the PE file.

    Args:
        pe (pefile.PE): The PE file object.
        config (dict): Configuration settings to control output.
    """
    if config.get("print_pe_header", False):
        try:
            print("== PE Header ==")
            # Printing various fields of the PE header
            print(f"Machine: {pe.FILE_HEADER.Machine}")
            print(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
            print(f"TimeDateStamp: {datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, tz=datetime.timezone.utc)}")
            print(f"Pointer to Symbol Table: {pe.FILE_HEADER.PointerToSymbolTable}")
            print(f"Number of Symbols: {pe.FILE_HEADER.NumberOfSymbols}")
            print(f"Size of Optional Header: {pe.FILE_HEADER.SizeOfOptionalHeader}")
            print(f"Characteristics: {hex(pe.FILE_HEADER.Characteristics)}")
            print(f"Magic: {hex(pe.OPTIONAL_HEADER.Magic)}")
            print(f"Major Linker Version: {pe.OPTIONAL_HEADER.MajorLinkerVersion}")
            print(f"Minor Linker Version: {pe.OPTIONAL_HEADER.MinorLinkerVersion}")
            print(f"Size of Code: {pe.OPTIONAL_HEADER.SizeOfCode}")
            print(f"Size of Initialized Data: {pe.OPTIONAL_HEADER.SizeOfInitializedData}")
            print(f"Size of Uninitialized Data: {pe.OPTIONAL_HEADER.SizeOfUninitializedData}")
            print(f"Address of Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
            print(f"Base of Code: {hex(pe.OPTIONAL_HEADER.BaseOfCode)}")
            print(f"Image Base: {hex(pe.OPTIONAL_HEADER.ImageBase)}")
            print(f"Section Alignment: {pe.OPTIONAL_HEADER.SectionAlignment}")
            print(f"File Alignment: {pe.OPTIONAL_HEADER.FileAlignment}")
            print(f"Major Operating System Version: {pe.OPTIONAL_HEADER.MajorOperatingSystemVersion}")
            print(f"Minor Operating System Version: {pe.OPTIONAL_HEADER.MinorOperatingSystemVersion}")
            print(f"Major Image Version: {pe.OPTIONAL_HEADER.MajorImageVersion}")
            print(f"Minor Image Version: {pe.OPTIONAL_HEADER.MinorImageVersion}")
            print(f"Major Subsystem Version: {pe.OPTIONAL_HEADER.MajorSubsystemVersion}")
            print(f"Minor Subsystem Version: {pe.OPTIONAL_HEADER.MinorSubsystemVersion}")
            print(f"Size of Image: {pe.OPTIONAL_HEADER.SizeOfImage}")
            print(f"Size of Headers: {pe.OPTIONAL_HEADER.SizeOfHeaders}")
            print(f"CheckSum: {pe.OPTIONAL_HEADER.CheckSum}")
            print(f"Subsystem: {pe.OPTIONAL_HEADER.Subsystem}")
            print(f"DLL Characteristics: {hex(pe.OPTIONAL_HEADER.DllCharacteristics)}")
            print(f"Size of Stack Reserve: {pe.OPTIONAL_HEADER.SizeOfStackReserve}")
            print(f"Size of Stack Commit: {pe.OPTIONAL_HEADER.SizeOfStackCommit}")
            print(f"Size of Heap Reserve: {pe.OPTIONAL_HEADER.SizeOfHeapReserve}")
            print(f"Size of Heap Commit: {pe.OPTIONAL_HEADER.SizeOfHeapCommit}")
            print(f"Loader Flags: {pe.OPTIONAL_HEADER.LoaderFlags}")
            print(f"Number of Rva and Sizes: {pe.OPTIONAL_HEADER.NumberOfRvaAndSizes}")
        except AttributeError as e:
            print(f"Error in PE Header: {e}")

def print_pe_sections(pe, config):
    """
    Prints information about the sections in the PE file.

    Args:
        pe (pefile.PE): The PE file object.
        config (dict): Configuration settings to control output.
    """
    if config.get("print_pe_sections", False):
        try:
            print("== Sections ==")
            # Printing details of each section in the PE file
            for section in pe.sections:
                print(f"Section Name: {section.Name.decode().strip()}")
                print(f"Virtual Size: {hex(section.Misc_VirtualSize)}")
                print(f"Virtual Address: {hex(section.VirtualAddress)}")
                print(f"Size of Raw Data: {section.SizeOfRawData}")
                print(f"Pointer to Raw Data: {hex(section.PointerToRawData)}")
                print(f"Characteristics: {hex(section.Characteristics)}")
                print()
        except Exception as e:
            print(f"Error printing sections: {e}")

def print_pe_imports(pe, config):
    """
    Prints information about the imports in the PE file.

    Args:
        pe (pefile.PE): The PE file object.
        config (dict): Configuration settings to control output.
    """
    if config.get("print_pe_imports", False):
        try:
            print("== Imports ==")
            # Printing imported libraries and their functions
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    print(f"Library: {entry.dll.decode()}")
                    for imp in entry.imports:
                        print(f"  Function: {imp.name.decode() if imp.name else None}, Address: {hex(imp.address)}")
                    print()
            else:
                print("No imports found.")
        except Exception as e:
            print(f"Error printing imports: {e}")

def print_pe_exports(pe, config):
    """
    Prints information about the exports in the PE file.

    Args:
        pe (pefile.PE): The PE file object.
        config (dict): Configuration settings to control output.
    """
    if config.get("print_pe_exports", False):
        try:
            print("== Exports ==")
            # Printing exported functions and their addresses
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    print(f"Name: {exp.name.decode()}, Address: {hex(exp.address)}, Ordinal: {exp.ordinal}")
            else:
                print("No exports found.")
        except Exception as e:
            print(f"Error printing exports: {e}")

def print_pe_resources(pe, config):
    """
    Prints information about the resources in the PE file.

    Args:
        pe (pefile.PE): The PE file object.
        config (dict): Configuration settings to control output.
    """
    if config.get("print_pe_resources", False):
        try:
            print("== Resources ==")
            # Printing resource types and their associated data lengths
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    print(f"Resource Type: {resource_type.id}")
                    for resource_id in resource_type.directory.entries:
                        print(f"  Resource ID: {resource_id.name}")
                        if hasattr(resource_id, 'data'):
                            data = resource_id.data
                            print(f"    Data Length: {len(data)} bytes")
                    print()
            else:
                print("No resources found.")
        except Exception as e:
            print(f"Error printing resources: {e}")

def print_pe_tls(pe, config):
    """
    Prints information about the TLS (Thread Local Storage) in the PE file.

    Args:
        pe (pefile.PE): The PE file object.
        config (dict): Configuration settings to control output.
    """
    if config.get("print_pe_tls", False):
        try:
            print("== TLS (Thread Local Storage) ==")
            # Printing TLS information
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                tls_dir = pe.DIRECTORY_ENTRY_TLS
                print(f"Start Address of TLS: {hex(tls_dir.start_address_of_raw_data)}")
                print(f"End Address of TLS: {hex(tls_dir.end_address_of_raw_data)}")
        except Exception as e:
            print(f"Error printing TLS: {e}")

def print_pe_debug(pe, config):
    """
    Prints debugging information from the PE file.

    Args:
        pe (pefile.PE): The PE file object.
        config (dict): Configuration settings to control output.
    """
    if config.get("print_pe_debug", False):
        try:
            print("== Debug Information ==")
            # Printing debug entries
            if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                for debug_entry in pe.DIRECTORY_ENTRY_DEBUG:
                    print(f"Debug Type: {debug_entry.struct.Type}")
                    if debug_entry.struct.Type == 2:  # CodeView debug type
                        debug_data = debug_entry.struct
                        data_len = len(debug_data.__data__) if hasattr(debug_data, '__data__') else 0
                        print(f"  CodeView Debug Data Length: {data_len} bytes")
                    else:
                        print(f"  Unknown Debug Type: {debug_entry.struct.Type}")
            else:
                print("No debug information found.")
        except Exception as e:
            print(f"Error printing debug information: {e}")

def print_pe_relocations(pe, config):
    """
    Prints relocation information in the PE file.

    Args:
        pe (pefile.PE): The PE file object.
        config (dict): Configuration settings to control output.
    """
    if config.get("print_pe_relocations", False):
        try:
            print("== Relocations ==")
            # Printing base relocations
            if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
                for reloc in pe.DIRECTORY_ENTRY_BASERELOC.entries:
                    print(f"Virtual Address: {hex(reloc.struct.VirtualAddress)}")
                    print(f"Size of Block: {reloc.struct.SizeOfBlock}")
        except Exception as e:
            print(f"Error printing relocations: {e}")

def print_pe_signature(pe, config):
    """
    Prints the signature of the PE file.

    Args:
        pe (pefile.PE): The PE file object.
        config (dict): Configuration settings to control output.
    """
    if config.get("print_pe_signature", False):
        try:
            print("== Signature ==")
            print(f"Signature: {pe.__data__[:4]}")
        except Exception as e:
            print(f"Error printing signature: {e}")

def print_file_hashes(file_path, config):
    """
    Prints MD5, SHA1, and SHA256 hashes of the PE file.

    Args:
        file_path (str): Path to the PE file.
        config (dict): Configuration settings to control output.
    """
    if config.get("print_file_hashes", False):
        try:
            with open(file_path, "rb") as f:
                data = f.read()
                md5 = hashlib.md5(data).hexdigest()
                sha1 = hashlib.sha1(data).hexdigest()
                sha256 = hashlib.sha256(data).hexdigest()
                print(f"MD5: {md5}")
                print(f"SHA1: {sha1}")
                print(f"SHA256: {sha256}")
        except Exception as e:
            print(f"Error printing file hashes: {e}")

def print_overlay(pe, file_path, config):
    """
    Prints overlay data from the PE file.

    Args:
        pe (pefile.PE): The PE file object.
        file_path (str): Path to the PE file.
        config (dict): Configuration settings to control output.
    """
    if config.get("print_overlay", False):
        try:
            overlay_start = pe.OPTIONAL_HEADER.SizeOfHeaders + pe.OPTIONAL_HEADER.SizeOfImage
            with open(file_path, "rb") as f:
                f.seek(overlay_start)
                overlay_data = f.read()
                print(f"Overlay Size: {len(overlay_data)} bytes")
        except Exception as e:
            print(f"Error printing overlay: {e}")

def validate_checksum(pe, config):
    """
    Validates the checksum of the PE file.

    Args:
        pe (pefile.PE): The PE file object.
        config (dict): Configuration settings to control output.
    """
    if config.get("validate_checksum", False):
        try:
            if pe.OPTIONAL_HEADER.CheckSum == 0:
                print("No checksum found.")
            else:
                print(f"Checksum: {pe.OPTIONAL_HEADER.CheckSum}")
        except Exception as e:
            print(f"Error validating checksum: {e}")

def check_unusual_sections(pe, config):
    """
    Checks for unusual sections in the PE file.

    Args:
        pe (pefile.PE): The PE file object.
        config (dict): Configuration settings to control output.
    """
    if config.get("check_unusual_sections", False):
        try:
            for section in pe.sections:
                print(f"Section {section.Name.decode().strip()} Characteristics: {hex(section.Characteristics)}")
                if section.Characteristics & 0x20000000:  # Executable section
                    print(f"  Executable")
                if section.Characteristics & 0x40000000:  # Writable section
                    print(f"  Writable")
                if section.Characteristics & 0x80000000:  # Readable section
                    print(f"  Readable")
        except Exception as e:
            print(f"Error checking unusual sections: {e}")

def analyze_pe(file_path, config):
    """
    Analyzes the PE file based on the configuration.

    Args:
        file_path (str): Path to the PE file.
        config (dict): Configuration settings to control output.
    """
    try:
        pe = pefile.PE(file_path)
        # Calling each print function based on config settings
        print_pe_header(pe, config)
        print_pe_sections(pe, config)
        print_pe_imports(pe, config)
        print_pe_exports(pe, config)
        print_pe_resources(pe, config)
        print_pe_tls(pe, config)
        print_pe_debug(pe, config)
        print_pe_relocations(pe, config)
        print_pe_signature(pe, config)
        print_file_hashes(file_path, config)
        print_overlay(pe, file_path, config)
        validate_checksum(pe, config)
        check_unusual_sections(pe, config)
    except Exception as e:
        print(f"Error analyzing PE file: {e}")

def main():
    """
    Main entry point of the script.

    Parses command line arguments, loads the configuration file,
    and calls the analyze_pe function to analyze the specified PE file.
    """
    parser = argparse.ArgumentParser(description="PE file analysis tool")
    parser.add_argument("file", help="Path to the PE file")
    parser.add_argument("--config", default="config.json", help="Path to the configuration file")
    args = parser.parse_args()

    config = load_config(args.config)
    analyze_pe(args.file, config)

if __name__ == "__main__":
    main()
