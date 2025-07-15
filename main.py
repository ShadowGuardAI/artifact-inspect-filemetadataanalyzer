import argparse
import os
import stat
import time
import logging
import pefile
import magic

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Analyzes file metadata and flags anomalies.")
    parser.add_argument("filepath", help="Path to the file to analyze.")
    parser.add_argument("-t", "--threshold", type=int, default=30,
                        help="Threshold in days for flagging old modification/creation dates. Defaults to 30 days.")
    parser.add_argument("-o", "--owner", type=str,
                        help="Expected owner of the file. Flags if different.")
    parser.add_argument("-p", "--permissions", type=str,
                        help="Expected permissions (e.g., 'rwxr-xr--'). Flags if different.")
    parser.add_argument("--pe_check", action="store_true",
                        help="Perform additional checks if the file is a PE executable.")
    return parser.parse_args()


def analyze_file_metadata(filepath, threshold_days=30, expected_owner=None, expected_permissions=None):
    """
    Analyzes file metadata and flags anomalies based on provided thresholds and expectations.

    Args:
        filepath (str): Path to the file.
        threshold_days (int): Threshold in days for flagging old modification/creation dates.
        expected_owner (str): Expected owner of the file.
        expected_permissions (str): Expected permissions of the file (e.g., 'rwxr-xr--').
    """
    try:
        # Input validation
        if not isinstance(filepath, str):
            raise TypeError("Filepath must be a string.")
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        if not isinstance(threshold_days, int) or threshold_days < 0:
            raise ValueError("Threshold must be a non-negative integer.")
        if expected_owner and not isinstance(expected_owner, str):
            raise TypeError("Expected owner must be a string.")
        if expected_permissions and not isinstance(expected_permissions, str):
            raise TypeError("Expected permissions must be a string.")

        # Get file stats
        stat_info = os.stat(filepath)

        # Creation date (platform-dependent, often not reliable)
        creation_time = stat_info.st_ctime
        creation_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(creation_time))

        # Modification date
        modification_time = stat_info.st_mtime
        modification_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(modification_time))

        # Access date
        access_time = stat_info.st_atime
        access_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(access_time))

        # File size
        file_size = stat_info.st_size

        # Owner (UID)
        owner_uid = stat_info.st_uid

        # Permissions
        permissions = stat.filemode(stat_info.st_mode)

        logging.info(f"Analyzing file: {filepath}")
        logging.info(f"  Creation Date: {creation_date}")
        logging.info(f"  Modification Date: {modification_date}")
        logging.info(f"  Access Date: {access_date}")
        logging.info(f"  File Size: {file_size} bytes")
        logging.info(f"  Owner UID: {owner_uid}")
        logging.info(f"  Permissions: {permissions}")

        # Anomaly detection
        current_time = time.time()
        age_in_seconds = current_time - modification_time
        age_in_days = age_in_seconds / (60 * 60 * 24)

        if age_in_days > threshold_days:
            logging.warning(f"  [ANOMALY] Modification date is older than {threshold_days} days.")

        if expected_owner and str(owner_uid) != expected_owner:
            logging.warning(f"  [ANOMALY] Owner UID ({owner_uid}) does not match expected owner ({expected_owner}).")

        if expected_permissions and permissions != expected_permissions:
            logging.warning(f"  [ANOMALY] Permissions ({permissions}) do not match expected permissions ({expected_permissions}).")

    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        return
    except PermissionError as e:
        logging.error(f"Permission error: {e}")
        return
    except OSError as e:
        logging.error(f"OS error: {e}")
        return
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return


def analyze_pe_metadata(filepath):
    """
    Analyzes metadata specific to PE (Portable Executable) files.

    Args:
        filepath (str): Path to the PE file.
    """
    try:
        # Input validation
        if not isinstance(filepath, str):
            raise TypeError("Filepath must be a string.")
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        try:
            pe = pefile.PE(filepath)
        except pefile.PEFormatError as e:
            logging.warning(f"  [WARNING] Not a valid PE file or PE format error: {e}")
            return

        logging.info(f"Analyzing PE metadata for: {filepath}")

        # Check for suspicious sections
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            logging.info(f"  Section: {section_name}")
            logging.info(f"    Virtual Address: 0x{section.VirtualAddress:x}")
            logging.info(f"    Size of Raw Data: 0x{section.SizeOfRawData:x}")
            logging.info(f"    Characteristics: 0x{section.Characteristics:x}")

            if section.SizeOfRawData == 0 and section.Characteristics & 0x40000040:  # CODE and EXECUTE
                logging.warning("  [ANOMALY] Section with no raw data but marked as CODE and EXECUTABLE.")
            if ".text" not in section_name.lower() and section.Characteristics & 0x20000000:  # MEM_WRITE
                logging.warning("  [ANOMALY] Section marked as WRITEABLE but not named '.text'.")

        # Check for imports from known malicious DLLs
        suspicious_dlls = ["kernel32.dll", "user32.dll", "advapi32.dll", "ws2_32.dll"] # Example list, can be extended
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
            if dll_name in suspicious_dlls:
                logging.info(f"    Imports from {dll_name}:")
                for imp in entry.imports:
                    if imp.name:
                        logging.info(f"       {imp.name.decode('utf-8', errors='ignore')}")
                    else:
                        logging.info("       (Import by ordinal)")

        # Check file type (using magic)
        try:
            file_type = magic.from_file(filepath)
            logging.info(f"  File Type (magic): {file_type}")
        except magic.MagicException as e:
            logging.error(f"  Error getting file type using magic: {e}")

    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        return
    except pefile.PEFormatError as e:
        logging.error(f"  [ERROR] Not a valid PE file or PE format error: {e}")
        return
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return


def main():
    """
    Main function to execute the file metadata analysis.
    """
    args = setup_argparse()

    analyze_file_metadata(args.filepath, args.threshold, args.owner, args.permissions)

    if args.pe_check:
        analyze_pe_metadata(args.filepath)


if __name__ == "__main__":
    main()