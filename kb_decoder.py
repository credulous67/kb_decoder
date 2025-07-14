#!/usr/bin/env python3

"""
Decodes a 16-byte Thales or TR-31 keyblock header and provides a human-readable
explanation in a formatted table, constrained to 80 columns.

Based on the provided "Thales keyblock.pdf" and "TR31 keyblock.pdf"
specifications.
"""

import textwrap

# --- TR-31 Field Value Mappings ---
TR31_VERSION_ID = {
    'A': "Version 'A' (TR-31:2005) - Key Variant Binding Method",
    'B': "Version 'B' (TR-31:2010) - Key Derivation Binding Method",
    'C': "Version 'C' (TR-31:2010) - Key Variant Binding Method",
    'D': "Version 'D' (TR-31:2018) - AES Key Derivation Binding Method",
}

TR31_KEY_USAGE = {
    'B0': "Base Derivation Key (BDK)",
    'B1': "DUKPT Initial Key (IKEY)",
    'C0': "Card Verification Key",
    'D0': "Data Encryption Key (Generic)",
    'E0': "EMV/Chip card Master Key: Application Cryptogram (MKAC)",
    'E1': "EMV/Chip card Master Key: Secure Messaging for Confidentiality (MKSMC)",
    'E2': "EMV/Chip card Master Key: Secure Messaging for Integrity (MKSMI)",
    'E3': "EMV/Chip card Master Key: Data Authentication Code (MKDAC)",
    'E4': "EMV/Chip card Master Key: Dynamic Numbers (MKDN)",
    'E5': "EMV/Chip card Master Key: Card Personalisation",
    'E6': "EMV/chip card Master Key: Other",
    'I0': "Initialization Value",
    'K0': "Key Encryption / Wrapping Key (Generic)",
    'M0': "ISO 16609 MAC algorithm 1 (using 3DES)",
    'M1': "ISO 9797-1 MAC algorithm 1",
    'M2': "ISO 9797-1 MAC algorithm 2",
    'M3': "ISO 9797-1 MAC algorithm 3",
    'M4': "ISO 9797-1 MAC algorithm 4",
    'M5': "ISO 9797-1:1999 MAC algorithm 5",
    'M6': "ISO 9797-1:2011 MAC algorithm 5/CMAC",
    'P0': "PIN Encryption Key (Generic)",
    'V0': "PIN Verification Key (Generic)",
    'V1': "PIN Verification Key (IBM 3624 algorithm)",
    'V2': "PIN Verification Key (Visa PVV algorithm)",
}

TR31_ALGORITHM = {
    'A': "AES",
    'D': "DES (for backwards compatibility)",
    'E': "Elliptic Curve (for future reference)",
    'H': "HMAC-SHA1 (for future reference)",
    'R': "RSA (for future reference)",
    'S': "DSA (for future reference)",
    'T': "3DES",
}

TR31_MODE_OF_USE = {
    'B': "Both Encrypt and Decrypt",
    'C': "MAC Calculate (Generate or Verify)",
    'D': "Decrypt Only",
    'E': "Encrypt Only",
    'G': "MAC Generate Only",
    'N': "No special restrictions or not applicable",
    'S': "Signature Only",
    'T': "Both Sign and Decrypt",
    'V': "MAC Verify Only",
    'X': "Key Derivation",
    'Y': "Key used to create key variants",
}

TR31_EXPORTABILITY = {
    'E': "Exportable: May only be exported in a trusted Key Block",
    'N': "Not exportable: No export permitted",
    'S': "Sensitive: Other export possibilities are permitted if enabled",
}


# --- Thales Field Value Mappings ---
THALES_VERSION_ID = {
    '0': "Version '0' - Protected by a 3DES key",
    '1': "Version '1' - Protected by an AES key",
}

THALES_KEY_USAGE = {
    '01': "WatchWord Key (WWK)", '02': "RSA Public Key",
    '03': "RSA Private Key (signing/key mgt)", '04': "RSA Private Key (for ICCs)",
    '05': "RSA Private Key (PIN translation)", '06': "RSA Private Key (TLS)",
    'B0': "Base Derivation Key (BDK-1)", '41': "Base Derivation Key (BDK-2)",
    '42': "Base Derivation Key (BDK-3)", '43': "Base Derivation Key (BDK-4)",
    '44': "Base Derivation Key (BDK-5)", 'B1': "DUKPT Initial Key (IKEY)",
    'C0': "Card Verification Key", '11': "Card Verification Key (Amex CSC)",
    '12': "Card Verification Key (Mastercard CVC)", '13': "Card Verification Key (Visa CVV)",
    'D0': "Data Encryption Key (Generic)", '21': "Data Encryption Key (DEK)",
    '22': "Data Encryption Key (ZEK)", '23': "Data Encryption Key (TEK)",
    '24': "Key Encryption Key (Transport Key)", '25': "CTR Data Encryption Key",
    'E0': "EMV Master Key: App Cryptogram (MK-AC)",
    'E1': "EMV Master Key: Secure Msg Confidentiality (MK-SMC)",
    'E2': "EMV Master Key: Secure Msg Integrity (MK-SMI)",
    'E3': "EMV Master Key: Data Auth Code (MK-DAC)",
    'E4': "EMV Master Key: Dynamic Numbers (MK-DN)",
    'E5': "EMV Master Key: Card Personalization", 'E6': "EMV Master Key: Other",
    'E7': "EMV/Master Personalization Key", '31': "Visa Cash Master Load Key (KML)",
    '32': "Dynamic CVV Master Key (MK-CVC3)", '33': "Mobile Mgt Master Key (Confidentiality)",
    '34': "Mobile Mgt Master Key (Integrity)", '35': "Mobile Mgt Session Key (Confidentiality)",
    '36': "Mobile Mgt Session Key (Integrity)", '37': "EMV Card Key (Cryptograms)",
    '38': "EMV Card Key (Integrity)", '39': "EMV Card Key (Encryption)",
    '40': "EMV Personalization System Key", '47': "EMV Session Key (Cryptograms)",
    '48': "EMV Session Key (Integrity)", '49': "EMV Session Key (Encryption)",
    'I0': "Initialization Value", 'K0': "Key Encryption / Wrapping Key (Generic)",
    '51': "Terminal Key Encryption (TMK)", '52': "Zone Key Encryption (ZMK)",
    '53': "ZKA Master Key", '54': "Key Encryption Key (KEK)",
    '55': "Key Encryption Key (Transport Key)", 'M0': "ISO 16609 MAC algorithm 1",
    'M1': "ISO 9797-1 MAC algorithm 1", 'M2': "ISO 9797-1 MAC algorithm 2",
    'M3': "ISO 9797-1 MAC algorithm 3", 'M4': "ISO 9797-1 MAC algorithm 4",
    'M5': "ISO 9797-1:1999 MAC algorithm 5", 'M6': "ISO 9797-1:2011 MAC algorithm 5/CMAC",
    '61': "HMAC key (SHA-1)", '62': "HMAC key (SHA-224)",
    '63': "HMAC key (SHA-256)", '64': "HMAC key (SHA-384)",
    '65': "HMAC key (SHA-512)", 'P0': "PIN Encryption Key (Generic)",
    '71': "Terminal PIN Encryption Key (TPK)", '72': "Zone PIN Encryption Key (ZPK)",
    '73': "Transaction Key Register (TKR)", 'V0': "PIN Verification Key (Generic)",
    'V1': "PIN Verification Key (IBM 3624)", 'V2': "PIN Verification Key (Visa PVV)",
}

THALES_ALGORITHM = {
    'A': "AES", 'D': "DES", 'E': "Elliptic curve", 'H': "HMAC",
    'R': "RSA", 'S': "DSA", 'T': "3DES",
}

THALES_MODE_OF_USE = {
    'B': "Both encryption and decryption", 'C': "Both generate and verify",
    'D': "Decrypt only", 'E': "Encrypt only", 'G': "Generate only",
    'N': "No special restrictions", 'S': "Digital signature generation only",
    'V': "Verify only / Sig verification", 'X': "Derivation only",
}

THALES_EXPORTABILITY = {
    'E': "Exportable in a trusted key block", 'N': "Not exportable",
    'S': "Sensitive: Other exports permitted if enabled",
}

def print_row(field, byte_range, value, description):
    """Formats and prints a single row of the output table."""
    field_w, byte_w, value_w = 18, 7, 8
    desc_w = 80 - field_w - byte_w - value_w - 4

    wrapped_desc = textwrap.wrap(description, width=desc_w) or [""]
    
    first_line = f"{field:<{field_w}} {byte_range:<{byte_w}} {value:<{value_w}} {wrapped_desc[0]}"
    print(first_line)

    for line in wrapped_desc[1:]:
        print(f"{'':<{field_w}} {'':<{byte_w}} {'':<{value_w}} {line}")

def print_header(title, header_str):
    """Prints the title and header for the output table."""
    print(f"---[ {title} ]---".center(80))
    print(f"Header: {header_str}".center(80))
    print("-" * 80)
    print_row("Field", "Bytes", "Value", "Description")
    print("-" * 80)

def decode_tr31_header(header):
    """Decodes and prints a 16-byte TR-31 keyblock header."""
    print_header("Decoding TR-31 Keyblock Header", header)

    print_row("Version ID", "0", f"'{header[0]}'", TR31_VERSION_ID.get(header[0], 'Unknown'))
    print_row("Key Block Length", "1-4", f"'{header[1:5]}'", "Total length of the keyblock in bytes")
    print_row("Key Usage", "5-6", f"'{header[5:7]}'", TR31_KEY_USAGE.get(header[5:7], 'Proprietary'))
    print_row("Algorithm", "7", f"'{header[7]}'", TR31_ALGORITHM.get(header[7], 'Proprietary'))
    print_row("Mode of Use", "8", f"'{header[8]}'", TR31_MODE_OF_USE.get(header[8], 'Proprietary'))
    
    kvn = header[9:11]
    if kvn == "00": desc = "Versioning not used"
    elif kvn.startswith('C'): desc = f"Key component ({kvn[1]})"
    else: desc = f"Key version is '{kvn}'"
    print_row("Key Version", "9-10", f"'{kvn}'", desc)

    print_row("Exportability", "11", f"'{header[11]}'", TR31_EXPORTABILITY.get(header[11], 'Proprietary'))
    print_row("Optional Blocks", "12-13", f"'{header[12:14]}'", "Number of optional blocks")
    print_row("Reserved", "14-15", f"'{header[14:16]}'", "Reserved for future use (should be '00')")
    print("-" * 80)

def decode_thales_header(header):
    """Decodes and prints a 16-byte Thales keyblock header."""
    print_header("Decoding Thales Keyblock Header", header)

    print_row("Version ID", "0", f"'{header[0]}'", THALES_VERSION_ID.get(header[0], 'Unknown'))
    print_row("Key Block Length", "1-4", f"'{header[1:5]}'", "Total length of the keyblock in bytes")
    print_row("Key Usage", "5-6", f"'{header[5:7]}'", THALES_KEY_USAGE.get(header[5:7], 'Unknown'))
    print_row("Algorithm", "7", f"'{header[7]}'", THALES_ALGORITHM.get(header[7], 'Unknown'))
    print_row("Mode of Use", "8", f"'{header[8]}'", THALES_MODE_OF_USE.get(header[8], 'Unknown'))

    kvn = header[9:11]
    if kvn == "00": desc = "Versioning not used"
    elif kvn.startswith('C'): desc = f"Key component number {kvn[1]}"
    else: desc = f"Key version is '{kvn}'"
    print_row("Key Version", "9-10", f"'{kvn}'", desc)
    
    print_row("Exportability", "11", f"'{header[11]}'", THALES_EXPORTABILITY.get(header[11], 'Unknown'))
    print_row("Optional Blocks", "12-13", f"'{header[12:14]}'", "Number of optional blocks")
    print_row("LMK ID", "14-15", f"'{header[14:16]}'", "Identifier for the LMK")
    print("-" * 80)

def main():
    """Main function to get user input and call the appropriate decoder."""
    print("Keyblock Header Decoder".center(80))
    print("=" * 80)
    
    # Example from TR-31 PDF for demonstration
    example_header = "A0072V2TG22N0000"
    print(f"Running with example from TR-31 documentation: {example_header}\n")
    decode_tr31_header(example_header)
    print("\n" + "=" * 80 + "\n")

    while True:
        header = input("Enter 16-byte keyblock header (or 'q' to quit): ").replace(' ', '').strip().upper()

        if header == 'Q':
            break

        if len(header) != 16:
            print("\nError: Header must be exactly 16 bytes long. Please try again.\n")
            continue

        first_byte = header[0]
        if first_byte in TR31_VERSION_ID:
            decode_tr31_header(header)
        elif first_byte in THALES_VERSION_ID:
            decode_thales_header(header)
        else:
            msg = f"Unknown keyblock type. First byte '{first_byte}' is not a valid ID."
            print(f"\nError: {msg}\n")

        print("\n" + "=" * 80 + "\n")

if __name__ == "__main__":
    main()

