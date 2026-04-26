#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Remote Attestation Verification Script
Supports two verification modes:
1. CF+TOCTOU mode: Control Flow verification
2. DF mode: Control Flow + Data Flow verification
"""

import sys
import re
from pathlib import Path


def read_file_lines(filepath):
    """Read all lines from file and strip whitespace"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Failed to read file {filepath}: {e}")
        sys.exit(1)


def is_cf_data_line(line):
    """
    Check if line is a CF data line
    Format: 20 hex chars + space + 4 hex chars + space + T
    Example: 0000DB5900003FF10003 0000 T
    """
    pattern = r'^[0-9A-Fa-f]{20}\s+[0-9A-Fa-f]{4}\s+T$'
    return re.match(pattern, line) is not None


def is_df_marker_line(line):
    """
    Check if line is a DF marker line
    Format: 2 hex chars + space + T
    Example: 09 T, 03 T
    """
    pattern = r'^[0-9A-Fa-f]{2}\s+T$'
    return re.match(pattern, line) is not None


def parse_df_marker(line):
    """
    Parse DF marker line and return integer value
    Example: '09 T' -> 9
    """
    if is_df_marker_line(line):
        # Extract the hex part (first 2 characters)
        hex_str = line.split()[0]
        return int(hex_str, 16)
    return None


def parse_df_range_line(line):
    """
    Parse range line in database-DF
    Supported formats:
    1. Range with double dash: 0x0000--0xffff
    2. Single value: 09 T
    Returns: (min_val, max_val) or None
    """
    line = line.strip()
    
    # Format 1: Range with '--' separator, e.g., 0x0000--0xffff
    if '--' in line:
        parts = line.split('--')
        if len(parts) == 2:
            try:
                # Remove 0x prefix if present
                min_str = parts[0].strip().replace('0x', '').replace('0X', '')
                max_str = parts[1].strip().replace('0x', '').replace('0X', '')
                min_val = int(min_str, 16)
                max_val = int(max_str, 16)
                return (min_val, max_val)
            except ValueError:
                pass
    
    # Format 2: Single value, e.g., "09 T"
    if is_df_marker_line(line):
        try:
            hex_str = line.split()[0]
            val = int(hex_str, 16)
            return (val, val)
        except (ValueError, IndexError):
            pass
    
    return None


def load_df_ranges(database_df_path):
    """
    Load all valid ranges from database-DF
    Returns: [(min1, max1), (min2, max2), ...]
    """
    lines = read_file_lines(database_df_path)
    ranges = []
    
    for line_num, line in enumerate(lines, start=1):
        range_tuple = parse_df_range_line(line)
        if range_tuple:
            ranges.append(range_tuple)
        else:
            print(f"[WARNING] database-DF line {line_num} has invalid format, skipped: {line}")
    
    print(f"[INFO] Loaded {len(ranges)} valid ranges from {database_df_path}")
    return ranges


def is_value_in_ranges(value, ranges):
    """
    Check if value is within any range
    value: integer value
    ranges: [(min1, max1), (min2, max2), ...]
    """
    for min_val, max_val in ranges:
        if min_val <= value <= max_val:
            return True
    return False


def verify_cf_toctou_mode(runtime_cf_path, database_cf_path):
    """
    CF+TOCTOU mode verification
    Verify if every line in runtime-CF exists in database-CF
    """
    print("\n" + "="*60)
    print("Starting CF+TOCTOU Mode Verification")
    print("="*60)
    
    runtime_lines = read_file_lines(runtime_cf_path)
    database_lines = read_file_lines(database_cf_path)
    
    # Build database set for fast lookup
    database_set = set(database_lines)
    
    print(f"[INFO] Runtime-CF lines: {len(runtime_lines)}")
    print(f"[INFO] Database-CF lines: {len(database_lines)}")
    
    failed_lines = []
    
    for line_num, line in enumerate(runtime_lines, start=1):
        if line not in database_set:
            failed_lines.append((line_num, line))
    
    if failed_lines:
        print(f"\n[FAILED] Verification failed! {len(failed_lines)} line(s) not found in database-CF:\n")
        for line_num, line in failed_lines[:10]:  # Show first 10 only
            print(f"  Line {line_num}: {line}")
        if len(failed_lines) > 10:
            print(f"  ... and {len(failed_lines) - 10} more line(s)")
        return False
    else:
        print(f"\n[SUCCESS] Verification passed! All {len(runtime_lines)} line(s) found in database-CF")
        return True


def verify_df_mode(runtime_df_path, database_cf_path, database_df_path):
    """
    DF mode verification
    1. Verify if CF data lines in runtime-DF exist in database-CF
    2. Verify if DF markers before CF data lines are within database-DF ranges
    """
    print("\n" + "="*60)
    print("Starting DF Mode Verification")
    print("="*60)
    
    runtime_lines = read_file_lines(runtime_df_path)
    database_cf_lines = read_file_lines(database_cf_path)
    
    # Build database-CF set
    database_cf_set = set(database_cf_lines)
    
    # Load valid ranges from database-DF
    df_ranges = load_df_ranges(database_df_path)
    
    if not df_ranges:
        print("[WARNING] No valid range data in database-DF")
    
    print(f"[INFO] Runtime-DF lines: {len(runtime_lines)}")
    print(f"[INFO] Database-CF lines: {len(database_cf_lines)}")
    
    cf_failed = []
    df_failed = []
    pending_df_markers = []  # Pending DF markers to verify
    
    for line_num, line in enumerate(runtime_lines, start=1):
        if is_cf_data_line(line):
            # This is a CF data line
            # Step 1: Verify if CF data exists in database-CF
            if line not in database_cf_set:
                cf_failed.append((line_num, line))
                # CF verification failed, clear pending DF markers
                pending_df_markers = []
                continue
            
            # Step 2: CF verification passed, verify all collected DF markers
            for df_line_num, df_marker_str, df_value in pending_df_markers:
                if not is_value_in_ranges(df_value, df_ranges):
                    df_failed.append((df_line_num, df_marker_str, df_value, line_num, line))
            
            # Clear pending list, prepare for next CF data line
            pending_df_markers = []
            
        elif is_df_marker_line(line):
            # This is a DF marker line, add to pending list
            df_value = parse_df_marker(line)
            if df_value is not None:
                pending_df_markers.append((line_num, line, df_value))
    
    # Report results
    success = True
    
    if cf_failed:
        print(f"\n[FAILED] CF verification failed! {len(cf_failed)} line(s) not found in database-CF:\n")
        for line_num, line in cf_failed[:10]:
            print(f"  Line {line_num}: {line}")
        if len(cf_failed) > 10:
            print(f"  ... and {len(cf_failed) - 10} more line(s)")
        success = False
    else:
        print(f"\n[SUCCESS] CF verification passed!")
    
    if df_failed:
        print(f"\n[FAILED] DF verification failed! {len(df_failed)} marker(s) not within valid ranges:\n")
        for df_line_num, df_marker_str, df_value, cf_line_num, cf_line in df_failed[:10]:
            print(f"  Line {df_line_num} {df_marker_str} (value={df_value:#x})")
            print(f"    Associated with CF line {cf_line_num}: {cf_line}")
        if len(df_failed) > 10:
            print(f"  ... and {len(df_failed) - 10} more marker(s)")
        success = False
    else:
        print(f"[SUCCESS] DF verification passed!")
    
    if success:
        print(f"\n" + "="*60)
        print("[SUCCESS] DF Mode Verification Completely Passed!")
        print("="*60)
    else:
        print(f"\n" + "="*60)
        print("[FAILED] DF Mode Verification Failed!")
        print("="*60)
    
    return success


def main():
    """Main function"""
    # Default mode is CF+TOCTOU
    if len(sys.argv) == 1:
        print("Usage:")
        print("  Default (CF+TOCTOU): python verify_attestation.py <runtime-CF> <database-CF>")
        print("  CF+TOCTOU mode:      python verify_attestation.py cf <runtime-CF> <database-CF>")
        print("  DF mode:             python verify_attestation.py df <runtime-DF> <database-CF> <database-DF>")
        print("\nExamples:")
        print("  python verify_attestation.py runtime-CF.txt database-CF.txt")
        print("  python verify_attestation.py cf runtime-CF.txt database-CF.txt")
        print("  python verify_attestation.py df runtime-DF.txt database-CF.txt database-DF.txt")
        sys.exit(1)
    
    # Check if first argument is a mode or a file
    first_arg = sys.argv[1].lower()
    
    if first_arg in ['cf', 'df']:
        # Mode explicitly specified
        mode = first_arg
        
        if mode == 'cf':
            if len(sys.argv) != 4:
                print("[ERROR] CF mode requires 3 arguments: python verify_attestation.py cf <runtime-CF> <database-CF>")
                sys.exit(1)
            
            runtime_cf = sys.argv[2]
            database_cf = sys.argv[3]
            
            success = verify_cf_toctou_mode(runtime_cf, database_cf)
            sys.exit(0 if success else 1)
        
        elif mode == 'df':
            if len(sys.argv) != 5:
                print("[ERROR] DF mode requires 4 arguments: python verify_attestation.py df <runtime-DF> <database-CF> <database-DF>")
                sys.exit(1)
            
            runtime_df = sys.argv[2]
            database_cf = sys.argv[3]
            database_df = sys.argv[4]
            
            success = verify_df_mode(runtime_df, database_cf, database_df)
            sys.exit(0 if success else 1)
    else:
        # No mode specified, default to CF+TOCTOU
        if len(sys.argv) != 3:
            print("[ERROR] Default CF+TOCTOU mode requires 2 arguments: python verify_attestation.py <runtime-CF> <database-CF>")
            print("Or specify mode explicitly: python verify_attestation.py cf/df ...")
            sys.exit(1)
        
        runtime_cf = sys.argv[1]
        database_cf = sys.argv[2]
        
        success = verify_cf_toctou_mode(runtime_cf, database_cf)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

