#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Remote Attestation Verification Script
Supports two verification modes:
1. CF+TOCTOU mode: Control Flow + TOCTOU range verification
2. CF+DF mode: Control Flow + Data Flow verification
"""

import re
import sys


CF_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")
CF_EVENT_RE = re.compile(r"^[0-9A-Fa-f]{8}$")
DF_MARKER_RE = re.compile(r"^[0-9A-Fa-f]{2}$")


def read_file_lines(filepath):
    """Read all non-empty lines from a file."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)
    except Exception as exc:
        print(f"[ERROR] Failed to read file {filepath}: {exc}")
        sys.exit(1)


def split_fields(line):
    """Split a line into fields and drop the trailing 'T' token if present."""
    parts = line.split()
    if parts and parts[-1].upper() == "T":
        parts = parts[:-1]
    return parts


def normalize_hex(token):
    """Normalize a hex token for comparison."""
    return token.lower()


def parse_int_auto(token):
    """Parse token as int; supports 0x-prefixed hex or decimal."""
    token = token.strip()
    if token.lower().startswith("0x"):
        return int(token, 16)
    return int(token, 10)


def parse_hex_value(token):
    """Parse a hex token without prefix as an integer."""
    return int(token, 16)


def parse_range_line(line):
    """Parse a range line like '0x0000--0x0002' or '0--0' (closed interval)."""
    if "--" not in line:
        return None
    left, right = [part.strip() for part in line.split("--", 1)]
    try:
        return (parse_int_auto(left), parse_int_auto(right))
    except ValueError:
        return None


def load_cf_data(cf_path):
    """Load CF data lines that contain a single hex field ending with T."""
    lines = read_file_lines(cf_path)
    cf_list = []
    for line_num, line in enumerate(lines, start=1):
        fields = split_fields(line)
        if len(fields) != 1 or not CF_HEX_RE.match(fields[0]):
            print(f"[ERROR] Invalid CF data line {line_num}: {line}")
            sys.exit(1)
        cf_list.append(normalize_hex(fields[0]))
    return cf_list


def load_toctou_ranges(toctou_path):
    """Load TOCTOU ranges as closed intervals."""
    lines = read_file_lines(toctou_path)
    ranges = []
    for line_num, line in enumerate(lines, start=1):
        rng = parse_range_line(line)
        if rng is None:
            print(f"[ERROR] Invalid TOCTOU range line {line_num}: {line}")
            sys.exit(1)
        ranges.append(rng)
    return ranges


def load_df_paths(df_path):
    """Load DF ranges grouped by 'call-ret Path x:' headers."""
    lines = read_file_lines(df_path)
    paths = []
    current_ranges = []
    for line_num, line in enumerate(lines, start=1):
        if line.lower().startswith("call-ret path"):
            if current_ranges:
                paths.append(current_ranges)
            current_ranges = []
            continue
        rng = parse_range_line(line)
        if rng is None:
            print(f"[ERROR] Invalid DF range line {line_num}: {line}")
            sys.exit(1)
        current_ranges.append(rng)
    if current_ranges:
        paths.append(current_ranges)
    print(f"[INFO] Loaded {len(paths)} call-ret Path(s) from {df_path}")
    return paths


def verify_cf_toctou_mode(runtime_path, cf_path, toctou_path):
    """Verify runtime data against CF data and TOCTOU ranges."""
    print("\n" + "=" * 60)
    print("Starting CF+TOCTOU Mode Verification")
    print("=" * 60)

    runtime_lines = read_file_lines(runtime_path)
    cf_list = load_cf_data(cf_path)
    toctou_ranges = load_toctou_ranges(toctou_path)

    if len(runtime_lines) != len(cf_list) or len(runtime_lines) != len(toctou_ranges):
        print("[FAILED] Line count mismatch among runtime, CF, and TOCTOU data")
        print(f"  Runtime lines: {len(runtime_lines)}")
        print(f"  CF lines: {len(cf_list)}")
        print(f"  TOCTOU lines: {len(toctou_ranges)}")
        return False

    failures = []
    for idx, line in enumerate(runtime_lines, start=1):
        fields = split_fields(line)
        if len(fields) != 2 or not CF_HEX_RE.match(fields[0]) or not CF_HEX_RE.match(fields[1]):
            failures.append((idx, "invalid_runtime", line))
            continue

        cf_token = normalize_hex(fields[0])
        toctou_value = parse_hex_value(fields[1])
        expected_cf = cf_list[idx - 1]
        min_r, max_r = toctou_ranges[idx - 1]

        if cf_token != expected_cf:
            failures.append((idx, "cf_mismatch", line, expected_cf))
            continue

        if not (min_r <= toctou_value <= max_r):
            failures.append((idx, "toctou_out", line, (min_r, max_r)))

    if failures:
        print(f"\n[FAILED] CF+TOCTOU verification failed! {len(failures)} issue(s):\n")
        for entry in failures[:20]:
            if entry[1] == "invalid_runtime":
                _, _, line = entry
                print(f"  Line {entry[0]} invalid runtime format: {line}")
            elif entry[1] == "cf_mismatch":
                _, _, line, expected_cf = entry
                print(f"  Line {entry[0]} CF mismatch: {line}")
                print(f"    Expected CF: {expected_cf}")
            else:
                _, _, line, expected = entry
                min_r, max_r = expected
                print(f"  Line {entry[0]} TOCTOU out of range: {line}")
                print(f"    Expected range: {min_r}--{max_r}")
        if len(failures) > 20:
            print(f"  ... and {len(failures) - 20} more issue(s)")
        return False

    print("\n[SUCCESS] CF+TOCTOU verification passed!")
    return True


def verify_df_mode(runtime_path, cf_path, df_path):
    """Verify runtime data against CF data and DF path ranges."""
    print("\n" + "=" * 60)
    print("Starting CF+DF Mode Verification")
    print("=" * 60)

    runtime_lines = read_file_lines(runtime_path)
    cf_list = load_cf_data(cf_path)
    df_paths = load_df_paths(df_path)

    failures = []
    pending_markers = []
    cf_index = 0

    for line_num, line in enumerate(runtime_lines, start=1):
        fields = split_fields(line)
        if len(fields) != 1 or not CF_HEX_RE.match(fields[0]):
            failures.append((line_num, "invalid_runtime", line))
            continue

        token = normalize_hex(fields[0])

        if DF_MARKER_RE.match(token):
            pending_markers.append((line_num, token))
            continue

        if CF_EVENT_RE.match(token):
            if cf_index >= len(cf_list):
                failures.append((line_num, "extra_cf", line))
                pending_markers = []
                continue

            expected_cf = cf_list[cf_index]
            if token != expected_cf:
                failures.append((line_num, "cf_mismatch", line, expected_cf))
                pending_markers = []
                continue

            path_index = cf_index
            if path_index >= len(df_paths):
                failures.append((line_num, "missing_path", line, path_index + 1))
                pending_markers = []
                cf_index += 1
                continue

            ranges = df_paths[path_index]
            marker_count = len(pending_markers)
            range_count = len(ranges)

            for idx, (marker_line, marker_token) in enumerate(pending_markers):
                if idx < range_count:
                    min_r, max_r = ranges[idx]
                    value = parse_hex_value(marker_token)
                    if not (min_r <= value <= max_r):
                        failures.append((
                            marker_line,
                            "df_out",
                            marker_token,
                            (min_r, max_r),
                            path_index + 1,
                            line_num,
                            line,
                        ))

            if marker_count > range_count:
                failures.append((
                    line_num,
                    "df_marker_count_mismatch",
                    path_index + 1,
                    marker_count,
                    range_count,
                    line,
                ))

            if range_count > marker_count:
                failures.append((
                    line_num,
                    "df_missing_marker",
                    path_index + 1,
                    marker_count,
                    range_count,
                    line,
                ))

            pending_markers = []
            cf_index += 1
            continue

        failures.append((line_num, "unknown_token", line))

    if pending_markers:
        failures.append((pending_markers[0][0], "dangling_markers", len(pending_markers)))

    if cf_index != len(cf_list):
        failures.append((0, "missing_cf", cf_index, len(cf_list)))

    if failures:
        print(f"\n[FAILED] CF+DF verification failed! {len(failures)} issue(s):\n")
        for entry in failures[:30]:
            kind = entry[1]
            if kind == "invalid_runtime":
                print(f"  Line {entry[0]} invalid runtime format: {entry[2]}")
            elif kind == "extra_cf":
                print(f"  Line {entry[0]} extra CF event not in CF data: {entry[2]}")
            elif kind == "cf_mismatch":
                print(f"  Line {entry[0]} CF mismatch: {entry[2]}")
                print(f"    Expected CF: {entry[3]}")
            elif kind == "missing_path":
                print(f"  Line {entry[0]} missing DF path for CF index {entry[3]}: {entry[2]}")
            elif kind == "df_out":
                min_r, max_r = entry[3]
                print(
                    f"  Line {entry[0]} DF marker {entry[2]} not in range {min_r}--{max_r}"
                    f" for Path {entry[4]}"
                )
                print(f"    Associated with CF line {entry[5]}: {entry[6]}")
            elif kind == "df_no_range":
                print(
                    f"  Line {entry[0]} DF marker {entry[2]} has no corresponding range for Path {entry[3]}"
                )
                print(f"    Associated with CF line {entry[4]}: {entry[5]}")
            elif kind == "df_missing_marker":
                print(
                    f"  Line {entry[0]} missing DF markers for Path {entry[2]}"
                    f" (markers={entry[3]}, ranges={entry[4]})"
                )
                print(f"    Associated with CF line {entry[5]}")
            elif kind == "df_marker_count_mismatch":
                print(
                    f"  Line {entry[0]} DF marker count exceeds ranges for Path {entry[2]}"
                    f" (markers={entry[3]}, ranges={entry[4]})"
                )
                print(f"    Associated with CF line {entry[5]}")
            elif kind == "dangling_markers":
                print(f"  Line {entry[0]} has {entry[2]} DF markers with no following CF event")
            elif kind == "missing_cf":
                print(f"  Missing CF events in runtime (matched={entry[2]}, expected={entry[3]})")
            else:
                print(f"  Line {entry[0]} unknown runtime token: {entry[2]}")

        if len(failures) > 30:
            print(f"  ... and {len(failures) - 30} more issue(s)")
        return False

    print("\n[SUCCESS] CF+DF verification passed!")
    return True


def main():
    """Main function."""
    if len(sys.argv) == 1 or sys.argv[1] in {"-h", "--help"}:
        print("Usage:")
        print("  CF+TOCTOU mode: python database_verify.py cf <runtime_data> <CF_data> <TOCTOU_data>")
        print("  CF+DF mode:     python database_verify.py df <runtime> <CF> <DF>")
        sys.exit(0 if len(sys.argv) > 1 else 1)

    mode = sys.argv[1].lower()
    if mode == "cf":
        if len(sys.argv) != 5:
            print("[ERROR] CF+TOCTOU mode requires 4 arguments: python database_verify.py cf <runtime_data> <CF_data> <TOCTOU_data>")
            sys.exit(1)
        runtime_path = sys.argv[2]
        cf_path = sys.argv[3]
        toctou_path = sys.argv[4]
        success = verify_cf_toctou_mode(runtime_path, cf_path, toctou_path)
        sys.exit(0 if success else 1)

    if mode == "df":
        if len(sys.argv) != 5:
            print("[ERROR] CF+DF mode requires 4 arguments: python database_verify.py df <runtime> <CF> <DF>")
            sys.exit(1)
        runtime_path = sys.argv[2]
        cf_path = sys.argv[3]
        df_path = sys.argv[4]
        success = verify_df_mode(runtime_path, cf_path, df_path)
        sys.exit(0 if success else 1)

    print("[ERROR] Unknown mode. Use 'cf' or 'df'.")
    sys.exit(1)


if __name__ == "__main__":
    main()

