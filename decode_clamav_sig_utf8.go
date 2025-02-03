// SPDX-License-Identifier: GPL-3.0-or-later
// © 2025 Stephan Hegemann

package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
)

func cleaned_utf8(b []byte) string {
	return strings.ToValidUTF8(string(b), "⚠")
}

func decode_extended_format(ef string, mode string) []string {
	wip_string := ef

	// match the first ? of a field of ? by looking where there is a ? that is not preceeded by a ?. Then replace it, but keep the character before the ? by inserting the capture group that I made for the character before the ? that is not a ?
	question_mark_begin_re := regexp.MustCompile(`([^?])\?`)
	wip_string = question_mark_begin_re.ReplaceAllString(wip_string, "$1\n?")
	// Same in reverse
	question_mark_end_re := regexp.MustCompile(`\?([^?])`)
	wip_string = question_mark_end_re.ReplaceAllString(wip_string, "?\n$1")
	wip_string = strings.ReplaceAll(wip_string, "{", "\n{")
	wip_string = strings.ReplaceAll(wip_string, "}", "}\n")
	wip_string = strings.ReplaceAll(wip_string, "(", "\n(")
	wip_string = strings.ReplaceAll(wip_string, ")", ")\n")
	// I hope no one is crazy enough to put more than one * back to back and tries to match multiples of infinity.
	wip_string = strings.ReplaceAll(wip_string, "*", "\n*\n")

	if mode == "ldb" || mode == "ldu" {
		modifier_re := regexp.MustCompile(`::([[:alnum:]])`)
		wip_string = modifier_re.ReplaceAllString(wip_string, "\n::$1")
	} else if mode == "ndb" || mode == "ndu" {

	} else {
		os.Exit(2)
	}

	wip_string_list := strings.Split(wip_string, "\n")

	var decoded_string_list []string
	// Identify lines that only contain hex in order to decode them
	hex_line_re := regexp.MustCompile(`^[[:xdigit:]]*$`)
	for _, s := range wip_string_list {
		if hex_line_re.FindString(s) != "" {
			bytes_from_hex, _ := hex.DecodeString(s)
			cleaned_utf8_from_bytes := cleaned_utf8(bytes_from_hex)
			decoded_string_list = append(decoded_string_list, fmt.Sprintf("%s\noriginal_hex(%s)", cleaned_utf8_from_bytes, s))
		} else {
			decoded_string_list = append(decoded_string_list, s)
		}
	}

	return decoded_string_list
}

func decode_ndb_line(line string) []string {
	split_line := strings.Split(line, ":")
	var decoded_line []string

	for i := 0; i < len(split_line); i++ {
		if i == 0 {
			decoded_line = append(decoded_line, fmt.Sprintf("Malware Name : %s", split_line[i]))
		} else if i == 1 {
			decoded_line = append(decoded_line, fmt.Sprintf("Target Type  : %s", split_line[i]))
		} else if i == 2 {
			decoded_line = append(decoded_line, fmt.Sprintf("Offset       : %s", split_line[i]))
		} else if i == 3 {
			decoded_line = append(decoded_line, "Hex Signature:")
			decoded_line = append(decoded_line, decode_extended_format(split_line[i], "ndb")...)
		}

	}
	return decoded_line
}

func decode_ldb_line(line string) []string {
	split_line := strings.Split(line, ";")
	var decoded_line []string

	for i := 0; i < len(split_line); i++ {
		if i == 0 {
			decoded_line = append(decoded_line, fmt.Sprintf("Signature Name           : %s", split_line[i]))
		} else if i == 1 {
			decoded_line = append(decoded_line, fmt.Sprintf("Target Description Block : %s", split_line[i]))
		} else if i == 2 {
			decoded_line = append(decoded_line, fmt.Sprintf("Logical Expression       : %s", split_line[i]))
		} else {
			decoded_line = append(decoded_line, fmt.Sprintf("Subsignature %d:", i-3))
			decoded_line = append(decoded_line, decode_extended_format(split_line[i], "ldb")...)
		}

	}
	return decoded_line
}

func print_help_and_exit() {
	fmt.Println("Usage:")
	fmt.Println("cat main.[ldb|ldu|ndb|ndu] | decode_clamav_to_utf8 [ldb|ldu|ndb|ndu]")
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		print_help_and_exit()
	}
	mode := os.Args[1]

	stdin := bufio.NewScanner(os.Stdin)

	if mode == "ldb" || mode == "ldu" {
		for stdin.Scan() {
			in_line := stdin.Text()
			for _, decoded_ldb_line := range decode_ldb_line(in_line) {
				fmt.Println(decoded_ldb_line)
			}
			fmt.Println()
		}
	} else if mode == "ndb" || mode == "ndu" {
		for stdin.Scan() {
			in_line := stdin.Text()
			for _, decoded_ndb_line := range decode_ndb_line(in_line) {
				fmt.Println(decoded_ndb_line)
			}
			fmt.Println()
		}
	} else {
		print_help_and_exit()
	}
}
