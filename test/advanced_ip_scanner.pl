#-----------------------------------------------------------
# advanced_ip_scanner.pl
#
# Extracts forensic artefacts left by Advanced IP Scanner (AIS / Famatech)
# from NTUSER.DAT. Reports:
#   - Application version
#   - Locale (language) and first-execution timestamp
#   - Scan result display filters (show_alive, show_dead, show_unknown)
#   - Last IP range scanned (LastRangeUsed)
#   - Full scan history with scan-frequency counts (IpRangesMruList)
#   - IP address search history (SearchMruList)
#   - Last active tab on close (LastActiveTab)
#   - Last update-check timestamp (CheckUpdates\LastCheck, Qt @DateTime format)
#   - Registry key LastWrite timestamps for temporal analysis
#
# Registry path:
#   HKCU\Software\Famatech\advanced_ip_scanner
#
# Forensic significance:
#   Advanced IP Scanner is a free network scanner widely abused by ransomware
#   operators (Conti, DarkSide, REvil, Ryuk, Egregor, Hades/EvilCorp, Dharma,
#   UNC2447, UNC2465, UNC1878) for internal reconnaissance (MITRE T1046/T1595).
#   The locale value may reveal the operator's language preference; the
#   locale_timestamp records the first execution time in Unix epoch milliseconds
#   (UTC); IpRangesMruList preserves all scanned subnets with scan-frequency
#   counters; SearchMruList records individual IP lookups.
#
# Qt @DateTime binary format (CheckUpdates\LastCheck):
#   The value is stored as a REG_BINARY blob containing a UTF-16LE string of
#   the form @DateTime(<payload>). The payload, decoded as one byte per UTF-16LE
#   code unit, has the following layout (all big-endian):
#     Bytes 0-3  : QDataStream version (quint32) -- typically 0x10 = Qt_5_1
#     Bytes 5-12 : Julian Day number (quint64)
#     Bytes 13-16: Milliseconds since midnight (quint32)
#     Byte  17   : Qt::TimeSpec (0=Local, 1=UTC, 2=OffsetFromUTC, 3=TimeZone)
#
# Change history
#   20260503 - created
#
# References
#   https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
#
#-----------------------------------------------------------
package advanced_ip_scanner;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              category      => "program execution",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 1,
              osmask        => 22,
              version       => 20260503);

my $VERSION = getVersion();

sub getDescr {}
sub getConfig {return %config}
sub getHive   {return $config{hive};}
sub getVersion{return $config{version};}

sub getShortDescr {
	return "Extracts execution, locale, scan history and update-check artefacts for Advanced IP Scanner (Famatech).";
}

sub getRefs {
	my %refs = (
		"Hunt & Hackett - Advanced IP Scanner: the preferred scanner in the A(P)T toolbox" =>
			"https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox",
	);
	return %refs;
}

# ---------------------------------------------------------------------------
# _decode_qt_datetime
#   Decodes a Qt @DateTime() binary blob stored as a REG_BINARY value.
#   The blob is a UTF-16LE string; each UTF-16LE code unit encodes one byte
#   of the QDataStream payload.
#
#   Returns a human-readable string such as "2026-05-04 02:17:57 UTC"
#   or an error string if the format is unrecognised.
# ---------------------------------------------------------------------------
sub _decode_qt_datetime {
	my $raw = shift;          # raw bytes from get_data() on a REG_BINARY value

	# The blob is a UTF-16LE string: @DateTime(<payload>)
	# Decode UTF-16LE to get the Unicode string
	my $str = "";
	for (my $i = 0; $i + 1 < length($raw); $i += 2) {
		my $lo = ord(substr($raw, $i,   1));
		my $hi = ord(substr($raw, $i+1, 1));
		my $cp = $lo | ($hi << 8);
		$str .= chr($cp);
	}

	# Verify the wrapper
	unless ($str =~ /^\@DateTime\((.+)\)$/) {
		return "(unrecognised Qt DateTime format)";
	}
	my $inner = $1;

	# Each character in $inner represents one byte of the binary payload
	my @bytes = map { ord($_) } split(//, $inner);
	my $n = scalar @bytes;

	# Minimum payload: 4 (version) + 8 (JD) + 4 (ms) + 1 (spec) = 17 bytes
	# Observed layout: version at [0..3], JD at [5..12], ms at [13..16], spec at [17]
	# (byte 4 is always 0x00 -- padding / high byte of the 8-byte JD field)
	unless ($n >= 17) {
		return "(Qt DateTime payload too short: $n bytes)";
	}

	# Julian Day (big-endian quint64) at bytes 5..12
	my $jd = 0;
	for my $b (@bytes[5..12]) {
		$jd = ($jd << 8) | $b;
	}

	# Milliseconds since midnight (big-endian quint32) at bytes 13..16
	my $ms = 0;
	for my $b (@bytes[13..16]) {
		$ms = ($ms << 8) | $b;
	}

	# TimeSpec at byte 17
	my $spec = ($n >= 18) ? $bytes[17] : 0;
	my %spec_name = (0 => "Local", 1 => "UTC", 2 => "OffsetFromUTC", 3 => "TimeZone");
	my $spec_str  = exists $spec_name{$spec} ? $spec_name{$spec} : "Unknown($spec)";

	# Convert Julian Day to Gregorian date
	# Algorithm: Richards (2013) via Wikipedia "Julian day"
	# Valid for JD >= 0 (proleptic Gregorian)
	unless ($jd > 2299160) {   # sanity: must be after 1582-10-15
		return "(invalid Julian Day: $jd)";
	}

	my $f = $jd + 1401 + int((int((4 * $jd + 274277) / 146097) * 3) / 4) - 38;
	my $e = 4 * $f + 3;
	my $g = int(($e % 1461) / 4);
	my $h = 5 * $g + 2;
	my $day   = int(($h % 153) / 5) + 1;
	my $month = (int($h / 153) + 2) % 12 + 1;
	my $year  = int($e / 1461) - 4716 + int((14 - $month) / 12);

	# Convert milliseconds to H:M:S
	my $total_s = int($ms / 1000);
	my $ms_part = $ms % 1000;
	my $hh      = int($total_s / 3600);
	my $mm      = int(($total_s % 3600) / 60);
	my $ss      = $total_s % 60;

	return sprintf("%04d-%02d-%02d %02d:%02d:%02d.%03d %s",
		$year, $month, $day, $hh, $mm, $ss, $ms_part, $spec_str);
}

# ---------------------------------------------------------------------------
# _decode_locale_timestamp
#   Converts a Unix epoch in milliseconds (stored as a REG_SZ string) to a
#   human-readable UTC datetime string.
# ---------------------------------------------------------------------------
sub _decode_locale_timestamp {
	my $ts_ms = shift;
	return "(empty)" unless ($ts_ms && $ts_ms =~ /^\d+$/);

	my $epoch_s = int($ts_ms / 1000);
	my $ms_part = $ts_ms % 1000;

	# Use RegRipper's built-in helper which returns "YYYY-MM-DD HH:MM:SS"
	my $date_str = ::getDateFromEpoch($epoch_s);
	return "$date_str.${ms_part} UTC (epoch ms: $ts_ms)";
}

# ---------------------------------------------------------------------------
# _parse_mru_list
#   Parses IpRangesMruList / SearchMruList.
#
#   The value may use either of two layouts depending on the AIS version:
#     Layout A (single-line): "[count]-[unknown] [value]\n[count]-[unknown] [value]\n..."
#     Layout B (two-line):    "[count]-[unknown]\n[value]\n[count]-[unknown]\n[value]\n..."
#
#   Returns a list of hash-refs: { count, unknown, value }.
# ---------------------------------------------------------------------------
sub _parse_mru_list {
	my $raw = shift;
	return () unless $raw;

	my @lines = split(/\r?\n/, $raw);
	my @entries;
	my $i = 0;
	while ($i < scalar @lines) {
		my $line = $lines[$i];
		$line =~ s/^\s+|\s+$//g;
		$i++;
		next unless length($line);

		if ($line =~ /^(\d+)-(\d+)\s+(.+)$/) {
			# Layout A: prefix and value on the same line
			push @entries, { count => $1, unknown => $2, value => $3 };
		} elsif ($line =~ /^(\d+)-(\d+)$/) {
			# Layout B: prefix alone; value is on the next non-empty line
			my ($cnt, $unk) = ($1, $2);
			my $val = "";
			while ($i < scalar @lines) {
				my $next = $lines[$i];
				$next =~ s/^\s+|\s+$//g;
				$i++;
				if (length($next)) {
					$val = $next;
					last;
				}
			}
			push @entries, { count => $cnt, unknown => $unk, value => $val };
		} else {
			push @entries, { count => "?", unknown => "?", value => $line };
		}
	}
	return @entries;
}

# ---------------------------------------------------------------------------
# pluginmain
# ---------------------------------------------------------------------------
sub pluginmain {
	my $class = shift;
	my $hive  = shift;

	::logMsg("Launching advanced_ip_scanner v.".$VERSION);
	::rptMsg("advanced_ip_scanner v.".$VERSION);
	::rptMsg("(".getHive().") ".getShortDescr()."\n");

	my $reg      = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

	my $base_path = "Software\\Famatech\\advanced_ip_scanner";
	my $base_key;

	unless ($base_key = $root_key->get_subkey($base_path)) {
		::rptMsg("$base_path not found.");
		::rptMsg("Advanced IP Scanner does not appear to have been executed under this user profile.");
		return;
	}

	# -----------------------------------------------------------------------
	# Section 1: Application root key
	# -----------------------------------------------------------------------
	::rptMsg("=" x 72);
	::rptMsg("ADVANCED IP SCANNER - APPLICATION KEY");
	::rptMsg("=" x 72);
	::rptMsg("Key  : $base_path");
	::rptMsg("MTime: ".::getDateFromEpoch($base_key->get_timestamp())."Z");
	::rptMsg("");

	my $run = eval { $base_key->get_value("run")->get_data() };
	::rptMsg(sprintf("  %-22s : %s", "Version (run)", $run // "(not set)"));

	my $locale = eval { $base_key->get_value("locale")->get_data() };
	::rptMsg(sprintf("  %-22s : %s", "Locale", $locale // "(not set)"));

	my $locale_ts = eval { $base_key->get_value("locale_timestamp")->get_data() };
	if ($locale_ts) {
		::rptMsg(sprintf("  %-22s : %s",
			"First Execution (UTC)",
			_decode_locale_timestamp($locale_ts)));
		::rptMsg("  " . " " x 22 . "   NOTE: locale_timestamp is set at first launch and");
		::rptMsg("  " . " " x 22 . "   does not update on subsequent executions.");
	} else {
		::rptMsg(sprintf("  %-22s : (not set)", "First Execution (UTC)"));
	}

	::rptMsg("");
	::rptMsg("  Scan result display filters:");
	my $show_alive   = eval { $base_key->get_value("show_alive")->get_data()   };
	my $show_dead    = eval { $base_key->get_value("show_dead")->get_data()    };
	my $show_unknown = eval { $base_key->get_value("show_unknown")->get_data() };
	::rptMsg(sprintf("    %-20s : %s", "show_alive",   $show_alive   // "(not set)"));
	::rptMsg(sprintf("    %-20s : %s", "show_dead",    $show_dead    // "(not set)"));
	::rptMsg(sprintf("    %-20s : %s", "show_unknown", $show_unknown // "(not set)"));
	::rptMsg("");

	# -----------------------------------------------------------------------
	# Section 2: State subkey
	# -----------------------------------------------------------------------
	my $state_key;
	unless ($state_key = $base_key->get_subkey("State")) {
		::rptMsg("$base_path\\State not found.");
		return;
	}

	::rptMsg("=" x 72);
	::rptMsg("ADVANCED IP SCANNER - STATE KEY");
	::rptMsg("=" x 72);
	::rptMsg("Key  : $base_path\\State");
	::rptMsg("MTime: ".::getDateFromEpoch($state_key->get_timestamp())."Z");
	::rptMsg("");

	# Last active tab
	my $last_tab = eval { $state_key->get_value("LastActiveTab")->get_data() };
	if (defined $last_tab) {
		my $tab_name = ($last_tab == 0) ? "Results (0)" : "Favorites ($last_tab)";
		::rptMsg(sprintf("  %-22s : %s", "Last Active Tab", $tab_name));
	}

	# Last range used
	my $last_range = eval { $state_key->get_value("LastRangeUsed")->get_data() };
	::rptMsg(sprintf("  %-22s : %s",
		"Last Range Used",
		$last_range // "(not set -- no scan performed yet)"));
	::rptMsg("  " . " " x 22 . "   NOTE: created only after the first scan is executed.");
	::rptMsg("");

	# IpRangesMruList
	my $ip_mru_raw = eval { $state_key->get_value("IpRangesMruList")->get_data() };
	if ($ip_mru_raw) {
		::rptMsg("  IP Ranges MRU List (all subnets ever scanned):");
		::rptMsg("  Format: [scan_count]-[unknown_field] [ip_range]");
		::rptMsg("  " . "-" x 60);
		my @entries = _parse_mru_list($ip_mru_raw);
		if (@entries) {
			foreach my $e (@entries) {
				::rptMsg(sprintf("    Scans: %-4s  Range: %s", $e->{count}, $e->{value}));
			}
		} else {
			::rptMsg("    (empty)");
		}
		::rptMsg("");
	} else {
		::rptMsg("  IpRangesMruList : (not set)");
		::rptMsg("");
	}

	# SearchMruList
	my $search_mru_raw = eval { $state_key->get_value("SearchMruList")->get_data() };
	if ($search_mru_raw && length($search_mru_raw) > 0) {
		::rptMsg("  Search MRU List (individual IP addresses searched via GUI):");
		::rptMsg("  Format: [count]-[unknown_field] [ip_address]");
		::rptMsg("  " . "-" x 60);
		my @entries = _parse_mru_list($search_mru_raw);
		if (@entries) {
			foreach my $e (@entries) {
				::rptMsg(sprintf("    Count: %-4s  IP: %s", $e->{count}, $e->{value}));
			}
		} else {
			::rptMsg("    (empty)");
		}
	} else {
		::rptMsg("  SearchMruList   : (empty -- no individual IP searches recorded)");
	}
	::rptMsg("");

	# Miscellaneous state values
	::rptMsg("  Miscellaneous State Values:");
	my $lock_toolbars = eval { $state_key->get_value("lock_toolbars")->get_data() };
	::rptMsg(sprintf("    %-20s : %s", "lock_toolbars", $lock_toolbars // "(not set)"));
	my $col_size_init = eval { $state_key->get_value("results_col_size_init")->get_data() };
	::rptMsg(sprintf("    %-20s : %s", "results_col_size_init", $col_size_init // "(not set)"));
	::rptMsg("");

	# -----------------------------------------------------------------------
	# Section 3: CheckUpdates subkey
	# -----------------------------------------------------------------------
	my $updates_key;
	if ($updates_key = $state_key->get_subkey("CheckUpdates")) {
		::rptMsg("=" x 72);
		::rptMsg("ADVANCED IP SCANNER - CHECK UPDATES KEY");
		::rptMsg("=" x 72);
		::rptMsg("Key  : $base_path\\State\\CheckUpdates");
		::rptMsg("MTime: ".::getDateFromEpoch($updates_key->get_timestamp())."Z");
		::rptMsg("");

		my $last_check_raw = eval { $updates_key->get_value("LastCheck")->get_data() };
		if ($last_check_raw) {
			my $decoded = _decode_qt_datetime($last_check_raw);
			::rptMsg(sprintf("  %-22s : %s", "Last Update Check", $decoded));
			::rptMsg("  " . " " x 22 . "   (Qt \@DateTime format: JD + msecs-since-midnight, UTC)");
		} else {
			::rptMsg(sprintf("  %-22s : (not set)", "Last Update Check"));
		}

		my $upd_version = eval { $updates_key->get_value("Version")->get_data() };
		::rptMsg(sprintf("  %-22s : %s", "Update Version", $upd_version // "(empty)"));

		my $upd_level = eval { $updates_key->get_value("Level")->get_data() };
		::rptMsg(sprintf("  %-22s : %s", "Update Level", defined $upd_level ? $upd_level : "(not set)"));
		::rptMsg("");
	}

	# -----------------------------------------------------------------------
	# Section 4: Investigator notes
	# -----------------------------------------------------------------------
	::rptMsg("=" x 72);
	::rptMsg("INVESTIGATOR NOTES");
	::rptMsg("=" x 72);
	::rptMsg("  * Both the installer and portable versions of AIS create identical");
	::rptMsg("    registry artefacts -- the presence of these keys does NOT confirm");
	::rptMsg("    an installed copy.");
	::rptMsg("  * locale_timestamp is set once at first launch and never updated;");
	::rptMsg("    it provides a reliable lower bound on first execution time.");
	::rptMsg("  * IpRangesMruList is written to the registry only on application");
	::rptMsg("    close; it is buffered in memory during a running session.");
	::rptMsg("  * The scan-frequency counter (first digit of the MRU prefix) shows");
	::rptMsg("    how many times each subnet was scanned.");
	::rptMsg("  * Locale values such as 'fa_ir' (Farsi/Iran), 'ru_ru' (Russian),");
	::rptMsg("    'zh_cn' (Simplified Chinese) may indicate operator origin.");
	::rptMsg("  * MITRE ATT&CK: T1046 (Network Service Scanning), T1595 (Active Scanning).");
	::rptMsg("  * Threat actors known to use AIS: Conti, DarkSide/UNC2465, Egregor,");
	::rptMsg("    Hades/EvilCorp, REvil, Ryuk/UNC1878, UNC2447, UNC Iranian actor, Dharma.");
	::rptMsg("");
}

1;
