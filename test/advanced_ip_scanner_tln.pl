#-----------------------------------------------------------
# advanced_ip_scanner_tln.pl
#
# Extracts forensic artefacts left by Advanced IP Scanner (AIS / Famatech)
# from NTUSER.DAT and outputs them in TLN (Timeline) format.
#
# Change history
#   20260503 - created
#
# References
#   https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
#
#-----------------------------------------------------------
package advanced_ip_scanner_tln;
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
	return "Extracts execution, locale, and scan history for Advanced IP Scanner in TLN format.";
}

sub getRefs {
	my %refs = (
		"Hunt & Hackett - Advanced IP Scanner: the preferred scanner in the A(P)T toolbox" =>
			"https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox",
	);
	return %refs;
}

# ---------------------------------------------------------------------------
# _decode_locale_timestamp
#   Converts a Unix epoch in milliseconds to "YYYY-MM-DD HH:MM:SS UTC"
# ---------------------------------------------------------------------------
sub _decode_locale_timestamp {
	my $ts_ms = shift;
	return "" unless ($ts_ms && $ts_ms =~ /^\d+$/);

	my $epoch_s = int($ts_ms / 1000);
	my $date_str = ::getDateFromEpoch($epoch_s);
	return "$date_str UTC";
}

# ---------------------------------------------------------------------------
# pluginmain
# ---------------------------------------------------------------------------
sub pluginmain {
	my $class = shift;
	my $hive  = shift;

	# ::logMsg("Launching advanced_ip_scanner_tln v.".$VERSION);
	my $reg      = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

	my $base_path = "Software\\Famatech\\advanced_ip_scanner";
	my $base_key;

	if ($base_key = $root_key->get_subkey($base_path)) {
		
		my $lw = $base_key->get_timestamp();
		my @out_parts;

		# State key (for Last Range Used)
		my $state_key = $base_key->get_subkey("State");
		if ($state_key) {
			my $last_range = eval { $state_key->get_value("LastRangeUsed")->get_data() };
			if ($last_range) {
				push @out_parts, "Last Range Used : $last_range";
			}
		}

		# Locale
		my $locale = eval { $base_key->get_value("locale")->get_data() };
		if ($locale) {
			push @out_parts, "Locale: $locale";
		}

		# First Execution
		my $locale_ts = eval { $base_key->get_value("locale_timestamp")->get_data() };
		if ($locale_ts) {
			my $decoded_ts = _decode_locale_timestamp($locale_ts);
			if ($decoded_ts) {
				push @out_parts, "First Execution: $decoded_ts";
			}
		}

		if (@out_parts) {
			my $msg = join("; ", @out_parts);
			::rptMsg($lw."|REG|||[Program Execution] Advanced IP Scanner - $msg");
		}
	}
}

1;
