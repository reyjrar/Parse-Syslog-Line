#!perl

use Test::More tests => 9;

use Data::Dumper;
use DateTime;

my $dt = DateTime->now();
my $year = $dt->year;

BEGIN {
	use_ok( 'Parse::Syslog::Line' );
}

my %msgs = (
	'Snort Message Parse' => q|<11>Jan  1 00:00:00 mainfw snort[32640]: [1:1893:4] SNMP missing community string attempt [Classification: Misc Attack] [Priority: 2]: {UDP} 1.2.3.4:23210 -> 5.6.7.8:161|,
	'IP as Hostname' => q|<11>Jan  1 00:00:00 11.22.33.44 dhcpd: DHCPINFORM from 172.16.2.137 via vlan3|,
	'Without Preamble' => q|Jan  1 00:00:00 11.22.33.44 dhcpd: DHCPINFORM from 172.16.2.137 via vlan3|,
	'Dotted Hostname' => q|<11>Jan  1 00:00:00 dev.example.com dhcpd: DHCPINFORM from 172.16.2.137 via vlan3|,
);

@dtfields = qw/time datetime_obj epoch date_str/;

my %resps = (
  'Snort Message Parse' => {
          'priority' => 'err',
          'time' => '00:00:00',
          'date' => qq{$year-01-01},
          'content' => '[1:1893:4] SNMP missing community string attempt [Classification: Misc Attack] [Priority: 2]: {UDP} 1.2.3.4:23210 -> 5.6.7.8:161',
          'facility' => 'user',
          'domain' => undef,
          'program_sub' => undef,
          'host_raw' => 'mainfw',
          'program_raw' => 'snort[32640]',
          'date_raw' => 'Jan  1 00:00:00',
          'message_raw' => '<11>Jan  1 00:00:00 mainfw snort[32640]: [1:1893:4] SNMP missing community string attempt [Classification: Misc Attack] [Priority: 2]: {UDP} 1.2.3.4:23210 -> 5.6.7.8:161',
          'priority_int' => 3,
          'preamble' => '11',
          'date_str' => qq{$year-01-01 00:00:00},
          'epoch' => 1356998400,
          'program_pid' => '32640',
          'facility_int' => 8,
          'program_name' => 'snort',
          'message' => 'snort[32640]: [1:1893:4] SNMP missing community string attempt [Classification: Misc Attack] [Priority: 2]: {UDP} 1.2.3.4:23210 -> 5.6.7.8:161',
          'host' => 'mainfw'
        },
 'IP as Hostname' => {
          'priority' => 'err',
          'time' => '00:00:00',
          'date' => qq{$year-01-01},
          'content' => 'DHCPINFORM from 172.16.2.137 via vlan3',
          'facility' => 'user',
          'domain' => undef,
          'program_sub' => undef,
          'host_raw' => '11.22.33.44',
          'program_raw' => 'dhcpd',
          'date_raw' => 'Jan  1 00:00:00',
          'message_raw' => '<11>Jan  1 00:00:00 11.22.33.44 dhcpd: DHCPINFORM from 172.16.2.137 via vlan3',
          'priority_int' => 3,
          'preamble' => '11',
          'date_str' => qq{$year-01-01 00:00:00},
          'epoch' => 1356998400,
          'program_pid' => undef,
          'facility_int' => 8,
          'program_name' => 'dhcpd',
          'message' => 'dhcpd: DHCPINFORM from 172.16.2.137 via vlan3',
          'host' => '11.22.33.44'
        },
 'Without Preamble' => {
          'priority' => undef,
          'time' => '00:00:00',
          'date' => qq{$year-01-01},
          'content' => 'DHCPINFORM from 172.16.2.137 via vlan3',
          'facility' => undef,
          'domain' => undef,
          'program_sub' => undef,
          'host_raw' => '11.22.33.44',
          'program_raw' => 'dhcpd',
          'date_raw' => 'Jan  1 00:00:00',
          'message_raw' => 'Jan  1 00:00:00 11.22.33.44 dhcpd: DHCPINFORM from 172.16.2.137 via vlan3',
          'priority_int' => undef,
          'preamble' => undef,
          'date_str' => qq{$year-01-01 00:00:00},
          'epoch' => 1356998400,
          'program_pid' => undef,
          'facility_int' => undef,
          'program_name' => 'dhcpd',
          'message' => 'dhcpd: DHCPINFORM from 172.16.2.137 via vlan3',
          'host' => '11.22.33.44'
        },
 'Dotted Hostname' => {
          'priority' => 'err',
          'time' => '00:00:00',
          'date' => qq{$year-01-01},
          'content' => 'DHCPINFORM from 172.16.2.137 via vlan3',
          'facility' => 'user',
          'domain' => 'example.com',
          'program_sub' => undef,
          'host_raw' => 'dev.example.com',
          'program_raw' => 'dhcpd',
          'date_raw' => 'Jan  1 00:00:00',
          'message_raw' => '<11>Jan  1 00:00:00 dev.example.com dhcpd: DHCPINFORM from 172.16.2.137 via vlan3',
          'priority_int' => 3,
          'preamble' => '11',
          'date_str' => qq{$year-01-01 00:00:00},
          'epoch' => 1356998400,
          'program_pid' => undef,
          'facility_int' => 8,
          'program_name' => 'dhcpd',
          'message' => 'dhcpd: DHCPINFORM from 172.16.2.137 via vlan3',
          'host' => 'dev'
        },
);

#
# Remove DateTimeObject because it's large.
foreach my $name (keys %msgs) {
	my $msg = parse_syslog_line($msgs{$name});
	delete $msg->{datetime_obj};
	is_deeply( $msg, $resps{$name}, $name );
}

sub parse_func {
    my ($date) = @_;
    $date //= " ";
    my $modified = "[$date]";

    return $modified, undef, undef, undef;
}

$Parse::Syslog::Line::DateTimeCreate = 0;
$Parse::Syslog::Line::FmtDate = \&parse_func;

foreach my $name (keys %msgs) {
    foreach my $part (@dtfields) {
        $resps{$name}{$part} = undef if exists $resps{$name}{$part};
    }
    $resps{$name}{date} = "[" . $resps{$name}{date_raw} . "]";
    my $msg = parse_syslog_line($msgs{$name});
	delete $msg->{datetime_obj};
    is_deeply( $msg, $resps{$name}, "FmtDate " . $name );
}

