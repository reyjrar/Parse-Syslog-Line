#!perl

use Test::More tests => 5;

use Data::Dumper;
use DateTime;

my $dt = DateTime->now();
my $year = $dt->year;

BEGIN {
	use_ok( 'Parse::Syslog::Line' );
}

my %msgs = (
	'Snort Message Parse' => q|<11>Mar  1 11:44:36 mainfw snort[32640]: [1:1893:4] SNMP missing community string attempt [Classification: Misc Attack] [Priority: 2]: {UDP} 1.2.3.4:23210 -> 5.6.7.8:161|,
	'IP as Hostname' => q|<11>Mar 23 17:40:50 11.22.33.44 dhcpd: DHCPINFORM from 172.16.2.137 via vlan3|,
	'Without Preamble' => q|Mar 23 17:40:50 11.22.33.44 dhcpd: DHCPINFORM from 172.16.2.137 via vlan3|,
	'Dotted Hostname' => q|<11>Mar 23 17:40:50 dev.example.com dhcpd: DHCPINFORM from 172.16.2.137 via vlan3|,
);

my %resps = (
  'Snort Message Parse' => {
          'priority' => 'err',
          'time' => '11:44:36',
          'date' => qq{$year-03-01},
          'content' => '[1:1893:4] SNMP missing community string attempt [Classification: Misc Attack] [Priority: 2]: {UDP} 1.2.3.4:23210 -> 5.6.7.8:161',
          'facility' => 'user',
          'domain' => undef,
          'program_sub' => undef,
          'host_raw' => 'mainfw',
          'program_raw' => 'snort[32640]',
          'datetime_raw' => 'Mar  1 11:44:36',
          'message_raw' => '<11>Mar  1 11:44:36 mainfw snort[32640]: [1:1893:4] SNMP missing community string attempt [Classification: Misc Attack] [Priority: 2]: {UDP} 1.2.3.4:23210 -> 5.6.7.8:161',
          'priority_int' => 3,
          'preamble' => '11',
          'datetime_str' => qq{$year-03-01 11:44:36},
          'program_pid' => '32640',
          'facility_int' => 8,
          'program_name' => 'snort',
          'message' => 'snort[32640]: [1:1893:4] SNMP missing community string attempt [Classification: Misc Attack] [Priority: 2]: {UDP} 1.2.3.4:23210 -> 5.6.7.8:161',
          'host' => 'mainfw'
        },
 'IP as Hostname' => {
          'priority' => 'err',
          'time' => '17:40:50',
          'date' => qq{$year-03-23},
          'content' => 'DHCPINFORM from 172.16.2.137 via vlan3',
          'facility' => 'user',
          'domain' => undef,
          'program_sub' => undef,
          'host_raw' => '11.22.33.44',
          'program_raw' => 'dhcpd',
          'datetime_raw' => 'Mar 23 17:40:50',
          'message_raw' => '<11>Mar 23 17:40:50 11.22.33.44 dhcpd: DHCPINFORM from 172.16.2.137 via vlan3',
          'priority_int' => 3,
          'preamble' => '11',
          'datetime_str' => qq{$year-03-23 17:40:50},
          'program_pid' => undef,
          'facility_int' => 8,
          'program_name' => 'dhcpd',
          'message' => 'dhcpd: DHCPINFORM from 172.16.2.137 via vlan3',
          'host' => '11.22.33.44'
        },
 'Without Preamble' => {
          'priority' => undef,
          'time' => '17:40:50',
          'date' => qq{$year-03-23},
          'content' => 'DHCPINFORM from 172.16.2.137 via vlan3',
          'facility' => undef,
          'domain' => undef,
          'program_sub' => undef,
          'host_raw' => '11.22.33.44',
          'program_raw' => 'dhcpd',
          'datetime_raw' => 'Mar 23 17:40:50',
          'message_raw' => 'Mar 23 17:40:50 11.22.33.44 dhcpd: DHCPINFORM from 172.16.2.137 via vlan3',
          'priority_int' => undef,
          'preamble' => undef,
          'datetime_str' => qq{$year-03-23 17:40:50},
          'program_pid' => undef,
          'facility_int' => undef,
          'program_name' => 'dhcpd',
          'message' => 'dhcpd: DHCPINFORM from 172.16.2.137 via vlan3',
          'host' => '11.22.33.44'
        },
 'Dotted Hostname' => {
          'priority' => 'err',
          'time' => '17:40:50',
          'date' => qq{$year-03-23},
          'content' => 'DHCPINFORM from 172.16.2.137 via vlan3',
          'facility' => 'user',
          'domain' => 'example.com',
          'program_sub' => undef,
          'host_raw' => 'dev.example.com',
          'program_raw' => 'dhcpd',
          'datetime_raw' => 'Mar 23 17:40:50',
          'message_raw' => '<11>Mar 23 17:40:50 dev.example.com dhcpd: DHCPINFORM from 172.16.2.137 via vlan3',
          'priority_int' => 3,
          'preamble' => '11',
          'datetime_str' => qq{$year-03-23 17:40:50},
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
