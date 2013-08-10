#!perl

use Test::More;

use Data::Dumper;
use DateTime;

my $dt = DateTime->now();
my $year = $dt->year;

BEGIN {
	use_ok( 'Parse::Syslog::Line' );
}

my %msgs = (
	'Snort Message Parse' => q|<11>Jan  1 00:00:00 mainfw snort[32640]: [1:1893:4] SNMP missing community string attempt [Classification: Misc Attack] [Priority: 2]: {UDP} 1.2.3.4:23210 -> 5.6.7.8:161|,
	'IP as Hostname'      => q|<11>Jan  1 00:00:00 11.22.33.44 dhcpd: DHCPINFORM from 172.16.2.137 via vlan3|,
	'Without Preamble'    => q|Jan  1 00:00:00 11.22.33.44 dhcpd: DHCPINFORM from 172.16.2.137 via vlan3|,
	'Dotted Hostname'     => q|<11>Jan  1 00:00:00 dev.example.com dhcpd: DHCPINFORM from 172.16.2.137 via vlan3|,
	'Syslog reset'        => q|Jan  1 00:00:00 example syslogd 1.2.3: restart (remote reception).|,
    'Cisco ASA'           => q|<163>Jun 7 18:39:00 hostname.domain.tld %ASA-3-313001: Denied ICMP type=5, code=1 from 1.2.3.4 on interface inside|,
    'Cisco ASA Alt'       => q|<161>Jun 7 18:39:00 hostname : %ASA-3-313001: Denied ICMP type=5, code=1 from 1.2.3.4 on interface inside|,
    'Cisco NX-OS'         => q|2013-08-09T11:09:36+02:00 hostname.company.tld : 2013 Aug  9 11:09:36.290 CET: %ETHPORT-5-IF_DOWN_CFG_CHANGE: Interface Ethernet121/1/1 is down(Config change)|,
);

@dtfields = qw/time datetime_obj epoch date_str datetime_str/;

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
          'datetime_raw' => 'Jan  1 00:00:00',
          'date_raw' => 'Jan  1 00:00:00',
          'message_raw' => '<11>Jan  1 00:00:00 mainfw snort[32640]: [1:1893:4] SNMP missing community string attempt [Classification: Misc Attack] [Priority: 2]: {UDP} 1.2.3.4:23210 -> 5.6.7.8:161',
          'priority_int' => 3,
          'preamble' => '11',
          'datetime_str' => qq{$year-01-01 00:00:00},
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
          'datetime_raw' => 'Jan  1 00:00:00',
          'date_raw' => 'Jan  1 00:00:00',
          'message_raw' => '<11>Jan  1 00:00:00 11.22.33.44 dhcpd: DHCPINFORM from 172.16.2.137 via vlan3',
          'priority_int' => 3,
          'preamble' => '11',
          'date_str' => qq{$year-01-01 00:00:00},
          'datetime_str' => qq{$year-01-01 00:00:00},
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
          'datetime_raw' => 'Jan  1 00:00:00',
          'date_raw' => 'Jan  1 00:00:00',
          'message_raw' => 'Jan  1 00:00:00 11.22.33.44 dhcpd: DHCPINFORM from 172.16.2.137 via vlan3',
          'priority_int' => undef,
          'preamble' => undef,
          'date_str' => qq{$year-01-01 00:00:00},
          'datetime_str' => qq{$year-01-01 00:00:00},
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
          'datetime_raw' => 'Jan  1 00:00:00',
          'date_raw' => 'Jan  1 00:00:00',
          'message_raw' => '<11>Jan  1 00:00:00 dev.example.com dhcpd: DHCPINFORM from 172.16.2.137 via vlan3',
          'priority_int' => 3,
          'preamble' => '11',
          'date_str' => qq{$year-01-01 00:00:00},
          'datetime_str' => qq{$year-01-01 00:00:00},
          'epoch' => 1356998400,
          'program_pid' => undef,
          'facility_int' => 8,
          'program_name' => 'dhcpd',
          'message' => 'dhcpd: DHCPINFORM from 172.16.2.137 via vlan3',
          'host' => 'dev'
        },
 'Syslog reset' => {
          'priority' => undef,
          'time' => '00:00:00',
          'date' => qq{$year-01-01},
          'content' => 'restart (remote reception).',
          'facility' => undef,
          'domain' => undef,
          'program_sub' => undef,
          'host_raw' => 'example',
          'program_raw' => 'syslogd 1.2.3',
          'datetime_raw' => 'Jan  1 00:00:00',
          'date_raw' => 'Jan  1 00:00:00',
          'message_raw' => 'Jan  1 00:00:00 example syslogd 1.2.3: restart (remote reception).',
          'priority_int' => undef,
          'preamble' => undef,
          'date_str' => qq{$year-01-01 00:00:00},
          'datetime_str' => qq{$year-01-01 00:00:00},
          'epoch' => 1356998400,
          'program_pid' => undef,
          'facility_int' => undef,
          'program_name' => 'syslogd',
          'message' => 'syslogd 1.2.3: restart (remote reception).',
          'host' => 'example'
        },
 'Cisco ASA' => {
           'priority' => 'err',
           'time' => '18:39:00',
           'date' => '2013-06-07',
           'content' => 'Denied ICMP type=5, code=1 from 1.2.3.4 on interface inside',
           'facility' => 'local4',
           'domain' => 'domain.tld',
           'program_sub' => undef,
           'host_raw' => 'hostname.domain.tld',
           'program_raw' => '%ASA-3-313001',
           'datetime_raw' => 'Jun 7 18:39:00',
           'date_str' => '2013-06-07 18:39:00',
           'message_raw' => '<163>Jun 7 18:39:00 hostname.domain.tld %ASA-3-313001: Denied ICMP type=5, code=1 from 1.2.3.4 on interface inside',
           'priority_int' => 3,
           'epoch' => 1370630340,
           'preamble' => '163',
           'datetime_str' => '2013-06-07 18:39:00',
           'program_pid' => undef,
           'program_name' => '%ASA-3-313001',
           'facility_int' => 160,
           'message' => '%ASA-3-313001: Denied ICMP type=5, code=1 from 1.2.3.4 on interface inside',
           'host' => 'hostname',
           'date_raw' => 'Jun 7 18:39:00'
        },
 'Cisco ASA Alt' => {
           'priority' => 'alert',
           'time' => '18:39:00',
           'date' => '2013-06-07',
           'content' => 'Denied ICMP type=5, code=1 from 1.2.3.4 on interface inside',
           'facility' => 'local4',
           'domain' => undef,
           'program_sub' => undef,
           'host_raw' => 'hostname',
           'program_raw' => '%ASA-3-313001',
           'datetime_raw' => 'Jun 7 18:39:00',
           'date_str' => '2013-06-07 18:39:00',
           'message_raw' => '<161>Jun 7 18:39:00 hostname : %ASA-3-313001: Denied ICMP type=5, code=1 from 1.2.3.4 on interface inside',
           'priority_int' => 1,
           'epoch' => 1370630340,
           'preamble' => '161',
           'datetime_str' => '2013-06-07 18:39:00',
           'program_pid' => undef,
           'program_name' => '%ASA-3-313001',
           'facility_int' => 160,
           'message' => '%ASA-3-313001: Denied ICMP type=5, code=1 from 1.2.3.4 on interface inside',
           'host' => 'hostname',
           'date_raw' => 'Jun 7 18:39:00'
        },
  'Cisco NX-OS' => {
            message_raw => q|2013-08-09T11:09:36+02:00 hostname.company.tld : 2013 Aug  9 11:09:36.290 CET: %ETHPORT-5-IF_DOWN_CFG_CHANGE: Interface Ethernet121/1/1 is down(Config change)|,
           'priority' => undef,
           'time' => '11:09:36',
           'date' => '2013-08-09',
           'content' => 'Interface Ethernet121/1/1 is down(Config change)',
           'facility' => undef,
           'domain' => 'company.tld',
           'program_sub' => undef,
           'host_raw' => 'hostname.company.tld',
           'program_raw' => '%ETHPORT-5-IF_DOWN_CFG_CHANGE',
           'date_raw' => '2013-08-09T11:09:36+02:00',
           'datetime_raw' => '2013-08-09T11:09:36+02:00',
           'date_str' => '2013-08-09 11:09:36',
           'datetime_str' => '2013-08-09 11:09:36',
           'priority_int' => undef,
           'epoch' => 1376039376,
           'preamble' => undef,
           'program_pid' => undef,
           'program_name' => '%ETHPORT-5-IF_DOWN_CFG_CHANGE',
           'facility_int' => undef,
           'message' => '%ETHPORT-5-IF_DOWN_CFG_CHANGE: Interface Ethernet121/1/1 is down(Config change)',
           'host' => 'hostname',
    },

);

#
# Remove DateTimeObject because it's large.
foreach my $name (keys %msgs) {
	my $msg = parse_syslog_line($msgs{$name});
	delete $msg->{datetime_obj};
    if ( !exists $resps{$name} ) {
        diag( Dumper $msg );
    }
	is_deeply( $msg, $resps{$name}, $name ) || diag(Dumper $msg);
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
        $resps{$name}{$part} = undef;
    }
    $resps{$name}{date} = "[" . $resps{$name}{datetime_raw} . "]";
    my $msg = parse_syslog_line($msgs{$name});
    is_deeply( $msg, $resps{$name}, "FmtDate " . $name );
}

done_testing();
