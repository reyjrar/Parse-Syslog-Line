#!perl

use Test::More;

use Data::Dumper;
use DateTime;

my $dt = DateTime->now();
my $year = $dt->year;

BEGIN {
	use_ok( 'Parse::Syslog::Line' );
}
$Parse::Syslog::Line::EpochCreate = 1;

my %msgs = (
	'Snort Message Parse'    => q|<11>Jan  1 00:00:00 mainfw snort[32640]: [1:1893:4] SNMP missing community string attempt [Classification: Misc Attack] [Priority: 2]: {UDP} 1.2.3.4:23210 -> 5.6.7.8:161|,
	'IP as Hostname'         => q|<11>Jan  1 00:00:00 11.22.33.44 dhcpd: DHCPINFORM from 172.16.2.137 via vlan3|,
	'Without Preamble'       => q|Jan  1 00:00:00 11.22.33.44 dhcpd: DHCPINFORM from 172.16.2.137 via vlan3|,
	'Dotted Hostname'        => q|<11>Jan  1 00:00:00 dev.example.com dhcpd: DHCPINFORM from 172.16.2.137 via vlan3|,
	'Syslog reset'           => q|Jan  1 00:00:00 example syslogd 1.2.3: restart (remote reception).|,
        'FreeBSD'                => q|<78>Oct 24 08:15:00 /usr/sbin/cron[73991]: (root) CMD (/usr/libexec/atrun)|,
    'Cisco ASA'              => q|<163>Jun 7 18:39:00 hostname.domain.tld %ASA-3-313001: Denied ICMP type=5, code=1 from 1.2.3.4 on interface inside|,
    'Cisco ASA Alt'          => q|<161>Jun 7 18:39:00 hostname : %ASA-3-313001: Denied ICMP type=5, code=1 from 1.2.3.4 on interface inside|,
    'Cisco NX-OS'            => q|2013-08-09T11:09:36+02:00 hostname.company.tld : 2013 Aug  9 11:09:36.290 CET: %ETHPORT-5-IF_DOWN_CFG_CHANGE: Interface Ethernet121/1/1 is down(Config change)|,
    'Cisco Catalyst'         => q|<188>Aug 13 00:10:02 10.43.0.10 1813056: Aug 13 00:15:02: %C4K_EBM-4-HOSTFLAPPING: Host 00:1B:21:4B:7B:5D in vlan 1 is flapping between port Gi6/37 and port Gi6/38|,
    'Cisco NTP No Sync'      => q|<187>Aug 21 14:58:58 fqdn.tld 6951: .Aug 21 14:58:57: %LINK-3-UPDOWN: Interface BRI0:1, changed state to down|,
    'Cisco NTP Unconfigured' => q|<189>Aug 22 12:22:26 1.2.3.4 5971: *Apr 29 02:54:25: %SYS-5-CONFIG_I: Configured from console by vty0 (10.100.0.68)|,
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
 'FreeBSD' => {
          'priority' => 'info',
          'time' => '08:15:00',
          'date' => qq{$year-10-24},
          'content' => '(root) CMD (/usr/libexec/atrun)',
          'facility' => 'cron',
          'domain' => undef,
          'program_sub' => undef,
          'host_raw' => undef,
          'program_raw' => '/usr/sbin/cron[73991]',
          'datetime_raw' => 'Oct 24 08:15:00',
          'date_raw' => 'Oct 24 08:15:00',
          'message_raw' => '<78>Oct 24 08:15:00 /usr/sbin/cron[73991]: (root) CMD (/usr/libexec/atrun)',
          'priority_int' => 6,
          'preamble' => 78,
          'date_str' => qq{$year-10-24 08:15:00},
          'datetime_str' => qq{$year-10-24 08:15:00},
          'epoch' => 1382602500,
          'program_pid' => '73991',
          'facility_int' => 72,
          'program_name' => '/usr/sbin/cron',
          'message' => '/usr/sbin/cron[73991]: (root) CMD (/usr/libexec/atrun)',
          'host' => undef,
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
           'ntp' => 'ok',
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
           'ntp' => 'ok',
    },
    'Cisco Catalyst' => {
           'ntp' => 'ok',
            message_raw => q|<188>Aug 13 00:10:02 10.43.0.10 1813056: Aug 13 00:15:02: %C4K_EBM-4-HOSTFLAPPING: Host 00:1B:21:4B:7B:5D in vlan 1 is flapping between port Gi6/37 and port Gi6/38|,
           'priority' => 'warn',
           'priority_int' => 4,
           'time' => '00:10:02',
           'date' => '2013-08-13',
           'content' =>'Host 00:1B:21:4B:7B:5D in vlan 1 is flapping between port Gi6/37 and port Gi6/38',
           'facility' => 'local7',
           'facility_int' => 184,
           'domain' => undef,
           'program_sub' => undef,
           'host_raw' => '10.43.0.10',
           'program_raw' => '%C4K_EBM-4-HOSTFLAPPING',
           'date_raw' => 'Aug 13 00:10:02',
           'datetime_raw' => 'Aug 13 00:10:02',
           'date_str' => '2013-08-13 00:10:02',
           'datetime_str' => '2013-08-13 00:10:02',
           'epoch' => 1376352602,
           'preamble' => 188,
           'program_pid' => undef,
           'program_name' => '%C4K_EBM-4-HOSTFLAPPING',
           'message' => '%C4K_EBM-4-HOSTFLAPPING: Host 00:1B:21:4B:7B:5D in vlan 1 is flapping between port Gi6/37 and port Gi6/38',
           'host' => '10.43.0.10',
           'ntp' => 'ok',
    },
    'Cisco NTP Unconfigured' => {
           'priority' => 'notice',
           'date' => '2013-08-22',
           'time' => '12:22:26',
           'content' => 'Configured from console by vty0 (10.100.0.68)',
           'facility' => 'local7',
           'domain' => undef,
           'program_sub' => undef,
           'host_raw' => '1.2.3.4',
           'program_raw' => '%SYS-5-CONFIG_I',
           'datetime_raw' => 'Aug 22 12:22:26',
           'ntp' => 'not configured',
           'date_str' => '2013-08-22 12:22:26',
           'message_raw' => '<189>Aug 22 12:22:26 1.2.3.4 5971: *Apr 29 02:54:25: %SYS-5-CONFIG_I: Configured from console by vty0 (10.100.0.68)',
           'priority_int' => 5,
           'epoch' => 1377174146,
           'preamble' => '189',
           'datetime_str' => '2013-08-22 12:22:26',
           'program_pid' => undef,
           'facility_int' => 184,
           'program_name' => '%SYS-5-CONFIG_I',
           'message' => '%SYS-5-CONFIG_I: Configured from console by vty0 (10.100.0.68)',
           'host' => '1.2.3.4',
           'date_raw' => 'Aug 22 12:22:26'
    },
    'Cisco NTP No Sync' => {
           'priority' => 'err',
           'date' => '2013-08-21',
           'time' => '14:58:58',
           'content' => 'Interface BRI0:1, changed state to down',
           'facility' => 'local7',
           'domain' => 'tld',
           'program_sub' => undef,
           'host_raw' => 'fqdn.tld',
           'program_raw' => '%LINK-3-UPDOWN',
           'datetime_raw' => 'Aug 21 14:58:58',
           'ntp' => 'out of sync',
           'date_str' => '2013-08-21 14:58:58',
           'message_raw' => '<187>Aug 21 14:58:58 fqdn.tld 6951: .Aug 21 14:58:57: %LINK-3-UPDOWN: Interface BRI0:1, changed state to down',
           'priority_int' => 3,
           'epoch' => 1377097138,
           'preamble' => '187',
           'datetime_str' => '2013-08-21 14:58:58',
           'program_pid' => undef,
           'facility_int' => 184,
           'program_name' => '%LINK-3-UPDOWN',
           'message' => '%LINK-3-UPDOWN: Interface BRI0:1, changed state to down',
           'host' => 'fqdn',
           'date_raw' => 'Aug 21 14:58:58'
    },
);

#
# Remove DateTimeObject because it's large.
foreach my $set (qw(stable devel)) {
    local $Parse::Syslog::Line::RegexSet = $set;
    foreach my $name (keys %msgs) {
        my $msg = parse_syslog_line($msgs{$name});
        delete $msg->{datetime_obj};
        if ( !exists $resps{$name} ) {
            diag( Dumper $msg );
        }
        is_deeply( $msg, $resps{$name}, "$name ($set)" ) || diag(Dumper $msg);
    }
}

# Disable Program extraction
do {
    local $Parse::Syslog::Line::ExtractProgram = 0;
    foreach my $name (keys %msgs) {
        my $msg = parse_syslog_line($msgs{$name});
        my %expected = %{ $resps{$name} };
        delete $msg->{datetime_obj};
        $expected{content} = $expected{program_raw} . ': ' . $expected{content};
        $expected{$_} = undef for qw(program_raw program_name program_sub program_pid);
        is_deeply( $msg, \%expected, "$name (no extract program)" ) || diag(Dumper $msg);
    }
};


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
