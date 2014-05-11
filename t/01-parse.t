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
        'FreeBSD'                => q|<78>Jan  1 08:15:00 /usr/sbin/cron[73991]: (root) CMD (/usr/libexec/atrun)|,
    'Cisco ASA'              => q|<163>Jan 1 18:39:00 hostname.domain.tld %ASA-3-313001: Denied ICMP type=5, code=1 from 1.2.3.4 on interface inside|,
    'Cisco ASA Alt'          => q|<161>Jan 1 18:39:00 hostname : %ASA-3-313001: Denied ICMP type=5, code=1 from 1.2.3.4 on interface inside|,
    'Cisco NX-OS'            => qq|$year-01-01T11:09:36+02:00 hostname.company.tld : $year Jan  1 11:09:36.290 CET: %ETHPORT-5-IF_DOWN_CFG_CHANGE: Interface Ethernet121/1/1 is down(Config change)|,
    'Cisco Catalyst'         => q|<188>Jan 1 00:10:02 10.43.0.10 1813056: Jan 1 00:15:02: %C4K_EBM-4-HOSTFLAPPING: Host 00:1B:21:4B:7B:5D in vlan 1 is flapping between port Gi6/37 and port Gi6/38|,
    'Cisco NTP No Sync'      => q|<187>Jan 1 14:58:58 fqdn.tld 6951: .Jan 1 14:58:57: %LINK-3-UPDOWN: Interface BRI0:1, changed state to down|,
    'Cisco NTP Unconfigured' => q|<189>Jan 1 12:22:26 1.2.3.4 5971: *Jan 1 02:54:25: %SYS-5-CONFIG_I: Configured from console by vty0 (10.100.0.68)|,
    'Cisco Date Insanity'    => q|<189>May 8 19:12:19 router.company.tld 11815005: May 8 2014 19:12:18.454 CET: %CRYPTO-5-IPSEC_SETUP_FAILURE: IPSEC SETUP FAILED for local:1.2.3.4 local_id:1.2.3.4 remote:4.5.6.7 remote_id:4.5.6.7 IKE profile:foo fvrf:None fail_reason:IPSec Proposal failure fail_class_cnt:14|,
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
          'program_pid' => undef,
          'facility_int' => undef,
          'program_name' => 'syslogd',
          'message' => 'syslogd 1.2.3: restart (remote reception).',
          'host' => 'example'
        },
 'FreeBSD' => {
          'priority' => 'info',
          'time' => '08:15:00',
          'date' => qq{$year-01-01},
          'content' => '(root) CMD (/usr/libexec/atrun)',
          'facility' => 'cron',
          'domain' => undef,
          'program_sub' => undef,
          'host_raw' => undef,
          'program_raw' => '/usr/sbin/cron[73991]',
          'datetime_raw' => 'Jan  1 08:15:00',
          'date_raw' => 'Jan  1 08:15:00',
          'message_raw' => '<78>Jan  1 08:15:00 /usr/sbin/cron[73991]: (root) CMD (/usr/libexec/atrun)',
          'priority_int' => 6,
          'preamble' => 78,
          'date_str' => qq{$year-01-01 08:15:00},
          'datetime_str' => qq{$year-01-01 08:15:00},
          'program_pid' => '73991',
          'facility_int' => 72,
          'program_name' => '/usr/sbin/cron',
          'message' => '/usr/sbin/cron[73991]: (root) CMD (/usr/libexec/atrun)',
          'host' => undef,
 },
 'Cisco ASA' => {
           'priority' => 'err',
           'time' => '18:39:00',
           'date' => qq{$year-01-01},
           'content' => 'Denied ICMP type=5, code=1 from 1.2.3.4 on interface inside',
           'facility' => 'local4',
           'domain' => 'domain.tld',
           'program_sub' => undef,
           'host_raw' => 'hostname.domain.tld',
           'program_raw' => '%ASA-3-313001',
           'datetime_raw' => 'Jan 1 18:39:00',
           'date_str' => qq{$year-01-01 18:39:00},
           'message_raw' => '<163>Jan 1 18:39:00 hostname.domain.tld %ASA-3-313001: Denied ICMP type=5, code=1 from 1.2.3.4 on interface inside',
           'priority_int' => 3,
           'preamble' => '163',
           'datetime_str' => qq{$year-01-01 18:39:00},
           'program_pid' => undef,
           'program_name' => '%ASA-3-313001',
           'facility_int' => 160,
           'message' => '%ASA-3-313001: Denied ICMP type=5, code=1 from 1.2.3.4 on interface inside',
           'host' => 'hostname',
           'date_raw' => 'Jan 1 18:39:00'
        },
 'Cisco ASA Alt' => {
           'priority' => 'alert',
           'time' => '18:39:00',
           'date' => qq{$year-01-01},
           'content' => 'Denied ICMP type=5, code=1 from 1.2.3.4 on interface inside',
           'facility' => 'local4',
           'domain' => undef,
           'program_sub' => undef,
           'host_raw' => 'hostname',
           'program_raw' => '%ASA-3-313001',
           'datetime_raw' => 'Jan 1 18:39:00',
           'date_str' => qq{$year-01-01 18:39:00},
           'message_raw' => '<161>Jan 1 18:39:00 hostname : %ASA-3-313001: Denied ICMP type=5, code=1 from 1.2.3.4 on interface inside',
           'priority_int' => 1,
           'preamble' => '161',
           'datetime_str' => qq{$year-01-01 18:39:00},
           'program_pid' => undef,
           'program_name' => '%ASA-3-313001',
           'facility_int' => 160,
           'message' => '%ASA-3-313001: Denied ICMP type=5, code=1 from 1.2.3.4 on interface inside',
           'host' => 'hostname',
           'date_raw' => 'Jan 1 18:39:00'
        },
  'Cisco NX-OS' => {
           'ntp' => 'ok',
            message_raw => qq|$year-01-01T11:09:36+02:00 hostname.company.tld : $year Jan  1 11:09:36.290 CET: %ETHPORT-5-IF_DOWN_CFG_CHANGE: Interface Ethernet121/1/1 is down(Config change)|,
           'priority' => undef,
           'time' => '11:09:36',
           'date' => qq{$year-01-01},
           'content' => 'Interface Ethernet121/1/1 is down(Config change)',
           'facility' => undef,
           'domain' => 'company.tld',
           'program_sub' => undef,
           'host_raw' => 'hostname.company.tld',
           'program_raw' => '%ETHPORT-5-IF_DOWN_CFG_CHANGE',
           'date_raw' => qq{$year-01-01T11:09:36+02:00},
           'datetime_raw' => qq{$year-01-01T11:09:36+02:00},
           'date_str' => qq{$year-01-01 11:09:36},
           'datetime_str' => qq{$year-01-01 11:09:36},
           'priority_int' => undef,
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
            message_raw => q|<188>Jan 1 00:10:02 10.43.0.10 1813056: Jan 1 00:15:02: %C4K_EBM-4-HOSTFLAPPING: Host 00:1B:21:4B:7B:5D in vlan 1 is flapping between port Gi6/37 and port Gi6/38|,
           'priority' => 'warn',
           'priority_int' => 4,
           'time' => '00:10:02',
           'date' => qq{$year-01-01},
           'content' =>'Host 00:1B:21:4B:7B:5D in vlan 1 is flapping between port Gi6/37 and port Gi6/38',
           'facility' => 'local7',
           'facility_int' => 184,
           'domain' => undef,
           'program_sub' => undef,
           'host_raw' => '10.43.0.10',
           'program_raw' => '%C4K_EBM-4-HOSTFLAPPING',
           'date_raw' => 'Jan 1 00:10:02',
           'datetime_raw' => 'Jan 1 00:10:02',
           'date_str' => qq{$year-01-01 00:10:02},
           'datetime_str' => qq{$year-01-01 00:10:02},
           'preamble' => 188,
           'program_pid' => undef,
           'program_name' => '%C4K_EBM-4-HOSTFLAPPING',
           'message' => '%C4K_EBM-4-HOSTFLAPPING: Host 00:1B:21:4B:7B:5D in vlan 1 is flapping between port Gi6/37 and port Gi6/38',
           'host' => '10.43.0.10',
           'ntp' => 'ok',
    },
    'Cisco NTP Unconfigured' => {
           'priority' => 'notice',
           'date' => qq{$year-01-01},
           'time' => '12:22:26',
           'content' => 'Configured from console by vty0 (10.100.0.68)',
           'facility' => 'local7',
           'domain' => undef,
           'program_sub' => undef,
           'host_raw' => '1.2.3.4',
           'program_raw' => '%SYS-5-CONFIG_I',
           'datetime_raw' => 'Jan 1 12:22:26',
           'ntp' => 'not configured',
           'date_str' => qq{$year-01-01 12:22:26},
           'message_raw' => '<189>Jan 1 12:22:26 1.2.3.4 5971: *Jan 1 02:54:25: %SYS-5-CONFIG_I: Configured from console by vty0 (10.100.0.68)',
           'priority_int' => 5,
           'preamble' => '189',
           'datetime_str' => qq{$year-01-01 12:22:26},
           'program_pid' => undef,
           'facility_int' => 184,
           'program_name' => '%SYS-5-CONFIG_I',
           'message' => '%SYS-5-CONFIG_I: Configured from console by vty0 (10.100.0.68)',
           'host' => '1.2.3.4',
           'date_raw' => 'Jan 1 12:22:26'
    },
    'Cisco NTP No Sync' => {
           'priority' => 'err',
           'date' => qq{$year-01-01},
           'time' => '14:58:58',
           'content' => 'Interface BRI0:1, changed state to down',
           'facility' => 'local7',
           'domain' => 'tld',
           'program_sub' => undef,
           'host_raw' => 'fqdn.tld',
           'program_raw' => '%LINK-3-UPDOWN',
           'datetime_raw' => 'Jan 1 14:58:58',
           'ntp' => 'out of sync',
           'date_str' => qq{$year-01-01 14:58:58},
           'datetime_str' => qq{$year-01-01 14:58:58},
           'message_raw' => '<187>Jan 1 14:58:58 fqdn.tld 6951: .Jan 1 14:58:57: %LINK-3-UPDOWN: Interface BRI0:1, changed state to down',
           'priority_int' => 3,
           'preamble' => '187',
           'program_pid' => undef,
           'facility_int' => 184,
           'program_name' => '%LINK-3-UPDOWN',
           'message' => '%LINK-3-UPDOWN: Interface BRI0:1, changed state to down',
           'host' => 'fqdn',
           'date_raw' => 'Jan 1 14:58:58'
    },
    'Cisco Date Insanity' => {
           'priority' => 'notice',
           'date' => qq{$year-05-08},
           'time' => '19:12:19',
           'content' => 'IPSEC SETUP FAILED for local:1.2.3.4 local_id:1.2.3.4 remote:4.5.6.7 remote_id:4.5.6.7 IKE profile:foo fvrf:None fail_reason:IPSec Proposal failure fail_class_cnt:14',
           'facility' => 'local7',
           'domain' => 'company.tld',
           'program_sub' => undef,
           'program_sub' => undef,
           'host_raw' => 'router.company.tld',
           'program_raw' => '%CRYPTO-5-IPSEC_SETUP_FAILURE',
           'datetime_raw' => 'May 8 19:12:19',
           'ntp' => 'ok',
           'date_str' => qq{$year-05-08 19:12:19},
           'message_raw' => '<189>May 8 19:12:19 router.company.tld 11815005: May 8 2014 19:12:18.454 CET: %CRYPTO-5-IPSEC_SETUP_FAILURE: IPSEC SETUP FAILED for local:1.2.3.4 local_id:1.2.3.4 remote:4.5.6.7 remote_id:4.5.6.7 IKE profile:foo fvrf:None fail_reason:IPSec Proposal failure fail_class_cnt:14',
           'priority_int' => 5,
           'preamble' => 189,
           'datetime_str' => qq{$year-05-08 19:12:19},
           'program_pid' => undef,
           'program_name' => '%CRYPTO-5-IPSEC_SETUP_FAILURE',
           'facility_int' => 184,
           'message' => '%CRYPTO-5-IPSEC_SETUP_FAILURE: IPSEC SETUP FAILED for local:1.2.3.4 local_id:1.2.3.4 remote:4.5.6.7 remote_id:4.5.6.7 IKE profile:foo fvrf:None fail_reason:IPSec Proposal failure fail_class_cnt:14',
           'host' => 'router',
           'date_raw' => 'May 8 19:12:19'
    },
);

my @_delete = qw(datetime_obj epoch);
#
# Remove DateTimeObject because it's large.
foreach my $set (qw(stable devel)) {
    local $Parse::Syslog::Line::RegexSet = $set;
    foreach my $name (keys %msgs) {
        my $msg = parse_syslog_line($msgs{$name});
        delete $msg->{$_} for @_delete;
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
        delete $msg->{$_} for @_delete;
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
