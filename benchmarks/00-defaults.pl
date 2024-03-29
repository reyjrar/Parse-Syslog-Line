#!perl

use strict;
use warnings;
use Dumbbench;
use Const::Fast;
use Parse::Syslog::Line;

# Disable warnings
$ENV{PARSE_SYSLOG_LINE_QUIET} = 1;

const my @msgs => (
    q|<11>Jan  1 00:00:00 mainfw snort[32640]: [1:1893:4] SNMP missing community string attempt [Classification: Misc Attack] [Priority: 2]: {UDP} 1.2.3.4:23210 -> 5.6.7.8:161|,
    q|<11>Jan  1 00:00:00 11.22.33.44 dhcpd: DHCPINFORM from 172.16.2.137 via vlan3|,
    q|Jan  1 00:00:00 11.22.33.44 dhcpd: DHCPINFORM from 172.16.2.137 via vlan3|,
    q|<11>Jan  1 00:00:00 dev.example.com dhcpd: DHCPINFORM from 172.16.2.137 via vlan3|,
    q|Jan  1 00:00:00 example syslogd 1.2.3: restart (remote reception).|,
    q|<163>Jun 7 18:39:00 hostname.domain.tld %ASA-3-313001: Denied ICMP type=5, code=1 from 1.2.3.4 on interface inside|,
    q|<161>Jun 7 18:39:00 hostname : %ASA-3-313001: Denied ICMP type=5, code=1 from 1.2.3.4 on interface inside|,
    q|2013-08-09T11:09:36+02:00 hostname.company.tld : 2013 Aug  9 11:09:36.290 CET: %ETHPORT-5-IF_DOWN_CFG_CHANGE: Interface Ethernet121/1/1 is down(Config change)|,
    q|<134>Jan 1 11:28:13 filer-201.example.com [filer-201: scsitarget.ispfct.targetReset:notice]: FCP Target 0c: Target was Reset by the Initiator at Port Id: 0x11000 (WWPN 5001438021e071ec)|,
    q|2016-11-19T20:50:01.749659+01:00 janus CROND[14400]: (root) CMD (/usr/lib64/sa/sa1 1 1)|,
    q|2015 Nov 13 13:40:01 ether rsyslogd-2177: imuxsock begins to drop messages from pid 17840 due to rate-limit|,
);

my $last = '';
my @copy = ();
my $stub = sub {
    my ($test) = @_;
    @copy = @msgs unless @copy and $last ne $test;
    $last=$test;
    parse_syslog_line(shift @copy);
};

my $bench = Dumbbench->new(
    target_rel_precision => 0.005,
    initial_runs         => 1000,
);

$bench->add_instances(
    Dumbbench::Instance::PerlSub->new( code => sub { $stub->('Defaults') } ),
);

$bench->run();
$bench->report();
