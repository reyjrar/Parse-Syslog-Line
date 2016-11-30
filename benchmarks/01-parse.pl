#!perl

use strict;
use warnings;
use Benchmark qw/timethese cmpthese/;
use Const::Fast;
use Parse::Syslog::Line;

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
);

my $last = '';
my @copy = ();
my $stub = sub {
    my ($test) = @_;
    @copy = @msgs unless @copy and $last ne $test;
    $last=$test;
    parse_syslog_line(shift @copy);
};
my $results = timethese(50_000, {
    'Defaults' => sub {
        $stub->('Defaults');
    },
    'Defaults w/normalize' => sub {
        local $Parse::Syslog::Line::NormalizeToUTC  = 1;
        $stub->('Defaults w/normalize');
    },
    'Epoch Only' => sub {
        local $Parse::Syslog::Line::DateTimeCreate  = 0;
        local $Parse::Syslog::Line::EpochCreate     = 1;
        $stub->('Epoch Only');
    },
    'Ignore Timezones' => sub {
        local $Parse::Syslog::Line::DateTimeCreate  = 0;
        local $Parse::Syslog::Line::IgnoreTimeZones = 1;
        $stub->('Ignore Timezones');
    },
    'Minimalistic Data' => sub {
        local $Parse::Syslog::Line::DateParsing     = 0;
        local $Parse::Syslog::Line::PruneRaw        = 1;
        local $Parse::Syslog::Line::PruneEmpty      = 1;
        $stub->('Minimalistic Data');
    },
    'No Date Parsing' => sub {
        local $Parse::Syslog::Line::DateParsing     = 0;
        $stub->('No Date Parsing');
    },
});

print "\n";
cmpthese($results);
print "\nGood logfiles which have UTC offsets (like Cisco) run waaaay faster:\n";

const my @utc_syslogs => (
    q|2015-01-01T11:09:36+02:00 hostname.company.tld : $year Jan  1 11:09:36.290 CET: %ETHPORT-5-IF_DOWN_CFG_CHANGE: Interface Ethernet121/1/1 is down(Config change)|,
    q|2015-09-30T06:26:06.779373-05:00 my-host my-script.pl: {"lunchTime":1443612366.442}|,
    q|2015-09-30T06:26:06.779373Z my-host my-script.pl: {"lunchTime":1443612366.442}|,
);

@copy = @utc_syslogs;
my $utc_stub = sub {
    my ($test) = @_;
    @copy = @utc_syslogs unless @copy and $test ne $last;
    $last = $test;
    parse_syslog_line( shift @copy );
};
my $results_pure = timethese(50_000, {
    'Pure UTC log' => sub {
        local $Parse::Syslog::Line::NormalizeToUTC  = 1;
        local $Parse::Syslog::Line::DateTimeCreate  = 0;
        local $Parse::Syslog::Line::EpochCreate     = 0;
        local $Parse::Syslog::Line::IgnoreTimezones = 0;

        $utc_stub->('Pure UTC log');
    },

    'Defaults' => sub {
        local $Parse::Syslog::Line::NormalizeToUTC  = 0;
        local $Parse::Syslog::Line::DateTimeCreate  = 1;
        local $Parse::Syslog::Line::EpochCreate     = 0;
        local $Parse::Syslog::Line::IgnoreTimezones = 0;

        $utc_stub->('Defaults');
    },

    'Defaults w/normalize' => sub {
        local $Parse::Syslog::Line::NormalizeToUTC  = 1;
        local $Parse::Syslog::Line::DateTimeCreate  = 1;
        local $Parse::Syslog::Line::EpochCreate     = 0;
        local $Parse::Syslog::Line::IgnoreTimezones = 0;

        $utc_stub->('Defaults w/Normalize');
    },
    'No Date Parsing' => sub {
        local $Parse::Syslog::Line::DateParsing     = 0;
        $utc_stub->('No Date Parsing');
    },
});

print "\n";
cmpthese($results_pure);
print "\n";

print "Done.\n";
