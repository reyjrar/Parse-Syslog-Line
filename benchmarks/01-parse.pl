#!perl

use strict;
use warnings;
use Benchmark qw/timethese cmpthese/;
use Const::Fast;
use Parse::Syslog::Line;

use FindBin;
use lib "$FindBin::Bin/../t/lib";
use test::Data;

# Disable warnings
$ENV{PARSE_SYSLOG_LINE_QUIET} = 1;

const my @msgs => map { $_->{string} } values %{ get_test_data() };

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
    'PruneEmpty' => sub {
        local $Parse::Syslog::Line::PruneEmpty      = 1;
        $stub->('PruneEmpty');
    },
    'NoDates' => sub {
        local $Parse::Syslog::Line::DateParsing     = 0;
        $stub->('No Dates');
    },
    'JSON' => sub {
        local $Parse::Syslog::Line::AutoDetectJSON = 1;
        $stub->('JSON');
    },
    'KV' => sub {
        local $Parse::Syslog::Line::AutoDetectKeyValues = 1;
        $stub->('KV');
    },
    'NoRFCSDATA' => sub {
        local $Parse::Syslog::Line::RFC5424StructuredData = 0;
        $stub->('NoRFCSDATA');
    },
    'StrictRFC' => sub {
        local $Parse::Syslog::Line::RFC5424StructuredDataStrict = 1;
        $stub->('StrictRFC');
    },
    'AutoSDATA' => sub {
        local $Parse::Syslog::Line::AutoDetectJSON = 1;
        local $Parse::Syslog::Line::AutoDetectKeyValues = 1;
        $stub->('AutoSDATA');
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
    'NormalizeToUTC' => sub {
        local $Parse::Syslog::Line::NormalizeToUTC  = 1;
        $utc_stub->('NormalizeToUTC');
    },
    'DateTimeCreate' => sub {
        local $Parse::Syslog::Line::DateTimeCreate  = 1;
        $utc_stub->('Defaults');
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
