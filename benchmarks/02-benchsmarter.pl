#!perl

use strict;
use warnings;
use Const::Fast;
use Dumbbench;
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

my $bench = Dumbbench->new(
    target_rel_precision => 0.005,
    initial_runs         => 1_000,
);

$bench->add_instances(
    Dumbbench::Instance::PerlSub->new(
        name => 'Recommended',
        code => sub {
            local $Parse::Syslog::Line::DateTimeCreate  = 0;
            local $Parse::Syslog::Line::EpochCreate     = 1;
            local $Parse::Syslog::Line::PruneEmpty      = 1;
            $stub->('Recommended');
        },
    ),
    Dumbbench::Instance::PerlSub->new(
        name => 'DateTimeCreate',
        code => sub {
            local $Parse::Syslog::Line::DateTimeCreate  = 1;
            $stub->('DateTimeCreate');
        },
    ),
    Dumbbench::Instance::PerlSub->new(
        name => 'Defaults',
        code => sub { $stub->('Defaults') },
    ),
    Dumbbench::Instance::PerlSub->new(
        name => 'RFC5424Strict',
        code => sub {
            local $Parse::Syslog::Line::RFC5424StructuredDataStrict = 1;
            $stub->('RFC5424Strict')
        },
    ),
    Dumbbench::Instance::PerlSub->new(
        name => 'NormalizeToUTC',
        code => sub {
            local $Parse::Syslog::Line::NormalizeToUTC  = 1;
            $stub->('NormalizeToUTC');
        },
    ),
    Dumbbench::Instance::PerlSub->new(
        name => 'PruneEmpty',
        code => sub {
            local $Parse::Syslog::Line::PruneEmpty      = 1;
            $stub->('PruneEmpty');
        },
    ),
    Dumbbench::Instance::PerlSub->new(
        name => 'No Dates, Pruned',
        code => sub {
            local $Parse::Syslog::Line::DateParsing     = 0;
            local $Parse::Syslog::Line::PruneRaw        = 1;
            local $Parse::Syslog::Line::PruneEmpty      = 1;
            $stub->('No Dates, Pruned');
        },
    ),
    Dumbbench::Instance::PerlSub->new(
        name => 'No Dates',
        code => sub {
            local $Parse::Syslog::Line::DateParsing     = 0;
            $stub->('No Dates');
        },
    ),
);
$bench->run();
$bench->report();

print "\nGood logfiles which have UTC offsets:\n";

const my @utc_syslogs => (
    q|2015-01-01T11:09:36+02:00 hostname.company.tld : $year Jan  1 11:09:36.290 CET: %ETHPORT-5-IF_DOWN_CFG_CHANGE: Interface Ethernet121/1/1 is down(Config change)|,
    q|2015-09-30T06:26:06.779373-05:00 my-host my-script.pl: {"lunchTime":1443612366.442}|,
    q|2015-09-30T06:26:06.779373Z my-host my-script.pl: {"lunchTime":1443612366.442}|,
);

$bench = Dumbbench->new(
    target_rel_precision => 0.005,
    initial_runs         => 1_000,
);

@copy = @utc_syslogs;
my $utc_stub = sub {
    my ($test) = @_;
    @copy = @utc_syslogs unless @copy and $test ne $last;
    $last = $test;
    parse_syslog_line( shift @copy );
};
$bench->add_instances(
    Dumbbench::Instance::PerlSub->new(
        name => 'NormalizeToUTC',
        code => sub {
            local $Parse::Syslog::Line::NormalizeToUTC  = 1;
            $utc_stub->('NormalizeToUTC');
        },
    ),
    Dumbbench::Instance::PerlSub->new(
        name => 'DateTimeCreate',
        code => sub {
            local $Parse::Syslog::Line::DateTimeCreate  = 1;
            $utc_stub->('Defaults');
        },
    ),
);

$bench->run();
$bench->report();

print "Done.\n";
