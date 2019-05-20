#!perl

use strict;
use warnings;

use FindBin;
use Data::Dumper;
use Path::Tiny qw(path);
use Test::MockTime;
use Test::More;
use YAML ();

use Parse::Syslog::Line qw/:with_timezones/;

# Avoid Issues with not being able to source timezone
set_syslog_timezone('UTC');

# this avoids HTTP::Date weirdnes with dates "in the future"
Test::MockTime::set_fixed_time("2018-12-01T00:00:00Z");

my $dataDir = path("$FindBin::Bin")->child('data');
my @TESTS = ();

$dataDir->visit(sub {
    my ($p) = @_;

    # Skip non-yaml files
    return unless $p->is_file and $p->stringify =~ /\.yaml/;

    # Load the Test Data, fatal errors will cause test failures
    eval {
        push @TESTS, YAML::LoadFile( $p->stringify );
        1;
    } or do {
        my $err = $@;
        fail(sprintf "loading YAML in %s failed: %s",
            $p->stringify,
            $err,
        );
    };
});


my @dtfields = qw/time datetime_obj epoch datetime_str/;

subtest "Basic Functionality Test" => sub {
    # There's other tests for scrutinizing the date data
    my @_delete = qw(datetime_obj epoch offset);

    foreach my $test (sort { $a->{name} cmp $b->{name} } @TESTS) {
        my $msg = parse_syslog_line($test->{string});
        delete $msg->{$_} for grep { exists $msg->{$_} } @_delete;
        delete $test->{expected}{$_} for grep { exists $test->{expected}{$_} } @_delete;
        is_deeply( $msg, $test->{expected}, $test->{name} ) || diag( Dumper $test );
    }

    # Disable Program extraction
    do {
        local $Parse::Syslog::Line::ExtractProgram = 0;
        foreach my $test (sort { $a->{name} cmp $b->{name} } @TESTS) {
            my $msg = parse_syslog_line($test->{string});
            my %expected = %{ $test->{expected} };
            delete $msg->{$_} for @_delete;
            $expected{content} = $expected{program_raw} . ': ' . $expected{content};
            $expected{$_} = undef for qw(program_raw program_name program_sub program_pid);
            is_deeply( $msg, \%expected, "$test->{name} (no extract program)" );
        }
    };
};

subtest 'Custom parser' => sub {

    sub parse_func {
        my ($date) = @_;
        $date //= " ";
        my $modified = "[$date]";

        return $modified;
    }

    local $Parse::Syslog::Line::FmtDate = \&parse_func;

    foreach my $test (sort { $a->{name} cmp $b->{name} } @TESTS) {
        my %resp = %{ $test->{expected} };
        foreach my $part (@dtfields) {
            $resp{$part} = undef;
        }
        $resp{date} = "[" . $resp{datetime_raw} . "]";
        my $msg = parse_syslog_line($test->{string});
        is_deeply( $msg, \%resp, "FmtDate " . $test->{name} );
    }
    done_testing();
};

done_testing();
