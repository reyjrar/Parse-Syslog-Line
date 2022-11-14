#!perl
# PODNAME: parse-syslog-line.pl
# ABSTRACT: Parse a syslog message and display the structured data
use strict;
use warnings;

use Data::Printer;
use Getopt::Long::Descriptive;
use Pod::Usage;
use JSON::MaybeXS;
use Parse::Syslog::Line qw( parse_syslog_line );
use YAML;

my $enc;
my %formats = (
    print => sub { p($_[0]) },
    json  => sub {
        $enc ||= JSON->new->utf8->canonical;
        printf "%s\n", $enc->encode($_[0]);
    },
    pretty  => sub {
        $enc ||= JSON->new->utf8->canonical->pretty;
        print $enc->encode($_[0]);
    },
    yaml => sub {
        print YAML::Dump($_[0]);
    },
);
my ($opt,$usage) = describe_options("%c %o",
    ['Output Format'],
    ['format' => 'hidden', {
        one_of => [
            [ print  => 'Format with Data::Printer' ],
            [ json   => 'Format as JSON, minified' ],
            [ pretty => 'Format as JSON, pretty' ],
            [ yaml   => 'Format as YAML' ],
        ],
        default => 'print',
    }],
    [],
    ['Field Control'],
    ['disable-rfc-sdata|S', "Disables the built-in RFC5424-ish structured data extraction"],
    ['strict-rfc-sdata|D',  "Require strict adherence to RFC5424 for structured data extraction"],
    ['sdata|s',  'Enable all SDATA detection (JSON and K/V pairs)'],
    ['empty|e',  'Display fields with undef or blank string', ],
    ['raw|r',    'Display the raw fields in the hash.',],
    ['all|a', 'Display all fields.', { implies => [qw(raw empty)] }],
    [],
    ['help',   'Display this help', { shortcircuit => 1 }],
    ['manual', 'Display the manual', { shortcircuit => 1 }],
);
if( $opt->help ) {
    print $usage->text;
    exit 0;
}
pod2usage(-verbose => 2, -exitval => 0 ) if $opt->manual;

=head1 SYNOPSIS

Use this utility to parse syslog lines to arbitrary formats.

    tail -1 /var/log/messages | parse-syslog-line.pl

For help, see:

    parse-syslog-line.pl --help

=head1 EXAMPLES

Use C<parse-syslog-line.pl> as a way to do things with L<jq|https://stedolan.github.io/jq/>:

    tail /var/log/messages | parse-syslog-line.pl --json |jq '.program_name'

Attempt to extract all structured data in the log:

    tail /var/log/messages | parse-syslog-line.pl --sdata --json |jq '{ program: .program_name, sdata: .SDATA }'

See all the keys available,

    tail /var/log/messages | parse-syslog-line.pl --all

Output Pretty JSON:

    tail -1 /var/log/messages | parse-syslog-line.pl --pretty

Output prettier JSON:

    tail -1 /var/log/messages | parse-syslog-line.pl --json | jq '.'

Output as YAML:

    tail -1 /var/log/messages | parse-syslog-line.pl --yaml

=cut

# Configure
$Parse::Syslog::Line::PruneEmpty = !$opt->empty;
$Parse::Syslog::Line::PruneRaw   = !$opt->raw;
$Parse::Syslog::Line::AutoDetectJSON = $Parse::Syslog::Line::AutoDetectKeyValues = $opt->sdata;
$Parse::Syslog::Line::RFC5424StructuredData = !$opt->disable_rfc_sdata;
$Parse::Syslog::Line::RFC5424StructuredDataStrict = $opt->strict_rfc_sdata;

while(<>) {
    my $msg = parse_syslog_line($_);
    $formats{$opt->format}->( $msg );
}
