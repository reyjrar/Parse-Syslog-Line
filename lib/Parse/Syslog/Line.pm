# ABSTRACT: Simple syslog line parser

package Parse::Syslog::Line;

use warnings;
use strict;

use Exporter;
use Const::Fast;
use DateTime::Format::HTTP;
use HTTP::Date;

our $VERSION        = '2.9';

our $DateTimeCreate    = 1;
our $ExtractProgram    = 1;
our $FmtDate;
our $EpochCreate       = 0;
our $PruneRaw          = 0;
our $PruneEmpty        = 0;
our $RegexSet          = 'stable';
our @PruneFields       = ();

=head1 SYNOPSIS

I wanted a very simple log parser for network based syslog input.
Nothing existed that simply took a line and returned a hash ref all
parsed out.

    use Parse::Syslog::Line qw(parse_syslog_line);

    $Parse::Syslog::Line::DateTimeCreate = 1;

    my $href = parse_syslog_line( $msg );
    #
    # $href = {
    #       preamble        => '13',
    #       priority        => 'notice',
    #       priority_int    => 5,
    #       facility        => 'user',
    #       facility_int    => 8,
    #       date            => 'YYYY-MM-DD',
    #       time            => 'HH::MM:SS',
    #       epoch           => 1361095933,
    #       datetime_str    => 'YYYY-MM-DD HH:MM:SS',
    #       datet_str       => 'YYYY-MM-DD HH:MM:SS',
    #       datetime_obj    => new DateTime(), # If installed
    #       datetime_raw    => 'Feb 17 11:12:13'
    #       date_raw        => 'Feb 17 11:12:13'
    #       date_raw        => 'Feb 17 11:12:13'
    #       host_raw        => 'hostname',  # Hostname as it appeared in the message
    #       host            => 'hostname',  # Hostname without domain
    #       domain          => 'blah.com',  # if provided
    #       program_raw     => 'sshd(blah)[pid]',
    #       program_name    => 'sshd',
    #       program_sub     => 'pam_unix',
    #       program_pid     => 20345,
    #       content         => 'the rest of the message'
    #       message         => 'program[pid]: the rest of the message',
    #       message_raw     => 'The message as it was passed',
    #       ntp             => 'ok',           # Only set for Cisco messages
    # };
    ...

=cut

my %INT_PRIORITY = (
    'emerg'         => 0,
    'alert'         => 1,
    'crit'          => 2,
    'err'           => 3,
    'warn'          => 4,
    'notice'        => 5,
    'info'          => 6,
    'debug'         => 7,
);

my %INT_FACILITY = (
    #
    # POSIX Facilities
    'kern'          => 0 << 3,
    'user'          => 1 << 3,
    'mail'          => 2 << 3,
    'daemon'        => 3 << 3,
    'auth'          => 4 << 3,
    'syslog'        => 5 << 3,
    'lpr'           => 6 << 3,
    'news'          => 7 << 3,
    'uucp'          => 8 << 3,
    'cron'          => 9 << 3,
    'authpriv'      => 10 << 3,
    'ftp'           => 11 << 3,
    #
    # Local Reserved
    'local0'        => 16 << 3,
    'local1'        => 17 << 3,
    'local2'        => 18 << 3,
    'local3'        => 19 << 3,
    'local4'        => 20 << 3,
    'local5'        => 21 << 3,
    'local6'        => 22 << 3,
    'local7'        => 23 << 3,
    #
    # Apple Additions
    'netinfo'       => 12 << 3,
    'remoteauth'    => 13 << 3,
    'install'       => 14 << 3,
    'ras'           => 15 << 3,
    'launchd'       => 24 << 3,
);

const our %LOG_PRIORITY => (
    %INT_PRIORITY,
    reverse(%INT_PRIORITY),
);

const our %LOG_FACILITY => (
    %INT_FACILITY,
    reverse(%INT_FACILITY),
);

const our %CONV_MASK => (
    priority        => 0x07,
    facility        => 0x03f8,
);

=head1 EXPORT

Exported by default:
       parse_syslog_line( $one_line_of_syslog_message );

Optional Exports:
  :preamble
       preamble_priority
       preamble_facility

  :constants
       %LOG_FACILITY
       %LOG_PRIORITY
=cut

our @ISA = qw(Exporter);
our @EXPORT = qw(parse_syslog_line);
our @EXPORT_OK = qw(
    parse_syslog_line
    preamble_priority preamble_facility
    %LOG_FACILITY %LOG_PRIORITY
);
our @EXPORT_TAGS = (
    constants       => [ qw( %LOG_FACILITY %LOG_PRIORITY ) ],
    preamble        => [ qw(preamble_priority preamble_facility) ],
);

# Regex to Support Matches
 my %RE = (
    IPv4    => qr/(?:[0-9]{1,3}\.){3}[0-9]{1,3}/,
);

# Regex to Extract Data
my %REGEXP = (
    stable => {
        preamble        => qr/^\<(\d+)\>/,
        date            => qr/^([a-zA-Z]{3}\s+[0-9]+\s+[0-9]{1,2}(?:\:[0-9]{2}){1,2})/,
        date_long => qr/^
                (?:[0-9]{4}\s+)?                # Year: Because, Cisco
                ([.*])?                         # Cisco adds a * for no ntp, and a . for configured but out of sync
                [a-zA-Z]{3}\s+[0-9]+            # Date: Jan  1
                (?:\s+[0-9]{4})?                # Year: Because, Cisco
                \s+                             # Date Separator: spaces
                [0-9]{1,2}(?:\:[0-9]{2}){1,2}   # Time: HH:MM or HH:MM:SS
                (?:\.[0-9]{3})?                 # Time: .DDD ms resolution
                (?:\s+[A-Z]{3,4})?              # Timezone, ZZZ or ZZZZ
                (?:\:?)                         # Cisco adds a : after the second timestamp
        /x,
        date_iso8601    => qr/^(
                [0-9]{4}(\-[0-9]{2}){2}     # Date YYYY-MM-DD
                (\s|T)                      # Date Separator T or ' '
                [0-9]{2}(\:[0-9]{2}){1,2}   # Time HH:MM:SS
                ([+\-][0-9]{2}\:[0-9]{2})?  # UTC Offset +DD:MM
        )/x,
        host            => qr/^\s*([^:\s]+)\s+/,
        cisco_hates_you => qr/^\s*[0-9]*:\s+/,
        program_raw     => qr/^\s*([^\[][^:]+):\s*/,
        program_name    => qr/^([^\[\(\ ]+)/,
        program_sub     => qr/\(([^\)]+)\)/,
        program_pid     => qr/\[([^\]]+)\]/,
        program_netapp  => qr/\[([^\]]+)\]:\s*/,
    },
    devel => {
        preamble        => qr/^\<(\d+)\>/,
        date            => qr/^([a-zA-Z]{3}\s+[0-9]+\s+[0-9]{1,2}(?:\:[0-9]{2}){1,2})/,
        date_long => qr/^
                (?:[0-9]{4}\s+)?                # Year: Because, Cisco
                ([.*])?                         # Cisco adds a * for no ntp, and a . for configured but out of sync
                [a-zA-Z]{3}\s+[0-9]+            # Date: Jan  1
                (?:\s+[0-9]{4})?                # Year: Because, Cisco
                \s+                             # Date Separator: spaces
                [0-9]{1,2}(?:\:[0-9]{2}){1,2}   # Time: HH:MM or HH:MM:SS
                (?:\.[0-9]{3})?                 # Time: .DDD ms resolution
                (?:\s+[A-Z]{3,4})?              # Timezone, ZZZ or ZZZZ
                (?:\:?)                         # Cisco adds a : after the second timestamp
        /x,
        date_iso8601    => qr/^(
                [0-9]{4}(?:\-[0-9]{2}){2}     # Date YYYY-MM-DD
                (?:\s|T)                      # Date Separator T or ' '
                [0-9]{2}(\:[0-9]{2}){1,2}   # Time HH:MM:SS
                (?:[+\-][0-9]{2}\:[0-9]{2})?  # UTC Offset +DD:MM
        )/x,
        host            => qr/^\s*([^:\s]+)\s+/,
        cisco_hates_you => qr/^\s*[0-9]*:\s+/,
        program_raw     => qr/^\s*([^\[][^:]+):\s*/,
        program_name    => qr/^([^\[\(\ ]+)/,
        program_sub     => qr/\(([^\)]+)\)/,
        program_pid     => qr/\[([^\]]+)\]/,
        program_netapp  => qr/\[([^\]]+)\]:\s*/,
    },
);

=head1 VARIABLES

=head2 ExtractProgram

If this variable is set to 1 (the default), parse_syslog_line() will try it's
best to extract a "program" field from the input.  This is the most expensive
set of regex in the module, so if you don't need that pre-parsed, you can speed
the module up significantly by setting this variable.

Vendors who do proprietary non-sense with their syslog formats are to blame for
this setting.


Usage:

  $Parse::Syslog::Line::ExtractProgram = 0;

=head2 DateTimeCreate

If this variable is set to 1 (the default), a DateTime object will be
returned in the $m->{datetime_obj} field.  Otherwise, this will be skipped.

Usage:

  $Parse::Syslog::Line::DateTimeCreate = 0;

=head2 EpochCreate

If this variable is set to 1, the number of seconds from UNIX epoch
will be returned in the $m->{epoch} field.  If DateTimeCreate is
not set, the parser will use C<HTTP::Date> to perform the parsing

Usage:

  $Parse::Syslog::Line::EpochCreate = 1;

=head2 PruneRaw

This variable defaults to 0, set to 1 to delete all keys in the return hash ending in "_raw"

Usage:

  $Parse::Syslog::Line::PruneRaw = 1;

=head2 PruneEmpty

This variable defaults to 0, set to 1 to delete all keys in the return hash which are undefined.

Usage:

  $Parse::Syslog::Line::PruneEmpty = 1;

=head2 PruneFields

This should be an array of fields you'd like to be removed from the hash reference.

Usage:

  @Parse::Syslog::Line::PruneFields = qw(date_str date_raw facility_int priority_int);

=head2 RegexSet

Allows the use of different regex sets, the default is stable.  This is mostly a developer level
feature to allow easy benchmarking of features against previous release.

Usage:

  $Parse::Syslog::Line::RegexSet = 'devel';


=head1 FUNCTIONS

=head2 parse_syslog_line

Returns a hash reference of syslog message parsed data.

=cut

my %_empty_msg = map { $_ => undef } qw(
    preamble priority priority_int facility facility_int
    datetime_raw date_raw date time date_str datetime_str datetime_obj epoch
    host_raw host domain
    program_raw program_name program_pid program_sub
);

sub parse_syslog_line {
    my ($raw_string) = @_;

    # Verify we have a valid RegexSet
    die "Invalid RegexSet '$RegexSet', valid are: ". join(", ", sort keys %REGEXP) unless exists $REGEXP{$RegexSet};

    # Initialize everything to undef
    my %msg =  $PruneEmpty ? () : %_empty_msg;
    $msg{message_raw} = $raw_string unless $PruneRaw;

    #
    # grab the preamble:
    if( $raw_string =~ s/$REGEXP{$RegexSet}->{preamble}//o ) {
        # Cast to integer
        $msg{preamble} = int $1;

        # Extract Integers
        $msg{priority_int} = $msg{preamble} & $CONV_MASK{priority};
        $msg{facility_int} = $msg{preamble} & $CONV_MASK{facility};

        # Lookups
        $msg{priority} = $LOG_PRIORITY{ $msg{priority_int} };
        $msg{facility} = $LOG_FACILITY{ $msg{facility_int} };
    }

    #
    # Handle Date/Time
    if( $raw_string =~ s/$REGEXP{$RegexSet}->{date}//o) {
        $msg{datetime_raw} = $1;
    }
    elsif( $raw_string =~ s/$REGEXP{$RegexSet}->{date_iso8601}//o) {
        $msg{datetime_raw} = $1;
    }
    if( exists $msg{datetime_raw} && length $msg{datetime_raw} ) {
        $msg{date_raw} = $msg{datetime_raw};

        # Only parse the DatetTime if we're configured to do so
        if( $DateTimeCreate ) {
            my $dt = DateTime::Format::HTTP->parse_datetime( $msg{datetime_raw} );
            $msg{date}         = $dt->ymd('-');
            $msg{time}         = $dt->hms;
            $msg{epoch}        = $dt->epoch if $EpochCreate;
            $msg{datetime_str} = $dt->ymd('-') . ' ' . $dt->hms;
            $msg{datetime_obj} = $dt;
        }
        elsif( $FmtDate && ref $FmtDate eq 'CODE' ) {
            @msg{qw(date time epoch datetime_str)} = $FmtDate->($msg{datetime_raw});
        }
        elsif( $EpochCreate ) {
            $msg{epoch}        = HTTP::Date::str2time($msg{datetime_raw});
            $msg{datetime_str} = HTTP::Date::time2iso($msg{epoch});
        }
        $msg{date_str} = $msg{datetime_str} if exists $msg{datetime_str};
    }

    #
    # Host Information:
    if( $raw_string =~ s/$REGEXP{$RegexSet}->{host}//o ) {
        my $hostStr = $1;
        my($ip) = ($hostStr =~ /($RE{IPv4})/o);
        if( defined $ip && length $ip ) {
            $msg{host_raw} = $hostStr;
            $msg{host} = $ip;
        }
        elsif( length $hostStr ) {
            my ($host,$domain) = split /\./, $hostStr, 2;
            $msg{host_raw} = $hostStr;
            $msg{host} = $host;
            $msg{domain} = $domain;
        }
    }
    if( $raw_string =~ s/$REGEXP{$RegexSet}->{cisco_hates_you}//o ) {
        # Yes, Cisco adds a second timestamp to it's messages, because it hates you.
        if( $raw_string =~ s/$REGEXP{$RegexSet}->{date_long}//o ) {
            # Cisco encodes the status of NTP in the second datestamp, so let's pass it back
            if ( my $ntp = $1 ) {
                $msg{ntp} = $ntp eq '.' ? 'out of sync'
                          : $ntp eq '*' ? 'not configured'
                          : 'unknown';
            }
            else {
                $msg{ntp} = 'ok';
            }
        }
    }

    #
    # Parse the Program portion
    if( $ExtractProgram ) {
        if( $raw_string =~ s/$REGEXP{$RegexSet}->{program_raw}//o ) {
            my $progStr = $1;
            chomp($progStr);
            if( defined $progStr && length $progStr) {
                $msg{program_raw} = $progStr;
                if( ($msg{program_name}) = ($progStr =~ /$REGEXP{$RegexSet}->{program_name}/o) ) {
                    if (length $msg{program_name} != length $msg{program_raw} ) {
                        (($msg{program_pid}) = ($progStr =~ /$REGEXP{$RegexSet}->{program_pid}/o))
                            || (($msg{program_sub}) = ($progStr =~ /$REGEXP{$RegexSet}->{program_sub}/o))
                    }
                }
            }
        }
        elsif( $raw_string =~ s/$REGEXP{$RegexSet}->{program_netapp}//o ) {
            # Check for a [host thing.subthing:level]: tag, Thanks NetApp.
            my $subStr = $1;
            $msg{program_raw} = qq{[$subStr]};
            my $progStr = (split /\s+/, $subStr)[-1];
            my ($program,$level) = split /\:/, $progStr;
            $msg{program_name} = $program;
            if(!exists $msg{priority} && exists $LOG_PRIORITY{$level}) {
                $msg{priority} = $level;
                $msg{priority_int} = $LOG_PRIORITY{$level};
            }
            $raw_string =~ s/^[\s:]+//;
        }
    }
    else {
        $raw_string =~ s/^\s+//;
    }

    # The left overs should be the message
    $msg{content} = $raw_string;
    chomp $msg{content};
    $msg{message} = defined $msg{program_raw} ? "$msg{program_raw}: $msg{content}" : $msg{content};

    if( $PruneRaw ) {
        delete $msg{$_} for grep { $_ =~ /_raw$/ } keys %msg;
    }
    if( $PruneEmpty ) {
        delete $msg{$_} for grep { !defined $msg{$_} } keys %msg;
    }
    if( @PruneFields ) {
        no warnings;
        delete $msg{$_} for @PruneFields;
    }

    #
    # Return our hash reference!
    return \%msg;
}

=head2 preamble_priority

Takes the Integer portion of the syslog messsage and returns
a hash reference as such:

    $prioRef = {
        'preamble'  => 13
        'as_text'   => 'notice',
        'as_int'    => 5,
    };

=cut

sub preamble_priority {
    my $preamble = int shift;

    my %hash = (
        preamble => $preamble,
    );

    $hash{as_int} = $preamble & $CONV_MASK{priority};
    $hash{as_text} = $LOG_PRIORITY{ $hash{as_int} };

    return \%hash;
}

=head2 preamble_facility

Takes the Integer portion of the syslog messsage and returns
a hash reference as such:

    $facRef = {
        'preamble'  => 13
        'as_text'   => 'user',
        'as_int'    => 8,
    };

=cut

sub preamble_facility {
    my $preamble = int shift;

    my %hash = (
        preamble => $preamble,
    );

    $hash{as_int} = $preamble & $CONV_MASK{facility};
    $hash{as_text} = $LOG_FACILITY{ $hash{as_int} };

    return \%hash;

}

1; # End of Parse::Syslog::Line
__END__

=head1 DEVELOPMENT

This module is developed with Dist::Zilla.  To build from the repository, use Dist::Zilla:

    dzil authordeps |cpanm
    dzil build
    dzil test

=over 4

=item * Github Page

L<http://github.com/reyjrar/Parse-Syslog-Line>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Parse-Syslog-Line>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Parse-Syslog-Line>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Parse-Syslog-Line>

=item * Search CPAN

L<http://search.cpan.org/dist/Parse-Syslog-Line>

=back

=head1 ACKNOWLEDGEMENTS

=over 4

=item Mattia Barbon

Contribution of patch to support faster HTTP::Date routines

=item Alexander Hartmaier

Contribution of log samples for Cisco devices and testing

=item Shawn Wilson

Contribution of patch to support custom date parsing function

=back

