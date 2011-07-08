#!perl -T

use Test::More tests => 2;
use Data::Dumper;

my $year = 1900 + (localtime)[5];

BEGIN {
	use_ok( 'Parse::Syslog::Line' );
}


my @msgs = (
	q|<11>Jun  1 11:44:36 mainfw snort[32640]: [1:1893:4] SNMP missing community string attempt [Classification: Misc Attack] [Priority: 2]: {UDP} 1.2.3.4:23210 -> 5.6.7.8:161|,
);

my @resps = (
 {
          'priority' => 'err',
          'time' => '11:44:36',
          'date' => qq{$year-06-01},
          'content' => '[1:1893:4] SNMP missing community string attempt [Classification: Misc Attack] [Priority: 2]: {UDP} 1.2.3.4:23210 -> 5.6.7.8:161',
          'facility' => 'user',
          'domain' => undef,
          'program_sub' => undef,
          'host_raw' => 'mainfw',
          'program_raw' => 'snort[32640]',
          'datetime_raw' => 'Jun  1 11:44:36',
          'message_raw' => '<11>Jun  1 11:44:36 mainfw snort[32640]: [1:1893:4] SNMP missing community string attempt [Classification: Misc Attack] [Priority: 2]: {UDP} 1.2.3.4:23210 -> 5.6.7.8:161',
          'priority_int' => 3,
          'preamble' => '11',
          'datetime_str' => qq{$year-06-01 11:44:36},
          'program_pid' => '32640',
          'facility_int' => 8,
          'program_name' => 'snort',
          'message' => 'snort[32640]: [1:1893:4] SNMP missing community string attempt [Classification: Misc Attack] [Priority: 2]: {UDP} 1.2.3.4:23210 -> 5.6.7.8:161',
          'host' => 'mainfw'
        },

);

#
# Remove DateTimeObject because it's large.
my $msg = parse_syslog_line($msgs[0]);
delete $msg->{datetime_obj};

is_deeply( $msg, $resps[0], 'Snort Message Parse' );
