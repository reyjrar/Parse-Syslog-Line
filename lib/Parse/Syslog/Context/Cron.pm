package Parse::Syslog::Context::Cron;
# ABSTRACT: Parse crond messages to structured data

use Moo;
with qw(
    Parse::Syslog::Role::Plugin
);
use namespace::autoclean;

# VERSION

=head1 SYNOPSIS

Parses the crond execution log file entries into structured data

=cut

my %PRG = map { $_ => 1 } qw(crond cron /usr/sbin/cron);

=for Pod::Coverage sample_messages

=cut

sub sample_messages {
    my @msgs = split /\r?\n/, <<'EOF';
Nov 24 01:00:01 janus CROND[30472]: (root) CMD (/usr/lib64/sa/sa1 1 1)
Nov 24 01:01:01 janus CROND[30689]: (root) CMD (run-parts /etc/cron.hourly)
Nov 24 01:01:01 janus CROND[30690]: (root) CMD (/usr/local/bin/linux_basic_performance_data.sh)
EOF
    return @msgs;
}

=method process

Parses the crond log messages specifying what was run into:

    action => 'execute'
    user   => User executing
    exe    => Full command as run by cron
    file   => Just the executeable without arguments

=cut

sub process {
    my ($self,$log,$ctx) = @_;

    return unless exists $PRG{lc $log->{program_name}};
    $ctx->{provider} = 'cron';
    my $str = $log->{content};

    if( $str =~ / CMD / ) {
        my @parts = map { s/(?:^\()|(?:\)$)//rg } split / CMD /, $str;
        $ctx->{user} = $parts[0];
        $ctx->{exe} = $parts[1];
        $ctx->{file} = (split /\s+/, $parts[1])[0];
        $ctx->{action} = 'execute';
    }
}

=head1 SEE ALSO

L<Parse::Syslog::Contextualize>, L<Parse::Syslog::Role::Plugin>

=cut

1;
