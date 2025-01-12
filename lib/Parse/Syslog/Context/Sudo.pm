package Parse::Syslog::Context::Sudo;
# ABSTRACT: Parses the sudo key=value pairs into structured documents

use Const::Fast;
use Moo;
with qw(
    Parse::Syslog::Role::Plugin
);
use namespace::autoclean;

# VERSION

=head1 SYNOPSIS

Translates the sudo syslog lines containing "key=value" to structured documents.

=for Pod::Coverage sample_messages

=cut

sub sample_messages {
    my @msgs = split /\r?\n/, <<'EOF';
Sep 10 19:59:02 ether sudo:     brad : TTY=pts/5 ; PWD=/home/brad ; USER=root ; COMMAND=/bin/grep -i sudo /var/log/messages
Sep 10 19:59:05 ether sudo:     brad : TTY=pts/5 ; PWD=/home/brad ; USER=root ; COMMAND=/bin/grep -i sudo /var/log/secure
EOF
    return @msgs;
}

=method process

Transforms the sudo syslog messages into structured data.

    dev      => TTY
    exe      => COMMAND
    location => PWD
    dst_user => USER
    src_user => from the syslog header
    action   => literal string 'execute'
    file     => extracts just the executeable from the 'exe' parameter

=cut

const my %MAP => (
    TTY     => 'dev',
    COMMAND => 'exe',
    PWD     => 'location',
    USER    => 'dst_user',
);

sub process {
    my ($self,$log,$ctx) = @_;

    return unless $log->{program_name} eq 'sudo';
    my $sdata = $log->{SDATA};
    my $str   = $log->{content};

    my ($user,$variables) = split ' : ', $str, 2;
    foreach my $k (sort keys %MAP) {
        if( exists $sdata->{$k} ) {
            $ctx->{$MAP{$k}} = $sdata->{$k};
        }
    }
    if( exists $ctx->{exe} ) {
        $ctx->{file} = (split /\s+/, $ctx->{exe})[0];
        $ctx->{action} = 'execute';
    }
    $ctx->{src_user} = $user if $user;
}

=head1 SEE ALSO

L<Parse::Syslog::Contextualize>, L<Parse::Syslog::Role::Plugin>

=cut

1;
