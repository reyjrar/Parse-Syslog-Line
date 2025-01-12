package Parse::Syslog::Context::OpenSSH;
# ABSTRACT: Parse sshd logs into structured data

use Const::Fast;
use Moo;
use namespace::autoclean;
with qw(
    Parse::Syslog::Role::Plugin
);

# VERSION

=head1 SYNOPSIS

Parse sshd logs into structured data

=for Pod::Coverage sample_messages

=cut

sub sample_messages {
    my @msgs = split /\r?\n/, <<EOF;
Jul 26 15:47:32 ether sshd[30700]: Accepted password for canuck from 2.82.66.219 port 54085 ssh2
Jul 26 15:47:32 ether sshd[30700]: pam_unix(sshd:session): session opened for user canuck by (uid=0)
Jul 26 15:50:14 ether sshd[4291]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=43.229.53.60  user=root
Jul 26 15:50:16 ether sshd[4291]: Failed password for root from 43.229.53.60 port 57806 ssh2
Jul 26 15:50:18 ether sshd[4291]: Failed password for root from 43.229.53.60 port 57806 ssh2
Jul 26 15:50:21 ether sshd[4291]: Failed password for root from 43.229.53.60 port 57806 ssh2
Jul 26 15:50:21 ether sshd[4292]: Disconnecting: Too many authentication failures for root
Jul 26 15:50:21 ether sshd[4291]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=43.229.53.60  user=root
Jul 26 15:50:22 ether sshd[4663]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=43.229.53.60  user=root
Jul 26 15:50:21 ether sshd[4291]: Invalid user trudy from 43.229.53.60
EOF
    return @msgs;
}

=method contextualize_message

Parses an sshd log and extracts the relevant details

    action => authentication/..
    status => succes/failure/invalid
    type   => keyboard/password/public key
    user   => user in question
    proto  => sshv2 / sshv1

And

    src_ip and src_port

=cut

const my %RE => (
    extract_details => qr/(?:Accepted|Failed) (\S+) for (\S+) from (\S+) port (\S+) (\S+)/,
    IPv4            => qr/\d{1,3}(?:\.\d{1,3}){3}/,
);
const my %F => (
    extract_details => [qw(type user src_ip src_port proto)],
);
const my %SDATA => qw(
    user  user
);

sub process {
    my ($self,$log,$ctx) = @_;

    return unless $log->{program_name} eq 'sshd';

    my $str = $log->{content};

    $ctx->{status} = $str =~ /Accepted/ ? 'success'
                   : $str =~ /Failed/   ? 'failure'
                   : undef;
    if( defined $ctx->{status} ) {
        $ctx->{action} = 'authentication';
        if( my @data = ($str =~ /(?>$RE{extract_details})/o) ) {
            @{ $ctx}{@{ $F{extract_details} }} = @data;
        }
    }
    elsif( $str =~ /Invalid/ ) {
        $ctx->{status} = 'invalid';
        @{ $ctx }{qw(user src_ip)} = ($str =~ /Invalid user (\S+) from (\S+)/);
    }
    else {
        delete $ctx->{status};
    }
    if( exists $log->{SDATA} ) {
        foreach my $k (keys %SDATA) {
            $ctx->{$SDATA{$k}} = $log->{sdata}{$k} if exists $log->{sdata}{$k};
        }
        if( exists $log->{SDATA}{rhost} ) {
            my $k = $log->{SDATA}{rhost} =~ /^$RE{IPv4}$/o ? 'src_ip' : 'src_host';
            $ctx->{$k} = $log->{SDATA}{rhost};
        }
    }
}

=head1 SEE ALSO

L<Parse::Syslog::Contextualize>, L<Parse::Syslog::Role::Plugin>

=cut

1;
