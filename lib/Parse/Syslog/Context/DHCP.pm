package Parse::Syslog::Context::DHCP;
# ABSTRACT: Parses dhcpd messages into structured data.

use Const::Fast;
use Moo;
with qw(
    Parse::Syslog::Role::Plugin
);
use namespace::autoclean;

# VERSION

=head1 SYNOPSIS

Parses dhcpd messages into structured data.

=for Pod::Coverage sample_messages

=cut

sub sample_messages {
    my @msgs = split /\r?\n/, <<'EOF';
Jul  4 17:06:58 10.0.1.1 dhcpd: DHCPDISCOVER from f0:f6:1c:b9:20:57 (Necktie) via igb1
Jul  4 17:06:58 10.0.1.1 dhcpd: DHCPOFFER on 10.0.1.33 to f0:f6:1c:b9:20:57 (Necktie) via igb1
Jul  4 17:06:59 10.0.1.1 dhcpd: DHCPREQUEST for 10.0.1.33 (10.0.1.1) from f0:f6:1c:b9:20:57 (Necktie) via igb1
Jul  4 17:06:59 10.0.1.1 dhcpd: DHCPACK on 10.0.1.33 to f0:f6:1c:b9:20:57 (Necktie) via igb1
EOF
    return @msgs;
}

=method process

Parses the DHCP daemon's log into structured data containing the keys:

    action   => DHCPACK/REQUEST/DISCOVER/OFFER
    dev      => Physical interface
    src      => Client ID, if specified
    src_ip   => Source IP Address
    src_mac  => Source MAC Address

Tags messages with 'inventory'

=cut

sub process {
    my ($self,$log,$ctx) = @_;

    return unless $log->{program_name} =~ /dhcpd$/;

    local $_ = $log->{content};
    if ( /^(?>(DHCPACK) on (\S+) to (\S+) (?:\(([^)]+)\) )?via (\S+))/ ) {
        @{ $ctx }{qw(action src_ip src_mac dev)} = ($1,$2,$3,$4);
    }
    elsif ( /^(?>(DHCPREQUEST) for (\S+) (?:\([^)]+\) )?from (\S+) (?:\(([^)]+)\) )?via (\S+))/ ) {
        @{ $ctx }{qw(action src_ip src_mac src dev)} = ($1,$2,$3,$4);
    }
    elsif ( /^(?>(DHCPDISCOVER) from (\S+) (?:\(([^)]+)\) )?via (\S+))/ ) {
        @{ $ctx }{qw(action src_mac src dev)} = ($1,$2,$3);
    }
    elsif ( /^(?>(DHCPOFFER) on (\S+) to (\S+) (?:\(([^)]+)\) )?via (\S+))/ ) {
        @{ $ctx }{qw(action src_ip src_mac src dev)} = ($1,$2,$3,$4,$5);
    }
    else {
        return;
    }

    $ctx->{_tags}{inventory} = 1;
}

=head1 SEE ALSO

L<Parse::Syslog::Contextualize>, L<Parse::Syslog::Role::Plugin>

=cut

1;
