package Parse::Syslog::Context::Yum;
# ABSTRACT: Parse the yum syslog output into structured data

use Const::Fast;
use Moo;
use namespace::autoclean;
with qw(
    Parse::Syslog::Role::Plugin
);

# VERSION

=for Pod::Coverage sample_messages

=cut

sub sample_messages {
    my @msgs = split /\r?\n/, <<EOF;
Sep  7 03:43:36 ether yum[26202]: Installed: nginx-filesystem-1.10.1-1.el6.noarch
Sep  7 03:43:36 ether yum[26202]: Installed: nginx-mod-http-geoip-1.10.1-1.el6.x86_64
Sep  7 03:43:36 ether yum[26202]: Installed: nginx-mod-mail-1.10.1-1.el6.x86_64
Sep  7 03:43:36 ether yum[26202]: Installed: nginx-mod-stream-1.10.1-1.el6.x86_64
Sep  7 03:43:36 ether yum[26202]: Installed: nginx-mod-http-image-filter-1.10.1-1.el6.x86_64
Sep  7 03:43:36 ether yum[26202]: Installed: nginx-mod-http-perl-1.10.1-1.el6.x86_64
Sep  7 03:43:36 ether yum[26202]: Updated: nginx-1.10.1-1.el6.x86_64
Sep  7 03:43:36 ether yum[26202]: Installed: nginx-mod-http-xslt-filter-1.10.1-1.el6.x86_64
Sep  7 03:43:36 ether yum[26202]: Installed: nginx-all-modules-1.10.1-1.el6.noarch
Sep  7 03:43:36 ether yum[26202]: Updated: libudev-147-2.73.el6_8.2.x86_64
Sep  7 03:43:36 ether yum[26202]: Updated: libgudev1-147-2.73.el6_8.2.x86_64
Sep  7 03:43:37 ether yum[26202]: Updated: udev-147-2.73.el6_8.2.x86_64
Sep  9 03:51:41 ether yum[12333]: Updated: puppetlabs-release-22.0-2.noarch
Sep 10 04:14:59 ether yum[22005]: Updated: perl-File-Next-1.16-1.el6.noarch
EOF
    return @msgs;
}

=method process

Extracts the package and action from the yum log into:

    action => installed/updated/removed
    file   => package name with full version

=cut

sub process {
    my ($self,$log,$ctx) = @_;

    return unless $log->{program_name} =~ /^(yum|dnf)/;

    my $str = $log->{content};
    if($str =~ /^(\S+): (\S+)/) {
        $ctx->{action} = lc $1;
        $ctx->{file} = $2;
    }
}

=head1 SEE ALSO

L<Parse::Syslog::Contextualize>, L<Parse::Syslog::Role::Plugin>

=cut

1;
