package Parse::Syslog::Context::Snort;
# ABSTRACT: Parses the Snort and Suricata alert logs

use Moo;
use namespace::autoclean;
with qw(
    Parse::Syslog::Role::Plugin
);

# VERSION

=head1 SYNOPSIS

This parses data in the Snort and Suricata alert logs into structured data.

=for Pod::Coverage sample_messages

=cut

sub sample_messages {
    my @msgs = split /\r?\n/, <<EOF;
Jul 26 15:50:21 ether suricata: [1:2210045:2] SURICATA STREAM Packet with invalid ack [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 5.22.134.191:15682 -> 99.46.177.250:50673
Jul 26 15:50:21 ether suricata: [1:2210046:2] SURICATA STREAM SHUTDOWN RST invalid ack [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 5.22.134.191:15682 -> 99.46.177.250:50673
Jul 26 15:50:21 ether suricata: [1:2210046:2] SURICATA STREAM SHUTDOWN RST invalid ack [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 141.226.218.88:48038 -> 99.46.177.250:50673
Jul 26 15:50:21 ether suricata: [1:2210045:2] SURICATA STREAM Packet with invalid ack [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} 141.226.218.88:48038 -> 99.46.177.250:50673
Jul 26 15:50:21 ether suricata: [1:2010935:2] ET POLICY Suspicious inbound to MSSQL port 1433 [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 183.60.48.25:12216 -> 99.46.177.250:1433
Jul 26 15:50:21 ether suricata: [1:2010935:2] ET POLICY Suspicious inbound to MSSQL port 1433 [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 208.100.26.228:50861 -> 99.46.177.250:1433
Jul 26 15:50:21 ether suricata: [1:2008581:3] ET P2P BitTorrent DHT ping request [Classification: Potential Corporate Privacy Violation] [Priority: 1] {UDP} 99.46.177.250:29902 -> 112.157.21.174:4652
EOF
    return @msgs;
}

=method process

Extracts information from the Snort and Suricata alert logs

    name  => rule name
    class => rule classification
    pri   => rule priority
    proto => protocol

And

    src_ip src_port dst_ip dst_port

Tags messages with 'security' and 'ids'.

=cut

sub process {
    my ($self,$log,$ctx) = @_;

    return unless $log->{program_name} =~ /^(snort|suricata)/;

    my $str = $log->{content};
    $ctx->{_tags}{$_} = 1 for qw(security ids);

    if ( $str =~ /^\[(\S+)\]\s+/g ) {
        $ctx->{id} = (split /:/, $1, 3)[1];
        if ( $str =~ /\G([^\[]+)/gc ) {
            $ctx->{name} = $1;
            $ctx->{name} =~ s/\s+$//;
            if ( $str =~ /(?>\[Classification: ([^\]]+)\])/ )  {
                $ctx->{class} = $1;
            }
            if ( $str =~ /(?>\[Priority: (\d+)\])/ )  {
                $ctx->{pri} = $1;
            }
            if ( $str =~ /(?>\{(\S+)\})/ ) {
                $ctx->{proto_app} = $1;
            }
            if( $str =~ /(?>(\S+):(\d+) -> (\S+):(\d+))/ ) {
                @{ $ctx }{qw(src_ip src_port dst_ip dst_port)} = ($1,$2,$3,$4);
            }
        }
    }
}

=head1 SEE ALSO

L<Parse::Syslog::Contextualize>, L<Parse::Syslog::Role::Plugin>

=cut

1;
