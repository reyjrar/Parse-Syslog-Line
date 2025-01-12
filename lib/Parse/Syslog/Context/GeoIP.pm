package Parse::Syslog::Context::GeoIP;
# ABSTRACT: Apply MaxMind GeoIP Data to events

use Const::Fast;
use GeoIP2::Database::Reader;
use Moo;
use Types::Standard qw(Any Bool Str);

use namespace::autoclean;
with qw(
    Parse::Syslog::Role::Plugin
);

# VERSION

=head1 SYNOPSIS

Use this module to tag geo location data to events with matching
field names.  You'll probably need to configure the C<geo_db> attribute.

=attr priority

Defaults to 1000, run last.

=cut

sub _build_priority { 1000 }

=attr geo_db

The file location for the GeoIP version 2 databases, defaults to
'/usr/share/GeoIP/GeoLite2-City.mmdb'.  Set in the config:

    ---
    contexts:
      configs:
        GeoIP:
          geo_db: '/var/lib/geoip/GeoIP2-Full.mmdb'

=cut

has 'geo_db' => (
    is      => 'ro',
    isa     => Str,
    default => '/usr/share/GeoIP/GeoLite2-City.mmdb',
);

=attr geo_lookup

This is an instance of a L<GeoIP2::Database::Reader> used to lookup
GeoIP data for an IP

=cut

has 'geo_lookup' => (
    is      => 'ro',
    isa     => Any,
    lazy    => 1,
    builder => '_build_geo_lookup',
);
sub _build_geo_lookup {
    my ($self) = @_;

    my $g;
    eval {
        $g = GeoIP2::Database::Reader->new(
            file => $self->geo_db,
            locales => [ 'en' ],
        );
        1;
    } or do {
        my $err = $@;
        warn sprintf "Failed loading GeoIP Database '%s' with error: %s",
            ( $self->geo_db || 'unspecified' ),
            ( $err || 'unknown error');
    };
    return $g;
}

=attr warnings

Should warnings about this context failing initialization be displayed.

Defaults to false so you won't get spew when the C<geo_db> is missing.

=cut

has 'warnings' => (
    is      => 'rw',
    isa     => Bool,
    default => 0,
);

=for Pod::Coverage sample_messages

=cut

sub sample_messages {
    my @msgs = split /\r?\n/, <<EOF;
EOF
    return @msgs;
}

=method process

Inspects the L<eris::log> context for any fields ending in '(.*)_ip'.  If found,
a new key "${1}_geoip" is created to contain a HashRef with the following data:

    city, country, continent, location, traits, postal_code

The only special elements being, location which is "latitude,longitude" and traits, which
is an array containing the following possible tags: anonymous, proxy, and/or satellite.

=cut

sub process {
    my ($self,$log,$ctx) = @_;

    my $geo = $self->geo_lookup;
    return unless $geo;

    my %add = ();
    foreach my $f ( keys %{ $ctx } ) {
        next unless $f =~ /^(.*)_ip$/;
        my $add_key = $1 . "_geoip";
        my %geo = ();
        eval {
            my $city = $self->geo_lookup->city( ip => $ctx->{$f} );
            $geo{city}  = $city->city->name;
            $geo{country}  = $city->country->iso_code;
            $geo{continent}  = $city->continent->code;
            my $loc = $city->location();
            $geo{location} = join(',', $loc->latitude, $loc->longitude);
            my @traits = ();
            my $traits = $city->traits;
            if( $traits->is_anonymous_proxy ) {
                push @traits, qw(anonymous proxy);
            }
            elsif( $traits->is_legitimate_proxy ) {
                push @traits, 'proxy';
            }
            elsif( $traits->is_satellite_provider ) {
                push @traits, 'satellite';
            }
            $geo{traits} = \@traits if @traits;
            my $pc = $city->postal->code;
            $geo{postal_code} = $pc if $pc;
        } or do {
            my $err = $@;
            warn sprintf("Geo lookup failed on %s: %s", $ctx->{$f}, $err) if $self->warnings;
        };
        $ctx->{$add_key} = \%geo if keys %geo;
    }
}

=head1 SEE ALSO

L<Parse::Syslog::Contextualize>, L<Parse::Syslog::Role::Plugin>, L<GeoIP2::Database::Reader>

=cut

1;
