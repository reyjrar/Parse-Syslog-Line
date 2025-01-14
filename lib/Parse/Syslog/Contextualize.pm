package Parse::Syslog::Contextualize;

use Moo;
use Types::Standard qw(CodeRef HashRef);
use Parse::Syslog::Line qw(parse_syslog_line);
use Storable qw(dclone);
use namespace::autoclean;

with qw(
    Parse::Syslog::Role::Pluggable
);
sub _build_namespace { 'Parse::Syslog::Context' }

has 'labels' => (
    is => 'ro',
    isa => HashRef,
    default => sub { {} },
);

# Document
# --------
# timestamp: YYYY-MM-DDTHH:MM:SS
# labels:
#   x: y
# message: "string"
# tags: [ 'a', 'b' ]
#
# host:
#   name: ...
#   domain: ...
#
# container:
#   image:
#     name: ..
#     tag: ..
#   name: ..
#   labels: {}
#
# event:
#   action: ...
#   category:
#   duration: ..
#   id: ..
#   provider: ..
#   size: ..
#   type: ..
#   outcome: ..
#   severity: ..
#   status: ..
#
# rule:
#   id:
#   name:
#   category:
#
# src:
#   ip: 1.2.3.4
#   geo:
#     country: US
#     city: Baltimore
#     location: lat,lon
#   user: bob
#
# dst:
#   ip: 10.10.10.1
#   geo: ~
#   user: alice
#
# process:
#   executable:
#   pid:
#   command:
#   exit_code:
#   working_dir:
#
# file:
#   path: ..
#   name: ..
#   extension: ..
#   size: ..
#   hash: ..
#
# http:
#   method: GET
#   host: example.com
#   request: /?s=235235532
#   path: /
#   status: 200
#   useragent: ...
#   referrer:
#     full: ...
#     host: ...
#     domain: ...
#
# client:
#   device: ..
#   type: ..
#   os: ..
#
# related:
#   ip:
#   user:

has parser => (
    is  => 'lazy',
    isa => CodeRef,
);
sub _build_parser {
    my ($self) = @_;


    return sub {
        my ($msg) = @_;
        # Configure things how we need them
        local $Parse::Syslog::Line::AutoDetectJSON = 1;
        local $Parse::Syslog::Line::AutoDetectKeyValues = 1;
        local $Parse::Syslog::Line::RFC5424StructuredData = 1;
        local $Parse::Syslog::Line::RFC5424StructuredDataStrict = 0;
        local $Parse::Syslog::Line::ExtractProgram = 1;
        local $Parse::Syslog::Line::DateParsing = 1;
        local $Parse::Syslog::Line::EpochCreate = 0;
        local $Parse::Syslog::Line::PruneRaw = 1;
        local $Parse::Syslog::Line::PruneEmpty = 1;
        local $Parse::Syslog::Line::FmtDate = undef;
        return parse_syslog_line($msg);
    };
}

sub parse {
    my ($self,$msg) = @_;

    my $res = $self->parser->($msg);
    my %doc = (
        labels => dclone($self->labels),
        timestamp => $res->{datetime_utc},
        message   => $msg,
        src_host  => $res->{host},
        provider  => $res->{program_name},
        # Optional Elements
        $res->{severity}    ? ( severity  => $res->{priority} ) : (),
        $res->{domain}      ? ( src_domain => $res->{domain} ) : (),
        $res->{program_pid} ? ( pid => $res->{program_pid} ) : (),
        $res->{program_sub} ? ( component => $res->{program_sub} ) : (),
        _tags => { syslog => 1 },
    );

    use DDP;
    foreach my $p ( @{ $self->plugins } ) {
        $p->process($res,\%doc);
        p($res, as => 'after_' . $p->name);
    }

    my %rel = ();
    foreach my $k ( keys %doc ) {
        if ( $k =~ /_ip$/ ) {
            $rel{ip}->{$doc{$k}} = 1;
        }
        elsif ( $k =~ /user$/ ) {
            $rel{user}->{$doc{$k}} = 1;
        }
    }
    foreach my $section ( keys %rel ) {
        $doc{related}{$section} = [ keys %{ $rel{$section} } ];
    }

    if ( my $tags = delete $doc{_tags} ) {
        $doc{tags} = [ sort keys %{ $tags } ];
    }

    p(%doc);
    exit;
    return \%doc;
}

1;
