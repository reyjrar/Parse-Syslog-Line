#!perl
#
use v5.32;
use Parse::Syslog::Contextualize;
use Benchmark qw/timethese cmpthese/;
my $COUNT = 100;
my $ctx = Parse::Syslog::Contextualize->new(
);

foreach my $p ( @{ $ctx->plugins } ) {
    say $p->name;
}

my @plugins = @{ $ctx->plugins };
my $results = timethese($COUNT, {
    ParseOnly     => \&parse_only,
    Contextualize => \&contextualize,
});

cmpthese($results);


sub contextualize {
    foreach my $p ( @plugins ) {
        foreach my $msg ( $p->sample_messages ) {
            my $x = $ctx->parse($msg);
        }
    }
}

sub parse_only {
    foreach my $p ( @plugins ) {
        foreach my $msg ( $p->sample_messages ) {
            my $x = $ctx->parser->($msg);
        }
    }
}
