package Parse::Syslog::Context::URL;
# ABSTRACT: Inspects URL's for common attack patterns

use JSON::MaybeXS;
use Const::Fast;
use Moo;

use namespace::autoclean;
with qw(
    Parse::Syslog::Role::Plugin
);

# VERSION

=head1 SYNOPSIS

This context matches any field ending in '_url' and inspects the URL for common
attack patterns.  This is not sophisticated, but leverages the reconnaissance
stage of an attack in which attackers try unsophisticated things to look for
weak spots in your infrastructure.

It was built on the "least work for most reward" principle.  This context is
prone to false positives and false negatives, but works fast enough to be
inlined into the log processing pipeline.

=cut

my %SUSPICIOUS = ();
# Not significant on their own
const my %NeedsMore => map { $_ => 1 } qw(select union update table sleep alter alert drop delete rand > \\), '&#';

=for Pod::Coverage BUILD

=cut

sub BUILD {

    # Initialize things to prevent running code at compile time
    #
    # Generic Attack Strings
    my @Generic = map { quotemeta } qw(
        etc/passwd etc/shadow /* */
    );
    push @Generic, q{\\\\(?!x)}, q{bin/[a-z]*sh}, q{\w+\.(?:exe|dll|bat|cgi)\b};
    unshift @Generic, q|\.\.(?:[\\\/]\.{0,2})+|;
    $SUSPICIOUS{generic} = join '|', @Generic;

    # SQL Injections
    my @SQLI = map { qr/(?<=[^a-z_\-=])$_(?![a-z_\-=])/ } map { quotemeta } qw(
        insert update delete drop alter select union table sleep rand char chr
    );
    push @SQLI, qr/or\s+1=1\s*;\s*--/;
    $SUSPICIOUS{sqli} =  join '|', @SQLI;

    # XSS Attempts
    my @XSS = map { qr/(?<=[^a-z_\-=])$_(?![a-z_\-=])/ } map { quotemeta } qw(
        script alert onerror onload
    );
    push @XSS, map { quotemeta } qw(
        --> > ';
    ), '&#';
    $SUSPICIOUS{xss} = join('|', @XSS);

    const %SUSPICIOUS => %SUSPICIOUS;

}

=attr priority

Defaults to 100, running after most other contexts so things can
end up in the right fields.

=cut

sub _build_priority { 100 }

=for Pod::Coverage sample_messages

=cut

sub sample_messages {
    my @msgs = map { encode_json($_) } (
        { resource => "https://www.example.com/?t='%20OR%201=1;--" },
        { resource => "https://www.example.com/../../../etc/passwd" },
        { resource => "https://www.example.com/?q='><script>alert(1);</script>" },
    );
    return @msgs;
}

=method process

Parses the fields 'resource' and 'referer' for attack patterns.

Provides 3 top level keys to the context:

=over 2

=item B<attack_score>

The higher the number, the more likely an attack has been detected.  Takes the
HTTP response code into account if available.

=item B<attack_triggers>

This is the count of distinct tokens detected in the URL leading us to believe this
is an attack.

=item B<attacks>

This is a HashRef containing all the tokens and attack signatures tripped.

=back

Tags messages with 'security' if an attack string is detected.

=cut

sub process {
    my ($self,$log,$ctx) = @_;

    my %add    = ();
    my $score  = 0;
    my %tokens = ();
    my %tags   = ();

    foreach my $f ( keys %{ $ctx } ) {
        next unless $f =~ /(?:_ur[li])|(?:^resource)$/o;

        # Normalize (Lower casing, Unescaping)
        my $url = lc $ctx->{$f} =~ s/%([0-9a-f]{2})/chr(hex($1))/reg;
        my %attack  = ();
        my @badness = ();

        # We need to call each of these one at a time.  Since our regexes live
        # in a hash, we can only optimize if they won't change.
        if( my @sqli = ($url =~ /$SUSPICIOUS{sqli}/go ) ) {
            push @badness, @sqli;
            $attack{tags} = 'sqli';
            $tags{sqli}   = 1;
        }
        elsif( my @xss = ($url =~ /$SUSPICIOUS{xss}/go ) ) {
            push @badness, @xss;
            $attack{tags} = 'xss';
            $tags{xss}    = 1;
        }
        elsif( my @generic = ($url =~ /$SUSPICIOUS{generic}/go ) ) {
            push @badness, @generic;
            $attack{tags}  = 'generic';
            $tags{generic} = 1;
        }
        next unless @badness;

        # Extract the unique tokens for this field and globally
        my %uniq;
        foreach my $token (@badness) {
            $uniq{$token} = $tokens{$token} = 1;
        }
        # Check that we're not squatting on a single english word
        my($t) = keys %uniq;
        if( keys(%uniq) == 1 && exists $NeedsMore{$t} ) {
            next;
        }
        # Store the Score and Tokens
        $score += $attack{score} = @badness;
        $attack{tokens} = [ sort keys %uniq ];
        $add{$f} = \%attack;
    }

    if( keys %add ) {
        # Continue summing incase other things added scores.
        $ctx->{attacks}       = \%add;
        $ctx->{attack_score}  = $score;
        $ctx->{attack_tokens} = [ sort keys %tokens ];
        $ctx->{attack_type}   = [ sort keys %tags ];
        $ctx->{_tags}{security} = 1;
    }
}

=head1 SEE ALSO

L<Parse::Syslog::Contextualize>, L<Parse::Syslog::Role::Plugin>

=cut

1;
