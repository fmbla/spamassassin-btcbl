package Mail::SpamAssassin::Plugin::BTCBL;
my $VERSION = 0.1;

use strict;
use Mail::SpamAssassin::Plugin;
use Net::DNS;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

my $btc_regex = qr/\b(?<!=)([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/;

sub dbg { Mail::SpamAssassin::Plugin::dbg ("BTCBL: @_"); }

sub new
{
    my ($class, $mailsa) = @_;

    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsa);
    bless ($self, $class);

    $self->{BTCBL_available} = 1;
    if ($mailsa->{local_tests_only}) {
        $self->{BTCBL_available} = 0;
        dbg("only local tests enabled, plugin disabled");
    }

    $self->register_eval_rule("check_btcbl");

    return $self;
}

# parse eval rule args
sub _parse_args {
    my ($self, $zone, $zone_match) = @_;

    if (not defined $zone) {
        warn("zone must be specified for rule");
        return ();
    }

    # zone
    $zone =~ s/\s+//g; $zone = lc($zone);
    unless ($zone =~ /^[a-z0-9_.-]+$/) {
        warn("invalid zone definition: $zone");
        return ();
    }

    # zone_match
    if (defined $zone_match) {
        my $tst = eval { qr/$zone_match/ };
        if ($@) {
            warn("invalid match regex: $zone_match");
            return ();
        }
    }
    else {
        $zone_match = '127\.\d+\.\d+\.\d+';
    }

    return ($zone, $zone_match);
}
sub _add_desc {
    my ($self, $pms, $email, $desc) = @_;

    my $rulename = $pms->get_current_eval_rule_name();
    if (not defined $pms->{conf}->{descriptions}->{$rulename}) {
        $pms->{conf}->{descriptions}->{$rulename} = $desc;
    }
}

# hash and lookup array of emails
sub _lookup {
    my ($self, $pms, $prs, $emails) = @_;

    return 0 unless @$emails;

    my %digests = map { $_ => $_ } @$emails;
    my $dcnt = scalar keys %digests;

    # nothing to do?
    return 0 unless $dcnt;

    # todo async lookup and proper timeout
    my $timeout = int(10 / $dcnt);
    $timeout = 3 if $timeout < 3;

    my $resolver = Net::DNS::Resolver->new(
        udp_timeout => $timeout,
        tcp_timeout => $timeout,
        retrans => 0,
        retry => 1,
        persistent_tcp => 0,
        persistent_udp => 0,
        dnsrch => 0,
        defnames => 0,
    );

    foreach my $digest (keys %digests) {
        my $email = $digests{$digest};

        # if cached
        if (defined $pms->{btcbl_lookup_cache}{"$digest.$prs->{zone}"}) {
            my $addr = $pms->{btcbl_lookup_cache}{"$digest.$prs->{zone}"};
            dbg("lookup: $digest.$prs->{zone} [cached]");
            return 0 if ($addr eq '');
            if ($addr =~ $prs->{zone_match}) {
                dbg("HIT! $digest.$prs->{zone} = $addr");
                $self->_add_desc($pms, $email, "btcbl hit at $prs->{zone}");
                return 1;
            }
            return 0;
        }

        dbg("lookup: $digest.$prs->{zone}");
        my $query = $resolver->query("$digest.$prs->{zone}", 'A');
        if (not defined $query) {
            if ($resolver->errorstring ne 'NOERROR' &&
                $resolver->errorstring ne 'NXDOMAIN') {
                dbg("DNS error? ($resolver->{errorstring})");
            }
            $pms->{btcbl_lookup_cache}{"$digest.$prs->{zone}"} = '';
            next;
        }
        foreach my $rr ($query->answer) {
            if ($rr->type ne 'A') {
                dbg("got answer of wrong type? ($rr->{type})");
                next;
            }
            if (defined $rr->address && $rr->address ne '') {
                $pms->{btcbl_lookup_cache}{"$digest.$prs->{zone}"} = $rr->address;
                if ($rr->address =~ $prs->{zone_match}) {
                    dbg("HIT! $digest.$prs->{zone} = $rr->{address}");
                    $self->_add_desc($pms, $email, "btcbl hit at $prs->{zone}");
                    return 1;
                }
                else {
                    dbg("got answer, but not matching $prs->{zone_match}");
                }
            }
            else {
                dbg("got answer but no IP? ($resolver->{errorstring})");
            }
        }
    }

    return 0;
}

sub _btcbl {
    my ($self, $pms, $zone, $zone_match) = @_;

    my $prs = {}; # per rule state
    $prs->{zone} = $zone;
    $prs->{zone_match} = $zone_match;
    $prs->{rulename} = $pms->get_current_eval_rule_name();

    dbg("RULE ($prs->{rulename}) zone:$prs->{zone} match:$prs->{zone_match}");

    my @lookup_body;

    # parse body
    # if not cached
    my $body = $pms->get_decoded_stripped_body_text_array();
    my %all;
    BODY: foreach (@$body) {
         while (/$btc_regex/g) {
              my $email = lc($1);
              $all{$email} = 1;
         }
     }
     dbg("all BTCs from body: ".join(', ', keys %all)) if %all;

     my @lookup_all = keys %all;
     return $self->_lookup($pms, $prs, \@lookup_all);

}

sub check_btcbl {
    my ($self, $pms, @args) = @_;

    return 0 unless $self->{BTCBL_available};
    return 0 unless (@args = $self->_parse_args(@args));
    return _btcbl($self, $pms, @args);
}

1;
