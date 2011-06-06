use Test::More tests => 1;
use Net::LDAP;
use Data::Dumper;
use strict;
BEGIN {
        unshift(@INC,"../lib") if -d "../lib";
        unshift(@INC,"lib") if -d "lib";
        use_ok('Net::ActiveDirectory');
      }
################################################################################
my ($USER, $DOMAIN) =("jameswhite", "eftdomain.net"); 
my $BASEDN="DC=".join(",DC=",split(/\./,$DOMAIN));
################################################################################
my $dns;
my $ad = Net::LDAP->new( $DOMAIN ) or return undef;
$ad->bind( $USER.'@'.$DOMAIN, password => $ENV{'WINDOWS_PASSWORD'} );
my $mesg = $ad->search(
                        'base'   => "cn=MicrosoftDNS,cn=System,".$BASEDN,
                        'filter' => "(objectClass=dnsZone)",
                        'scope'  => 'sub',
                       );
print STDERR $mesg->error if $mesg->code;
# read in all the zones into the zone hash
foreach my $zone ($mesg->entries){
    my $nmsg = $ad->search(
                            'base'   => $zone->dn,
                            'filter' => "(objectClass=dnsNode)",
                            'scope'  => 'sub',
                           );
    print STDERR $nmsg->error if $nmsg->code;
    foreach my $node ($nmsg->entries){
         my @records = $node->get_value('dnsRecord');
         foreach my $record (@records){
             push(@{ $dns->{$zone->get_value('dc')}->{$node->get_value('dc')} }, Net::ActiveDirectory::DNSRecord->new($record));
         }
    }
}

my $dump=1;
if($dump){
    print "dns:\n";
    foreach my $z (sort(keys(%{$dns}))){
        print "  - $z\n";
        foreach my $n (sort(keys(%{ $dns->{$z} }))){
            print "      - $n\n";
            foreach my $r (sort(@{ $dns->{$z}->{$n} })){
                print "          - ".$r->rdata->zoneform.
                      " ttl: ". $r->TTL .
                      " timestamp: ". $r->timestamp .
                      #" unknown_0: ". $r->unknown_0 .
                      #" unknown_1: ". $r->unknown_1 .
                      "\n";
            }
        }
    }
}

