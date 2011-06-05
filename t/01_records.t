use Test::More tests => 1;
use Net::LDAP;
use Data::Dumper;
BEGIN {
        unshift(@INC,"../lib") if -d "../lib";
        unshift(@INC,"lib") if -d "lib";
        use_ok('Net::ActiveDirectory');
      }
################################################################################
$USER="jameswhite";
$DOMAIN="eftdomain.net"; 
$BASEDN="DC=".join(",DC=",split(/\./,$DOMAIN));
################################################################################
my $dns;
my $ad = Net::LDAP->new( $DOMAIN ) or return undef;
$ad->bind( $USER.'@'.$DOMAIN, password => $ENV{'WINDOWS_PASSWORD'} );
my $zmsg = $ad->search(
                        'base'   => "cn=MicrosoftDNS,cn=System,".$BASEDN,
                        'filter' => "(objectClass=dnsZone)",
                        'scope'  => 'sub',
                       );
print STDERR $mesg->error if $zmsg->code;
# read in all the zones into the zone hash
foreach my $zone ($zmsg->entries){
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

my $debug=1;
if($debug){
    print "dns:\n";
    foreach my $z (sort(keys(%{$dns}))){
        print "  - $z\n";
        foreach my $n (sort(keys(%{ $dns->{$z} }))){
            print "      - $n\n";
            foreach my $r (sort(@{ $dns->{$z}->{$n} })){
                print "          - ".$r->rdata->zoneform."\n";
            }
        }
    }
}
