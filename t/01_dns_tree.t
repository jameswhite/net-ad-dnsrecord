use Test::More tests => 1;
use Net::LDAP;
use Data::Dumper;
BEGIN {
        unshift(@INC,"../lib") if -d "../lib";
        unshift(@INC,"lib") if -d "lib";
        use_ok('DNS::ActiveDirectory::DNSRecord');
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
         foreach my $record(@records){
             push(@{ $dns->{$zone->get_value('dc')}->{$node->get_value('dc')} }, DNS::ActiveDirectory::DNSRecord->new($dnsrecord));
         }
    }
}

print Data::Dumper->Dump([$dns]);

