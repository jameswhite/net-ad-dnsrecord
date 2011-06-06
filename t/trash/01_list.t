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
my $ad = Net::LDAP->new( $DOMAIN ) or return undef;
$ad->bind( $USER.'@'.$DOMAIN, password => $ENV{'WINDOWS_PASSWORD'} );
my $mesg = $ad->search(
                        'base'   => "cn=MicrosoftDNS,cn=System,".$BASEDN,
                        'filter' => "(objectClass=dnsZone)",
                        'scope'  => 'sub',
                       );
print STDERR $mesg->error if $mesg->code;

my $dns;

my @zones;
foreach my $entry ($mesg->entries){
    push(@zones,$entry->dn);
}

foreach my $zone (@zones){
    my $mesg = $ad->search(
                            'base'   => $zone,
                            'filter' => "(objectClass=dnsZone)",
                            'scope'  => 'sub',
                           );
    print STDERR $mesg->error if $mesg->code;
    foreach my $entry ($mesg->entries){
        print "sub-zone: ".$entry->dn."\n" if($entry->dn ne $zone);
    }
}
my @entries;

my $dnsrecords = {};
foreach my $entry (@entries){
    my @records = $entry->get_value('dnsRecord');
    push (@{ $dnsrecords->{$entry->get_value('dc') } } ,@records);
}

foreach my $dnsrecord (keys((@dnsrecords)){
    my $robj=DNS::ActiveDirectory::DNSRecord->new($dnsrecord);
    if($robj->type eq 'TXT'){
        print Data::Dumper->Dump([$robj]);
    }
}
