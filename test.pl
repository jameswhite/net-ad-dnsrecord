#!/usr/bin/perl -w
BEGIN {
        unshift(@INC,"../lib") if -d "../lib";
        unshift(@INC,"lib") if -d "lib";
      }
use Net::LDAP;
use Data::Dumper;
use strict;
use MS::DNS;


my $ldap = Net::LDAP->new( 'cronus.eftdomain.net' ) or die "$@";
my $mesg = $ldap->bind( 'jameswhite@eftdomain.net', password => $ENV{'WINDOWS_PASSWORD'});
$mesg = $ldap->search( 
                       base   => "dc=eftdomain.net,cn=MicrosoftDNS,cn=System,dc=eftdomain,dc=net",
                       filter => "(objectClass=dnsNode)",
                     );

my ($a, $b);
foreach my $entry ($mesg->entries){ 
    my @dcs = $entry->get_value('dc');
    if($#dcs > 0){
        print Data::Dumper->Dump([@dcs]);
    }else{
        my @dnsrecords=$entry->get_value('dnsRecord');
        foreach my $dnsrecord (@dnsrecords){
            my $blob = MS::DNS->new({'data' => $dnsrecord});
            if($blob->type){
                if($blob->is_a){
                    if($entry->get_value('dc') eq "ant01"){
                        print Data::Dumper->Dump([$blob]);
                    }
                }
            }
        }
    }
}
my $blob = MS::DNS->new();
my $record = $blob->a_record('192.168.2.223');
my $a_record = Net::LDAP::Entry->new;
my $host='ant03';
$a_record->dn("dc=$host,dc=eftdomain.net,CN=MicrosoftDNS,cn=System,dc=eftdomain,dc=net");

$mesg = $a_record->delete( $ldap );
print Data::Dumper->Dump([$mesg->code,$mesg->error]);

$a_record->add (
                'objectClass'            => [ 'top', 'dnsNode' ],
                'objectCategory'         => 'CN=Dns-Node,CN=Schema,CN=Configuration,DC=eftdomain,DC=net',
                'distinguishedName'      => "DC=$host,DC=eftdomain.net,CN=MicrosoftDNS,CN=System,DC=eftdomain,DC=net",
                'dc'                     => "$host",
                'name'                   => "$host",
                'instanceType'           => 4,
                'showInAdvancedViewOnly' => 'TRUE',
                'dnsRecord'              => $record,
              );
$mesg = $a_record->update( $ldap );
print Data::Dumper->Dump([$mesg->code,$mesg->error]);

#$a->replace( 'dnsRecord' => $b->get_value('dnsRecord') );
#$mesg = $a->update( $ldap );
#print Data::Dumper->Dump([$mesg->code,$mesg->error]);
