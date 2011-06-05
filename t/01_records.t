use Test::More tests => 7;
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

my $dump=1;
if($dump){
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

my $test_encoding=0;
if($test_encoding){
    my $all_a_ok = 1;
    my $all_cname_ok = 1;
    my $all_ptr_ok = 1;
    my $all_txt_ok = 1;
    my $all_ns_ok = 1;
    my $all_srv_ok = 1;
    foreach my $z (sort(keys(%{$dns}))){
        foreach my $n (sort(keys(%{ $dns->{$z} }))){
            foreach my $r_in (sort(@{ $dns->{$z}->{$n} })){
                my $hex_in = $r_in->hexdata; 
                #print STDERR $r_in->unknown_0." ".$r_in->unknown_1."\n";
                if($r_in->type eq 'A'){
                    my $ip = $r_in->rdata->ipaddress;
                    my $r_out = Net::ActiveDirectory::DNSRecord->craft({
                                    'type' => $r_in->type, 
                                    'textdata' => $r_in->rdata->ipaddress,
                                });
                    # normally we'd set this to $r->soa->serial so we just clone
                    $r_out->serial($r_in->serial);
                    $r_out->unknown_0($r_in->unknown_0);
                    $r_out->unknown_1($r_in->unknown_1);
                    if($r_in->hexdata ne $r_out->hexdata){
                        $all_a_ok = 0; 
                        print "1:[".$r_in->hexdata."]\n";
                        print "2:[".$r_out->hexdata."]\n";
                    }
                }elsif($r_in->type eq 'CNAME'){
                    my $cname = $r_in->rdata->cname;
                    my $r_out = Net::ActiveDirectory::DNSRecord->craft({
                                    'type' => $r_in->type, 
                                    'textdata' => $r_in->rdata->cname,
                                });
                    $r_out->serial($r_in->serial);
                    $r_out->unknown_0($r_in->unknown_0);
                    $r_out->unknown_1($r_in->unknown_1);
                   if($r_in->hexdata ne $r_out->hexdata){
                       $all_cname_ok = 0; 
                       print "1:[".$r_in->hexdata."]\n";
                       print "2:[".$r_out->hexdata."]\n";
                   }
                }elsif($r_in->type eq 'PTR'){
                    my $cname = $r_in->rdata->ptr;
                    my $r_out = Net::ActiveDirectory::DNSRecord->craft({
                                    'type' => $r_in->type, 
                                    'textdata' => $r_in->rdata->ptr,
                                });
                    $r_out->serial($r_in->serial);
                    $r_out->unknown_0($r_in->unknown_0);
                    $r_out->unknown_1($r_in->unknown_1);
                   if($r_in->hexdata ne $r_out->hexdata){
                       $all_ptr_ok = 0; 
                       print "1:[".$r_in->hexdata."]\n";
                       print "2:[".$r_out->hexdata."]\n";
                   }
                }elsif($r_in->type eq 'TXT'){
                    my $txt = $r_in->rdata->txt;
                    my $r_out = Net::ActiveDirectory::DNSRecord->craft({
                                    'type' => $r_in->type, 
                                    'textdata' => $r_in->rdata->txt,
                                });
                    $r_out->serial($r_in->serial);
                    $r_out->unknown_0($r_in->unknown_0);
                    $r_out->unknown_1($r_in->unknown_1);
                   if($r_in->hexdata ne $r_out->hexdata){
                       $all_txt_ok = 0; 
                       print "1:[".$r_in->hexdata."]\n";
                       print "2:[".$r_out->hexdata."]\n";
                   }
                }elsif($r_in->type eq 'NS'){
                    my $ns = $r_in->rdata->ns;
                    my $r_out = Net::ActiveDirectory::DNSRecord->craft({
                                    'type' => $r_in->type, 
                                    'textdata' => $r_in->rdata->ns,
                                });
                    $r_out->serial($r_in->serial);
                    $r_out->unknown_0($r_in->unknown_0);
                    $r_out->unknown_1($r_in->unknown_1);
                   if($r_in->hexdata ne $r_out->hexdata){
                       $all_ns_ok = 0; 
                       print "1:[".$r_in->hexdata."]\n";
                       print "2:[".$r_out->hexdata."]\n";
                   }
                }elsif($r_in->type eq 'SRV'){
                    my $srv = $r_in->rdata->srv;
#print Data::Dumper->Dump([$r_in]);
                    my $r_out = Net::ActiveDirectory::DNSRecord->craft({
                                    'type' => $r_in->type, 
                                    'textdata' => $r_in->rdata->srv,
                                });
                    $r_out->serial($r_in->serial);
                    $r_out->unknown_0($r_in->unknown_0);
                    $r_out->unknown_1($r_in->unknown_1);
                    $r_out->{'rdata'}->priority($r_in->{'rdata'}->priority);
                    $r_out->{'rdata'}->weight($r_in->{'rdata'}->weight);
                    $r_out->{'rdata'}->port($r_in->{'rdata'}->port);
                    if($r_in->hexdata ne $r_out->hexdata){
                        $all_srv_ok = 0; 
                        print "1:[".$r_in->hexdata."]\n";
                        print "2:[".$r_out->hexdata."]\n";
                    }
#print Data::Dumper->Dump([$r_out]);
                #}elsif($r_in->type eq 'A'){
                }
            }
        }
    }
    is($all_a_ok, 1, 'A records pack as un-packed');
    is($all_cname_ok, 1, 'CNAME records pack as un-packed');
    is($all_ptr_ok, 1, 'PTR records pack as un-packed');
    is($all_txt_ok, 1, 'TXT records pack as un-packed');
    is($all_ns_ok, 1, 'NS records pack as un-packed');
    is($all_srv_ok, 1, 'SRV records pack as un-packed');
}
