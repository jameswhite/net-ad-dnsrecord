use Test::More tests => 15;
print $VERSION;
BEGIN {
        unshift(@INC,"../lib") if -d "../lib";
        unshift(@INC,"lib") if -d "lib";
        use_ok('DNS::ActiveDirectory');
        use_ok('DNS::ActiveDirectory::DNSRecord');
      }
################################################################################
$USER="jameswhite";
$AD="eftdomain.net"; 
$AD_BASE="DC=".join(",DC=",split(/\./,$AD));
################################################################################
my $dns = DNS::ActiveDirectory->new({
                                        'domain'   => $AD,
                                        'username' => $USER,
                                        'password' => $ENV{'WINDOWS_PASSWORD'},
                                        'dns_base' => "dc=$AD,cn=MicrosoftDNS,cn=System,$AD_BASE",
                                     });
if($dns){
    ok($dns->lookup('@'), 'I have some records');
    ok($dns->soa, 'I have an SOA');
    ok($dns->soa->update_at_serial, 'I have an SOA update serial');
    ok($dns->lookup('ant01'), 'I have and ant01 of some type');
    ok($dns->lookup('ant02','A'), 'ant02 A record exists');
    my @records = $dns->lookup('ant02','A');
    ok($records[0]->attr('address'), 'ant02 A record has address attribute');
    ok(!$dns->lookup('ant04','A'), 'ant04 A record does not exist');
    ok($dns->add({ 
                   'type' => 'A', 
                   'name' => 'ant04', 
                   'address' => '192.168.2.224' 
                 }), 'add primary ant04 A record');
    ok($dns->add({ 
                   'type' => 'A', 
                   'name' => 'ant04', 
                   'address' => '192.168.2.225' 
                 }), 'add secondary ant04 A record');
    ok($dns->lookup('ant04','A'), 'ant04 A record exists');
    ok($dns->delete({ # we have to be specific here because there can be multiple dnsrecords
                     'type' => 'A', 
                     'name' => 'ant04', 
                     'address' => '192.168.2.225' 
                   }), 'remove secondary ant04 record');
    ok($dns->delete({ 
                     'type' => 'A', 
                     'name' => 'ant04', 
                     'address' => '192.168.2.224' 
                   }), 'remove primary ant04 record');
    ok(!$dns->lookup('ant04','A'), 'ant04 record does not exist');
}
