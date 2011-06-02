use Test::More tests => 3;
print $VERSION
BEGIN {
        unshift(@INC,"../lib") if -d "../lib";
        unshift(@INC,"lib") if -d "lib";
        use_ok('DNS::ActiveDirectory');
        use_ok('DNS::ActiveDirectory::DNSRecord');
      }
################################################################################
$USER="jameswhite";
$AD="eftdomain.net"; 
$AD_BASE="dc=".join(",dc=",split(/\./,$AD));
################################################################################
my $dns = DNS::ActiveDirectory->new({
                                        'domain'   => $AD,
                                        'username' => $USER,
                                        'password' => $ENV{'WINDOWS_PASSWORD'},
                                        'dns_base' => "dc=$AD,cn=MicrosoftDNS,cn=System,$AD_BASE",
                                     });
if($dns){
    my @records = $dns->lookup('ant01');
#    print Data::Dumper->Dump([@records]);
}
