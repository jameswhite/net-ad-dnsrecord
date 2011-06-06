use Test::More tests => 1;
BEGIN {
        unshift(@INC,"../lib") if -d "../lib";
        unshift(@INC,"lib") if -d "lib";
        use_ok('MS::DNS');
      }

$AD="eftdomain.net";
$AD_BASE="dc=".join(",dc=",split(/\./,$AD));
my $creds =  {
               'host'   => "$AD",
               'basedn' => "dc=$AD,cn=MicrosoftDNS,cn=System,$AD_BASE",
               'binddn' => "jameswhite\@$AD",
               'bindpw' => $ENV{'WINDOWS_PASSWORD'},
             };

################################################################################
my $ldap = Net::LDAP->new( $creds->{'host'} ) or die "$@";
my $mesg = $ldap->bind( 
                        $creds->{'binddn'}, 
                        password => $creds->{'bindpw'}
                      );
$mesg = $ldap->search( 
                       base   => $creds->{'basedn'},
                       filter => "(&(objectClass=dnsNode)(dc=\@))",
                     );
print STDERR $mesg->error if $mesg->code;
foreach my $entry ($mesg->entries){
    my @dcs = $entry->get_value('dc');
    if($#dcs > 0){
        print Data::Dumper->Dump([@dcs]);
    }else{
        my @dnsrecords=$entry->get_value('dnsRecord');
        foreach my $dnsrecord (@dnsrecords){
            my $blob = MS::DNS->new({'data' => $dnsrecord});
            if($blob->type){
                if($blob->is_soa){
                     print STDERR Data::Dumper->Dump([$blob->{'rdata'}])."\n";
                }
            }
        }
    }
}

################################################################################
