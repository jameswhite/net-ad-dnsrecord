use Test::More tests => 1;
BEGIN {
        unshift(@INC,"../lib") if -d "../lib";
        unshift(@INC,"lib") if -d "lib";
        use_ok('MS::DNS');
      }
################################################################################
# site-specific things
$AD="eftdomain.net";
$user="jameswhite";

################################################################################
#
$AD_BASE="dc=".join(",dc=",split(/\./,$AD));
my $creds =  {
               'host'   => "$AD",
               'basedn' => "dc=$AD,cn=MicrosoftDNS,cn=System,$AD_BASE",
               'binddn' => "$user\@$AD",
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
                       filter => "(&(objectClass=dnsNode)(dc=ant03))",
                     );
print STDERR $mesg->error if $mesg->code;
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

################################################################################
