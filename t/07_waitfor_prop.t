use Test::More tests => 1;
use Data::Dumper;
use Net::DNS;
BEGIN {
        unshift(@INC,"../lib") if -d "../lib";
        unshift(@INC,"lib") if -d "lib";
        use_ok('Net::ActiveDirectory');
      }
################################################################################
# site-specific things
my ($USER, $DOMAIN, $SUBNET) = ("$ENV{'WINDOWS_USERNAME'}","$ENV{'WINDOWS_DOMAIN'}");
################################################################################
# Set up the AD (ldap) connection
my $ad = Net::ActiveDirectory->new({
                                     'domain'   => $ENV{'WINDOWS_DOMAIN'},
                                     'username' => $ENV{'WINDOWS_USERNAME'},
                                     'password' => $ENV{'WINDOWS_PASSWORD'},
                                   });


################################################################################
# enable debugging or this seems to hang forever with no output
$ad->debug(1);

#Add them:
$ad->addrecord("$ENV{'WINDOWS_DOMAIN'}", "somehost IN A 192.168.2.225"       );
$ad->addrecord("2.168.192.in-addr.arpa", "225 IN PTR somehost.$ENV{'WINDOWS_DOMAIN'}.");

# Wait...
print "Waiting for add propagation:\n";
while( 
       !($ad->add_propagated("somehost.$ENV{'WINDOWS_DOMAIN'} IN A 192.168.2.225")) 
       ||
       !($ad->add_propagated("192.168.2.225 IN PTR somehost.$ENV{'WINDOWS_DOMAIN'}"))
    ){
    sleep 30;
}

# Delete them:
$ad->delrecord("$ENV{'WINDOWS_DOMAIN'}", "somehost IN A 192.168.2.225"        );
$ad->delrecord("2.168.192.in-addr.arpa", "225 IN PTR somehost.$ENV{'WINDOWS_DOMAIN'}." );

# Wait...
print "Waiting for delete propagation:\n";
while(!(
        $ad->del_propagated("somehost.$ENV{'WINDOWS_DOMAIN'} IN A 192.168.2.225") &&
        $ad->del_propagated("192.168.2.225 IN PTR somehost.$ENV{'WINDOWS_DOMAIN'}")
       )){
    sleep 30;
}
