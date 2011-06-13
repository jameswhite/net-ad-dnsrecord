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
# if two arguments are given, the first one targets the zone explicitly
#my @zones = $ad->all_zones;
#print join(":",@zones)."\n";

$ad->addrecord( "$ENV{'WINDOWS_DOMAIN'}",          "somehost IN A 192.168.2.225"        ); #ok
$ad->addrecord( "2.168.192.in-addr.arpa", "225 IN PTR somehost.$ENV{'WINDOWS_DOMAIN'}." ); #ok

$ad->delrecord( "$ENV{'WINDOWS_DOMAIN'}",          "somehost IN A 192.168.2.225"        ); #ok
$ad->delrecord( "2.168.192.in-addr.arpa", "225 IN PTR somehost.$ENV{'WINDOWS_DOMAIN'}." ); #ok

# or add an SRV record with the zone-explicit form

$ad->addrecord( "$ENV{'WINDOWS_DOMAIN'}", "_ldap._tcp IN SRV 0 10 389 192.168.2.225"        ); #ok
$ad->delrecord( "$ENV{'WINDOWS_DOMAIN'}", "_ldap._tcp IN SRV 0 10 389 192.168.2.225"        ); #ok

# or if one argument is given, it will find the "Best fit" of the zones on the server

# Example: if foo.bar.$ENV{'WINDOWS_DOMAIN'} is given, it will first try to add 
# foo to lab.$ENV{'WINDOWS_DOMAIN'} and if there is no lab.$ENV{'WINDOWS_DOMAIN'} it will add 
# foo.lab to $ENV{'WINDOWS_DOMAIN'}. To override this, use the explicit zone two-argument version.
# TTL is optional, just like in the zone file...

$ad->addrecord( "_ldap._tcp.$ENV{'WINDOWS_DOMAIN'}. 86400 IN SRV 0 10 389 192.168.2.225"        ); #ok
$ad->delrecord( "_ldap._tcp.$ENV{'WINDOWS_DOMAIN'}. 86400 IN SRV 0 10 389 192.168.2.225"        ); #ok


# or add a reciprocal pair (this will add / delete the A and PTR for both

$ad->addpair( "somehost.$ENV{'WINDOWS_DOMAIN'}", "192.168.2.225" );
$ad->delpair( "somehost.$ENV{'WINDOWS_DOMAIN'}", "192.168.2.225" );

# this will lookup all the nameservers on the domain

$ad->add_propagated("somehost IN A 192.168.2.225");
$ad->del_propagated("somehost IN A 192.168.2.225");
