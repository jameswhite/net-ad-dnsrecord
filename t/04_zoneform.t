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
                                     'domain'   => "$DOMAIN",
                                     'username' => "$USER",
                                     'password' => $ENV{'WINDOWS_PASSWORD'},
                                  });

################################################################################
# if two arguments are given, the first one targets the zone explicitly

$ad->addrecord( "example.org",          "somehost IN A 192.168.2.225"        );
$ad->addrecord( "2.168.192.in-addr.arpa", "225 IN PTR somehost.example.org." );

$ad->delrecord( "example.org",          "somehost IN A 192.168.2.225"        );
$ad->delrecord( "2.168.192.in-addr.arpa", "225 IN PTR somehost.example.org." );

# or add an SRV record with the zone-explicit form

$ad->addrecord( "example.org", "_ldap._tcp IN SRV 0 10 389 192.168.2.225"        );
$ad->delrecord( "example.org", "_ldap._tcp IN SRV 0 10 389 192.168.2.225"        );


# or if one argument is given, it will find the "Best fit" of the zones on the server

# Example: if foo.bar.example.org is given, it will first try to add 
# foo to lab.example.org and if there is no lab.example.org it will add 
# foo.lab to example.org. To override this, use the explicit zone two-argument version.
# TTL is optional, just like in the zone file...

$ad->addrecord( "_ldap._tcp.example.org. 86400 IN SRV 0 10 389 192.168.2.225"        );
$ad->delrecord( "_ldap._tcp.example.org. 86400 IN SRV 0 10 389 192.168.2.225"        );


# or add a reciprocal pair (this will add / delete the A and PTR for both

$ad->addpair( "somehost.example.org", "192.168.2.225" );
$ad->delpair( "somehost.example.org", "192.168.2.225" );

# this will lookup all the nameservers on the domain

$ad->block_until_propagated("somehost.example.org");
