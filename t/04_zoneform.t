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
my $ad = Net::ActiveDirectory->new({
                                     'domain'   => "$DOMAIN",
                                     'username' => "$USER",
                                     'password' => $ENV{'WINDOWS_PASSWORD'},
                                  });

# my @zones = $ad->all_zones;
# print join(":",@zones)."\n";


