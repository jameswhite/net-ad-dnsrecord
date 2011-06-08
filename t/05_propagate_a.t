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

# the test record
my ( $zone, $name, $type, $data ) = ( $DOMAIN, "ant32", "A", "192.168.2.227" );
################################################################################
my $ad = Net::ActiveDirectory->new({
                                     'domain'   => "$DOMAIN",
                                     'username' => "$USER",
                                     'password' => $ENV{'WINDOWS_PASSWORD'},
                                  });

# my @zones = $ad->all_zones;
# print join(":",@zones)."\n";

my $trace = 0;
my $sleep_interval = 10;
################################################################################
# set up our resolvers to test propagation
my @resolvers;
my @records = $ad->nslookup('@', NS);
foreach my $record (@records){
    my $nameserver = $record->{'rdata'}->ns;
    my $resolver = Net::DNS::Resolver->new(
                                            nameservers => [$nameserver],
                                            recurse     => 0,
                                            debug       => 0,
                                          );
    my $query = $resolver->search($nameserver);
    if ($query) {
        foreach my $rr ($query->answer) {
            next unless $rr->type eq "A";
            print $nameserver.": ".$rr->address, "\n" if($trace);
        }
        push(@resolvers,$resolver);
    } else {
        warn "query failed: ", $resolver->errorstring, "\n";
    }
}

################################################################################
# add and propagate
#
my $add_time=time;
$ad->add({ 'zone' => $zone, 'name' => $name, 'type' => $type, 'data' => $data});

my $fully_propagated = 0;
while($fully_propagated < ($#resolvers +1)){
    $fully_propagated=0;
    foreach my $res (@resolvers){
        print "Searching [".join(",",$res->nameservers)."] for $name.$DOMAIN: " if($trace);
        my $query = $res->search("$name.$DOMAIN");
        if ($query) {
            foreach my $rr ($query->answer) {
                next unless $rr->type eq $type;
                print "    ".$rr->address, "\n" if($trace);
            }
            $fully_propagated++;
        } else {
            print "    ".$res->errorstring, "\n" if($trace);
        }
    }
    print "Propagation is [ ".$fully_propagated." of "; 
    print $#resolvers + 1; 
    print " ]";  
    if($fully_propagated < ($#resolvers +1)){
        print " sleeping $sleep_interval...\n"; 
        sleep $sleep_interval;
    }else{
        print "\n"; 
    }
}
my $propagation_time0 = time - $add_time;

################################################################################
# delete and propagate
#
exit 0;
print "Removing.\n";
my $del_time=time;
# remove it
$ad->delete({'zone' => $zone, 'name' => $name,'type' => $type ,'data' => $data });

$fully_propagated = 0;
while($fully_propagated < ($#resolvers +1)){
    $fully_propagated=0;
    foreach my $res (@resolvers){
        print "Searching [".join(",",$res->nameservers)."] for $name.$DOMAIN: " if($trace);
        my $query = $res->search("$name.$DOMAIN");
        if ($query) {
            foreach my $rr ($query->answer) {
                next unless $rr->type eq $type;
                print "    ".$rr->address, "\n" if($trace);
            }
        } else {
            print "    ".$res->errorstring, "\n" if($trace);
            $fully_propagated++;
        }
    }
    print "Propagation is [ ".$fully_propagated." of "; 
    print $#resolvers + 1; 
    print " ]";  
    if($fully_propagated < ($#resolvers +1)){
        print " sleeping $sleep_interval...\n"; 
        sleep $sleep_interval;
    }else{
        print "\n"; 
    }
}
my $propagation_time1 = time - $del_time;

################################################################################
# reporting
#
print "--\n";
print "Add Propagated in $propagation_time0 seconds.\n";
print "Delete Propagated in $propagation_time1 seconds.\n";
