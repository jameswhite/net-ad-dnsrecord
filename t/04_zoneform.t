use Test::More tests => 1;
use Data::Dumper;
BEGIN {
        unshift(@INC,"../lib") if -d "../lib";
        unshift(@INC,"lib") if -d "lib";
        use_ok('Net::ActiveDirectory');
      }
################################################################################
# site-specific things
my ($USER, $DOMAIN) = ("jameswhite","eftdomain.net");
################################################################################
my $ad = Net::ActiveDirectory->new({
                                     'domain'   => "$DOMAIN",
                                     'username' => "$USER",
                                     'password' => $ENV{'WINDOWS_PASSWORD'},
                                  });

$ad->exists("ant01.eftdoamin.net IN A 192.168.2.222");
$ad->exists("192.168.2.222 IN PTR ant01.eftdomain.net");
$ad->exists("192.168.2.222 IN PTR ant01.eftdomain.net");


my @zones = $ad->all_zones;
print join(":",@zones)."\n";

print "--\n";

my @records = $ad->nslookup('@');
foreach my $record (@records){
    print $record->rdata->zoneform."\n" unless($record->rdata->zoneform=~m/unparsed/);
}

print "--\n";
@records = $ad->nslookup('@','NS');
foreach my $record (@records){
   print $record->rdata->zoneform."\n" unless($record->rdata->zoneform=~m/unparsed/);
}

print "--\n";
@records = $ad->nslookup('texttest','TXT');
foreach my $record (@records){
    print $record->rdata->zoneform."\n" unless($record->rdata->zoneform=~m/unparsed/);
}

print "--\n";
@records = $ad->soa;
foreach my $record (@records){
    print "update_at_serial: ".$record->update_at_serial."\n";
}

print "--\n";

# Low-level adding:
$ad->add({ 
           'zone' => 'eftdomain.net', 
           'name' => 'ant07', 
           'type' => 'A', 
           'data' => '192.168.2.227' 
        });

print "--\n";
# see if it's there
my @records = $ad->nslookup('ant07','A');
foreach my $record (@records){
    print "Found added: ".$record->rdata->zoneform."\n";
}

print "--\n";
print "Removing.\n";
# remove it
$ad->delete({
              'zone' => 'eftdomain.net', 
              'name' => 'ant07',
              'type' => 'A', 
              'data' => '192.168.2.227',
           });

print "--\n";
# see if it's gone
my @records = $ad->nslookup('ant07','A');
print "Deleted and Found: ".$#records."\n";


#$ad->add({ 
#                 'zone' => 'eftdomain.net', 
#                 'name' => 'ant05', 
#                 'type' => 'A', 
##                 'data' => '192.168.2.225' 
#             });

#print $ad->add({ 
#                 'zone' => "2.168.192.in-addr.arpa", 
#                 'name' => '225', 
#                 'type' => 'PTR', 
#                 'data' => 'ant05.eftdomain.net.'
#              });
