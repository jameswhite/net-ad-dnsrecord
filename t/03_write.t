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
if(0){
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
}
my ($add,$delete)=(1,1);
if($add){
    # Low-level adding:
    $ad->add({ 
               'zone' => 'eftdomain.net', 
               'name' => 'ant21', 
               'type' => 'A', 
               'data' => '192.168.2.230' 
            });
    
    print "--\n";
    # see if it's there
    my @records = $ad->nslookup('ant21','A');
    foreach my $record (@records){
        print "Found added: ".$record->rdata->zoneform."\n";
    }
    print "--\n";
}

if($delete){
    print "Removing.\n";
    # remove it
    $ad->delete({
                  'zone' => 'eftdomain.net', 
                  'name' => 'ant21',
                  'type' => 'A', 
                  'data' => '192.168.2.230',
               });
    
    print "--\n";
    # see if it's gone
    my @records = $ad->nslookup('ant21','A');
    foreach my $record (@records){
        print "Found after removal: ".$record->rdata->zoneform."\n";
    }
}
