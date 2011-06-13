#  This is basically an abstraction layer around Net::LDAP to use conventions that Active Directory uses
package Net::ActiveDirectory;
use Net::ActiveDirectory::DNSRecord;
use Net::DNS;
use Data::Dumper;
use MIME::Base64;
use Net::LDAP;
use Net::LDAP::Entry;
use YAML;
use strict;

sub new{ #ok
    my $class = shift;
    my $cnstr = shift if @_;
    my $self = {};
    bless $self, $class;
    if($cnstr->{'debug'}){ 
        $self->debug($cnstr->{'debug'});
    }else{
        $self->debug(0) ;
    };
    if($cnstr->{'username'}){ $self->username($cnstr->{'username'}) };
    if($cnstr->{'password'}){ $self->password($cnstr->{'password'}) };
    if($cnstr->{'domain'}){ $self->domain($cnstr->{'domain'}) };
    if($cnstr->{'zone'}){ 
        $self->zone($cnstr->{'zone'}) 
    }else{
        $self->zone($self->domain);
    };

    if($cnstr->{'dns_base'}){ 
        $self->dns_base($cnstr->{'dns_base'});
    }else{
        $self->dns_base("cn=MicrosoftDNS,cn=System,".$self->basedn);
    }
    
    $self->{'ldap'} = Net::LDAP->new( $self->domain ) or return undef;
    $self->{'mesg'} = $self->{'ldap'}->bind( 
                                             $self->username.'@'.$self->domain, 
                                             password => $self->password
                                           );

    #if($cnstr->{'data'}){ $self->decode($cnstr->{'data'}); }
    return $self;
}


sub get_resolvers{
    my $self = shift;
    my $zone = shift;
    $zone = $self->zone unless $zone;
    my $oldzone = $self->zone;
    my @records = $self->nslookup('@', 'NS');
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
                #print $nameserver.": ".$rr->address, "\n";
            }
            push(@{ $self->{'resolvers'}->{$zone} },$resolver);
        } else {
            warn "query failed: ", $resolver->errorstring, "\n";
        }
    }
    $self->zone($oldzone);
    return $self;
}

sub all_zones{ #ok
    my $self = shift;
    my @zones;
    my $mesg = $self->{'ldap'}->search(
                                        'base'   => $self->dns_base,
                                        'filter' => "(objectClass=dnsZone)",
                                        'scope'  => 'sub',
                                       );
    print STDERR $mesg->error if $mesg->code;
    foreach my $zone ($mesg->entries){
        push(@zones, $zone->get_value('dc'));
    }
    return @zones;
}

sub add_propagated{
    my $self = shift;
    my $hashform = $self->hashify(@_);
    #print STDERR Data::Dumper->Dump([$hashform]);
    $self->get_resolvers($hashform->{'zone'}) unless(defined($self->{'resolvers'}->{$hashform->{'zone'}})); 
    my $fully_propagated=0;
    foreach my $res (@{ $self->{'resolvers'}->{$hashform->{'zone'}}}){
        my $query;
        if($hashform->{'type'} eq 'A'){ 
            #print "Searching [".join(",",$res->nameservers)."] for $hashform->{'name'}.$hashform->{'zone'}\n";
            $query = $res->search("$hashform->{'name'}.$hashform->{'zone'}");
        }elsif($hashform->{'type'} eq 'PTR'){ 
            #print "Searching [".join(",",$res->nameservers)."] for $hashform->{'subnet'}.$hashform->{'name'}\n";
            $query = $res->search("$hashform->{'subnet'}.$hashform->{'name'}");
        }
        if ($query) {
            foreach my $rr ($query->answer) {
                next unless $rr->type eq $hashform->{'type'};
                if($hashform->{'type'} eq 'A'){ 
                    if($rr->address eq $hashform->{'data'}){ $fully_propagated++; }
                }elsif($hashform->{'type'} eq 'PTR'){ 
                    if($rr->ptrdname eq $hashform->{'data'}){ $fully_propagated++; }
                }
            }
        #} else {
        #    print STDERR "    ".$res->errorstring, "\n";
        }
    }
    my $resolver_count = $#{ $self->{'resolvers'}->{$hashform->{'zone'}}} + 1;
    print "$hashform->{'name'}.$hashform->{'zone'} is $hashform->{'data'} on [ ".$fully_propagated ." / ".$resolver_count ." ] nameservers.\n" if($self->debug);
    return 1 if($fully_propagated == $resolver_count);
    #print STDERR  Data::Dumper->Dump([$hashform]);
    return 0;
}


sub del_propagated{
    my $self = shift;
    my $hashform = $self->hashify(@_);
    #print STDERR Data::Dumper->Dump([$hashform]);
    $self->get_resolvers($hashform->{'zone'}) unless(defined($self->{'resolvers'}->{$hashform->{'zone'}}));
    my $fully_propagated=0;
    foreach my $res (@{ $self->{'resolvers'}->{$hashform->{'zone'}}}){
        my $query;
        if($hashform->{'type'} eq 'A'){
            #print "Searching [".join(",",$res->nameservers)."] for $hashform->{'name'}.$hashform->{'zone'}\n";
            $query = $res->search("$hashform->{'name'}.$hashform->{'zone'}");
        }elsif($hashform->{'type'} eq 'PTR'){
            #print "Searching [".join(",",$res->nameservers)."] for $hashform->{'subnet'}.$hashform->{'name'}\n";
            $query = $res->search("$hashform->{'subnet'}.$hashform->{'name'}");
        }
        if ($query) {
            foreach my $rr ($query->answer) {
                next unless $rr->type eq $hashform->{'type'};
                if($hashform->{'type'} eq 'A'){
                    if($rr->address eq $hashform->{'data'}){ $fully_propagated++; }
                }elsif($hashform->{'type'} eq 'PTR'){
                    if($rr->ptrdname eq $hashform->{'data'}){ $fully_propagated++; }
                }
            }
        #} else {
        #    print STDERR "    ".$res->errorstring, "\n";
        }
    }
    my $resolver_count = $#{ $self->{'resolvers'}->{$hashform->{'zone'}}} + 1;
    print "$hashform->{'name'}.$hashform->{'zone'} is $hashform->{'data'} on [ ".$fully_propagated ." / ".$resolver_count ." ] nameservers.\n" if($self->debug);
    return 1 if($fully_propagated == 0);
    #print STDERR  Data::Dumper->Dump([$hashform]);
    return 0;
}


sub nslookup{ #ok
    my $self=shift;
    my $query=shift if @_;
    my $type=shift if @_;
    return undef unless $query; 
    my @records;
    #print STDERR "&(objectClass=dnsNode)(DC=$query) dc=".$self->zone.",".$self->dns_base."\n";
    my $mesg = $self->{'ldap'}->search( 
        'base'   => "dc=".$self->zone.",".$self->dns_base,
        'filter' => "(&(objectClass=dnsNode)(DC=$query))",
    );
    print STDERR $mesg->error if $mesg->code;
    foreach my $entry ($mesg->entries){
        my @dcs = $entry->get_value('dc');
        if($#dcs > 0){
            print STDERR "multiple ldap entries found for $query\n";
            #print Data::Dumper->Dump([@dcs]);
        }else{
            my @dnsrecords=$entry->get_value('dnsRecord');
            foreach my $dnsrecord (@dnsrecords){
                 my $recobj = Net::ActiveDirectory::DNSRecord->new($dnsrecord);
                 if($type){
                     if(lc($recobj->type) eq lc($type)){
                         push(@records,$recobj)
                     }
                 }else{
                     push(@records,$recobj)
                }
            }
        }
    }
    return @records;
}

################################################################################
# Methods to parse the zone-style methods and hand them to add/delete
#
sub closest_arpa{
    my $self = shift;
    my $ip = shift if @_;
    return undef unless $ip;
    my $found=0;
    my @octets = split(/\./,$ip);
    my $hostocts='';
    while($found == 0){
        $hostocts.=".".pop(@octets);
        if($self->zone_exists( join('.',reverse(@octets)).".in-addr.arpa")){
            $found = 1;
        }
    }
    return join('.',reverse(@octets)).".in-addr.arpa" if @octets;
    return undef;
}

sub closest_zone{
    my $self = shift;
    my $zone = shift if @_;
    return undef unless $zone;
    my $found=0;
    my @zoneparts;
    my @zoneparts = split(/\./,$zone);
    my $name_part='';
    while($found == 0){
        $name_part.=".".shift(@zoneparts);
        if($self->zone_exists(join('.',@zoneparts))){
            $found = 1;
        }
    }
    return join('.',@zoneparts);
}

sub zone_exists{
    my $self = shift;
    my $zone = shift if @_;
    my @zones = $self->all_zones;
    my $found_it=0;
    foreach my $z (@zones){
        if($zone eq $z){ $found_it = 1; } 
    }
    unless($found_it){
        return 0;
    }
    return 1;
}

sub hashify{
    my $self = shift;
    if($#_ == 1){
        my ($zone, $record) = (@_);
        return undef unless $self->zone_exists($zone);
        my $oldzone = $self->zone;
        $self->zone($zone);
        my ($name, $ttl, $type, $data);
        if($record=~m/\s*(\S+)\s*\S*\s+IN\s+/){ $name = $1; }
        if($record=~m/\s*\S+\s+(\S+)\s+IN/){ $ttl = $1; }
        if($record=~m/\s+IN\s+(\S+)\s+(.*)/){ $type = $1; $data = $2; }
        $ttl = $self->soa->TTL unless $ttl;
        $self->zone($oldzone);
        return {
                 'zone' => $zone,
                 'name' => $name,
                 'ttl' => $ttl,
                 'type' => $type,
                 'data' => $data,
               };
    }elsif($#_ == 0){
        my ($record) = (@_);
        my ($fqdn, $name, $ttl, $type, $data, $fqip, $zone);
        if($record=~m/\s*(\S+)\s*\S*\s+IN\s+/){ $fqdn = $1; }
        if($record=~m/\s*\S+\s+(\S+)\s+IN/){ $ttl = $1; }
        if($record=~m/\s+IN\s+(\S+)\s+(.*)/){ $type = $1; $data = $2; }
        if( !$self->zone_exists($zone) ){ 
            if($type eq 'PTR'){
                my $arpa=$self->closest_arpa($fqdn); 
                my @subnet = split(/\./,$arpa);
                pop(@subnet); pop(@subnet);
                my $host_oct = $fqip;
                my $subnet = join('.',reverse(@subnet));
                $host_oct=$fqdn;
                $host_oct=~s/^$subnet.//;
                $ttl = $self->soa->TTL unless $ttl;
                return {
                         'zone' => $arpa,
                         'name' => $host_oct,
                         'ttl' => $ttl,
                         'type' => $type,
                         'data' => $data,
                         'subnet' => $subnet,
                       };
            }else{
                $zone=$self->closest_zone($fqdn); 
                $name=$fqdn;
                $name=~s/\.$zone$//;
                my $oldzone = $self->zone;
                $self->zone($zone);
                $ttl = $self->soa->TTL unless $ttl;
                $self->zone($oldzone);
                return {
                         'zone' => $zone,
                         'name' => $name,
                         'ttl' => $ttl,
                         'type' => $type,
                         'data' => $data,
                       };
            }
        }
    }
}

sub addrecord{
    my $self = shift;
    my $hashform = $self->hashify(@_);
    $self->add({
                'zone' => $hashform->{'zone'},
                'name' => $hashform->{'name'},
                'type' => $hashform->{'type'},
                'data' => $hashform->{'data'},
            });

}

sub delrecord{
    my $self = shift;
    my $hashform = $self->hashify(@_);
    $self->delete({
                    'zone' => $hashform->{'zone'},
                    'name' => $hashform->{'name'},
                    'type' => $hashform->{'type'},
                    'data' => $hashform->{'data'},
                 });
}

# add an A <---> PTR pair
sub addpair{
    my $self = shift;
    my ($fqdn, $fqip) = ( @_ );
    $fqdn=~s/\.$//;
    $fqip=~s/\.$//;
    my $zone = $self->closest_zone($fqdn);
    my $name=$fqdn;
    $name=~s/\.$zone$//g;

    my $arpa = $self->closest_arpa($fqip);
    my @subnet = split(/\./,$arpa);
    pop(@subnet); pop(@subnet);
    my $host_oct = $fqip;
    my $subnet = join('.',reverse(@subnet));
    $host_oct=~s/^$subnet.//;
    
    $self->add({
                'zone' => $zone,
                'name' => $name,
                'type' => 'A',
                'data' => $fqip,
            });
    $self->add({
                 'name' => $host_oct,
                 'zone' => $arpa,
                 'type' => 'PTR',
                 'data' => $fqdn,
              });

    return $self;
}

# add an A <---> PTR pair
sub delpair{
    my $self = shift;
    my ($fqdn, $fqip) = ( @_ );
    $fqdn=~s/\.$//;
    $fqip=~s/\.$//;
    my $zone = $self->closest_zone($fqdn);
    my $name=$fqdn;
    $name=~s/\.$zone$//g;

    my $arpa = $self->closest_arpa($fqip);
    my @subnet = split(/\./,$arpa);
    pop(@subnet); pop(@subnet);
    my $host_oct = $fqip;
    my $subnet = join('.',reverse(@subnet));
    $host_oct=~s/^$subnet.//;
    
    $self->delete({
                    'zone' => $zone,
                    'name' => $name,
                    'type' => 'A',
                    'data' => $fqip,
                });
    $self->delete({
                     'name' => $host_oct,
                     'zone' => $arpa,
                     'type' => 'PTR',
                     'data' => $fqdn,
                  });


    return $self;
}

################################################################################
# check all regeistered nameservers for propagation 
sub add{
    my $self = shift;
    my $cnstr = shift;
    my $record = Net::LDAP::Entry->new;
    # Because we can't be sure if the fqdn will have a trailing . or not.
    if($cnstr->{'type'}){
        if($cnstr->{'data'}){
            if($cnstr->{'type'} eq 'PTR'){
                $cnstr->{'data'}.="." unless $cnstr->{'data'}=~m/\.$/;
            }
        }
    }
    my $query = $cnstr->{'name'}; 
    my $type = $cnstr->{'type'};
    my $oldzone = $self->zone;
    if($cnstr->{'zone'}){
        $self->zone($cnstr->{'zone'});
        delete $cnstr->{'zone'};
    }
    $cnstr->{'update_at_serial'} = $self->soa->update_at_serial;
    $cnstr->{'textdata'} = $cnstr->{'data'} if $cnstr->{'data'};
    my $dnsrecord = Net::ActiveDirectory::DNSRecord->craft($cnstr);
    ############################################################################
    if($self->nslookup($query)){ # the record exists, so we only need update it.
    ############################################################################
        print "Will update.\n" if($self->debug);
        my $mesg = $self->{'ldap'}->search(
                                            'base'   => "dc=".$self->zone.",".$self->dns_base,
                                            'filter' => "(&(objectClass=dnsNode)(DC=$query))",
                                          );
        if($self->debug){ print STDERR $mesg->error if $mesg->code; }
        foreach my $entry ($mesg->entries){
            my @dcs = $entry->get_value('dc');
            if($#dcs > 0){
                print STDERR "multiple ldap entries found for $query\n";
                #print Data::Dumper->Dump([@dcs]);
            }else{
                my @dnsrecords = $entry->get_value('dnsRecord');
                # look for an exact match
                 my $exists=0;
                 foreach my $dnsrec (@dnsrecords){
                     my $recobj = Net::ActiveDirectory::DNSRecord->new($dnsrec);
                     if($dnsrecord->rdata->zoneform eq $recobj->rdata->zoneform){
                         print "[".$dnsrecord->rdata->zoneform."] [".$recobj->rdata->zoneform."]\n";
                         $exists=1;
                     }
                 }
                 if($exists == 0){
                     my @allrecords;
                     foreach my $dnsrec (@dnsrecords){
                         my $recobj = Net::ActiveDirectory::DNSRecord->new($dnsrec);
                         if($recobj->type ne 'Tombstone'){  # remove the tombstone record and attr
                             push(@allrecords, $dnsrec);
                         } 
                     }
                     $entry->delete('dNSTombstoned') if $entry->get_value('dNSTombstoned');

                     push(@allrecords,$dnsrecord->raw_record); # add the new record
                     $entry->replace('dnsRecord'=>\@allrecords);
                     $mesg=$entry->update( $self->{'ldap'});   # and update LDAP
                     if($self->debug){ print STDERR $mesg->error if $mesg->code; }
                 }else{
                    print STDERR "Duplicate entry, taking no action.\n";
                 }
            }
        }  
        $self->zone($oldzone);
        return $self;
    ############################################################################
    }else{                           # no ldap entry, so create new
    ############################################################################
        print "Will add.\n" if($self->debug);
        $record->dn("DC=$query,dc=$self->{'zone'},$self->{'dns_base'}");
        my $raw = $dnsrecord->raw_record;
        $record->add(
                      'objectClass'            => [ 'top', 'dnsNode' ],
                      'objectCategory'         => "CN=Dns-Node,CN=Schema,CN=Configuration,$self->{'basedn'}",
                      'distinguishedName'      => "DC=$query,dc=$self->{'zone'},$self->{'dns_base'}",
                      'dc'                     => "$query",
                      'name'                   => "$query",
                      'instanceType'           => 4,
                      'showInAdvancedViewOnly' => 'TRUE',
                      'dnsRecord'              => $raw,
                    );
        my $mesg = $record->update( $self->{'ldap'} );
        if($mesg->code){
            print STDERR $mesg->error."\n";
            $self->zone($oldzone);
            return undef;
         }
        $self->zone($oldzone);
        return $self;
    }
    ############################################################################
    $self->zone($oldzone);
    return $self;
}

sub delete{
    my $self = shift;
    my $cnstr = shift;
    my $oldzone = $self->zone;
    if($cnstr->{'zone'}){
        $self->zone($cnstr->{'zone'});
        delete $cnstr->{'zone'};
    }
    # Because we can't be sure if the fqdn will have a trailing . or not.
    if($cnstr->{'type'}){
        if($cnstr->{'data'}){
            if($cnstr->{'type'} eq 'PTR'){
                $cnstr->{'data'}.="." unless $cnstr->{'data'}=~m/\.$/;
            }
        }
    }
    my $delrecord = Net::ActiveDirectory::DNSRecord->craft($cnstr);
    return undef unless $cnstr->{'name'};
    my $query = $cnstr->{'name'};
    delete $cnstr->{'name'};
    my $type = undef;
    if($cnstr->{'type'}){
        $type = $cnstr->{'type'};
        delete $cnstr->{'type'};
    }
    my $mesg = $self->{'ldap'}->search(
                   'base'   => "dc=".$self->zone.",".$self->dns_base,
                   'filter' => "(&(objectClass=dnsNode)(DC=$query))",
               );
    if($mesg->code){
        print STDERR $mesg->error."\n";
        $self->zone($oldzone);
        return undef;
    }
    foreach my $entry ($mesg->entries){
        my @newrecords=();
        my $update_needed=0;
        my @dcs = $entry->get_value('dc');
        if($#dcs > 0){
            print STDERR "multiple ldap entries found for $query\n";
        }else{
            my @dnsrecords=$entry->get_value('dnsRecord');
            foreach my $dnsrecord (@dnsrecords){
                my $recobj = Net::ActiveDirectory::DNSRecord->new($dnsrecord);
                if($delrecord->rdata->zoneform ne $recobj->rdata->zoneform){
                    push(@newrecords,$dnsrecord);
                }else{
                    $update_needed=1;
                }
            }
        }
        if($update_needed == 1){ 
            if($#newrecords < 0){ 
                my $tombstone = Net::ActiveDirectory::DNSRecord->craft({
                                                                         'type'=> 'Tombstone',
                                                                         'data'=> time,
                                                                       });
                $entry->add('dNSTombstoned' => 'TRUE');
                $entry->replace( 'dnsRecord' => $tombstone->raw_record); 
            }else{
                $entry->replace( 'dnsRecord' => \@newrecords ); 
            }
            my $mesg = $entry->update( $self->{'ldap'} );
            print STDERR $mesg->code.": ".$mesg->error."\n" if($self->debug);
            if($mesg->code){
                print STDERR $mesg->error."\n";
                $self->zone($oldzone);
                return undef;
            }
        }
    }
    $self->zone($oldzone);
    return $self;
}

sub soa{ #ok
    my $self = shift;
    my @records = $self->nslookup('@','SOA');
    my @soas;
    foreach my $record(@records){
        if($record->type eq 'SOA'){ push(@soas, $record); }
    }
    if ($#soas > 0){ 
        print STDERR "Multiple SOAs on zone, returning first one.\n";
    }
    return shift @soas;
}

sub dns_base{
    my $self = shift;
    $self->{'dns_base'} = shift if @_;
    return $self->{'dns_base'};
}

sub basedn{
    my $self = shift;
    $self->{'basedn'} = shift if @_;
    return $self->{'basedn'};
}

sub password{
    my $self = shift;
    $self->{'password'} = shift if @_;
    return $self->{'password'};
}

sub dns_base{
    my $self = shift;
    $self->{'dns_base'} = shift if @_;
    return $self->{'dns_base'};
}

sub zone{
    my $self = shift;
    $self->{'zone'} = shift if @_;
    return $self->{'zone'};
}

sub domain{
    my $self = shift;
    $self->{'domain'} = shift if @_;
    $self->basedn("DC=".join(",DC=",split(/\./,$self->{'domain'}))) if($self->{'domain'});
    return $self->{'domain'};
}

sub username{
    my $self = shift;
    $self->{'username'} = shift if @_;
    return $self->{'username'};
}

sub debug{
    my $self = shift;
    $self->{'debug'} = shift if @_;
    return $self->{'debug'};
}

1;
