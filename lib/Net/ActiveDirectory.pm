#  This is basically an abstraction layer around Net::LDAP to use conventions that Active Directory uses
package Net::ActiveDirectory;
use Net::ActiveDirectory::DNSRecord;
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

sub add{
    my $self = shift;
    my $cnstr = shift;
    my $record = Net::LDAP::Entry->new;
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
        print "Will update.\n";
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
                     print STDERR $mesg->error if $mesg->code;
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
        print "Will add.\n";
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
print STDERR "newrecords: $#newrecords\n";
            if($#newrecords < 0){ 
                my $tombstone = Net::ActiveDirectory::DNSRecord->craft({
                                                                         'type'=> 'Tombstone',
                                                                         'data'=> time,
                                                                       });
                $entry->add('dNSTombstoned' => 'TRUE');
                $entry->replace( 'dnsRecord' => $tombstone->raw_record); 
foreach my $value ($entry->get_value('dNSRecord')){
    print "dnsrecord ".unpack('h*',$value)."\n";
}
            }else{
                $entry->replace( 'dnsRecord' => \@newrecords ); 
            }
            my $mesg = $entry->update( $self->{'ldap'} );
            print STDERR $mesg->code.": ".$mesg->error."\n";
            if($mesg->code){
                print STDERR $mesg->error."\n";
                return undef;
            }
        }
    }
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

1;
