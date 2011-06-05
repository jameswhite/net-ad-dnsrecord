#  This is basically an abstraction layer around Net::LDAP to use conventions that Active Directory uses
package Net::ActiveDirectory;
use Net::ActiveDirectory::DNSRecord;
use Data::Dumper;
use MIME::Base64;
use Net::LDAP;
use YAML;
use strict;

sub new{
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
        $self->zone = $self->domain;
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

sub lookup{
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
                 my $recobj = DNS::ActiveDirectory::DNSRecord->new($dnsrecord);
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
    $cnstr->{'serial'} = $self->soa->update_at_serial;
    my $dnsrecord = DNS::ActiveDirectory::DNSRecord->new();
    $dnsrecord->create($cnstr);
    print STDERR Data::Dumper->Dump([$dnsrecord]);
    if($self->lookup($query, $type)){ # the record exists, so we only need update it.
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
                # look for an exact match
                push(@dnsrecords,$dnsrecord->raw_record);
                $entry->replace('dnsRecord'=>\@dnsrecords);
                $mesg=$entry->update( $self->{'ldap'});
                print STDERR $mesg->error if $mesg->code;
            }
        }
        return $self;
    }else{                           # no ldap entry, so create new
        $record->dn("DC=$query,dc=$self->{'zone'},$self->{'dns_base'}");
        $record->add(
                      'objectClass'            => [ 'top', 'dnsNode' ],
                      'objectCategory'         => "CN=Dns-Node,CN=Schema,CN=Configuration,$self->{'basedn'}",
                      'distinguishedName'      => "DC=$query,dc=$self->{'zone'}$self->{'dns_base'}",
                      'dc'                     => "$query",
                      'name'                   => "$query",
                      'instanceType'           => 4,
                      'showInAdvancedViewOnly' => 'TRUE',
                      'dnsRecord'              => $dnsrecord->raw_record,
                    );
        my $mesg = $record->update( $self->{'ldap'} );
        if($mesg->code){
            print STDERR $mesg->error."\n";
            return undef;
            }
        return $self;
    }
}

sub delete{
    my $self = shift;
    my $cnstr = shift;
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
        my @dcs = $entry->get_value('dc');
        if($#dcs > 0){
            print STDERR "multiple ldap entries found for $query\n";
            #print Data::Dumper->Dump([@dcs]);
        }else{
            my @dnsrecords=$entry->get_value('dnsRecord');
            foreach my $dnsrecord (@dnsrecords){
                 my $recobj = DNS::ActiveDirectory::DNSRecord->new($dnsrecord);
                 if($type){
                     if(lc($recobj->type) eq lc($type)){
                         my @attributes = keys(%{ $cnstr });
                         my $matches=-1;
                         foreach my $attr (@attributes){
                             if($recobj->attr($attr) eq $cnstr->{$attr}){
                                 $matches++;
                             }
                         }
                         push(@newrecords,$dnsrecord) unless ($matches == $#attributes);
                     }else{
                         push(@newrecords,$dnsrecord);
                    }
                }
            }
        }
        if($#newrecords >= 0){
            $entry->replace( 'dnsRecord' => \@newrecords );
        }else{
            $entry->delete;
        }
        my $mesg = $entry->update( $self->{'ldap'} );
        if($mesg->code){
            print STDERR $mesg->error."\n";
            return undef;
        }
    }
    return $self;
}

sub soa{
    my $self = shift;
    my @records = $self->lookup('@','SOA');
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
