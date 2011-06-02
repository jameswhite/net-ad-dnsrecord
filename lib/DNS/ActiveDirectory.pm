package DNS::ActiveDirectory;
use DNS::ActiveDirectory::DNSRecord;
use Data::Dumper;
use Net::LDAP;
use strict;

sub new{
    my $class = shift;
    my $cnstr = shift if @_;
    my $self = {};
    bless $self, $class;
    if($cnstr->{'username'}){ $self->username($cnstr->{'username'}) };
    if($cnstr->{'password'}){ $self->password($cnstr->{'password'}) };

    if($cnstr->{'domain'}){ $self->domain($cnstr->{'domain'}) };

    if($cnstr->{'dns_base'}){ 
        $self->dns_base($cnstr->{'dns_base'});
    }else{
        $self->dns_base("dc=".$self->domain.",cn=MicrosoftDNS,cn=System,".$self->basedn);
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
    return undef unless $query; 
    my @records;
    my $mesg = $self->{'ldap'}->search( 
                                        'base'   => $self->dns_base,
                                        'filter' => "(&(objectClass=dnsNode)(dc=$query))",
                                      );
    print STDERR $mesg->error if $mesg->code;
    foreach my $entry ($mesg->entries){
        my @dcs = $entry->get_value('dc');
        if($#dcs > 0){
            print STDERR "multiple ldap entries found for $query\n";
            #print Data::Dumper->Dump([@dcs]);
        }else{
            my @dnsrecords=$entry->get_value('dnsRecord');
            print STDERR $entry->get_value('dc')."\n";
            foreach my $dnsrecord (@dnsrecords){
                 push(@records,DNS::ActiveDirectory::DNSRecord->new($dnsrecord));
#                if($record->type){
#                     print STDERR $record->type;
#                    if($decoded_record->is_soa){
#                         print STDERR Data::Dumper->Dump([$decoded_record->{'rdata'}])."\n";
#                    }
#                }
            }
        }
    }
    return @records;
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

sub domain{
    my $self = shift;
    $self->{'domain'} = shift if @_;
    $self->basedn("dc=".join(",dc=",split(/\./,$self->{'domain'}))) if($self->{'domain'});
    return $self->{'domain'};
}

sub username{
    my $self = shift;
    $self->{'username'} = shift if @_;
    return $self->{'username'};
}

1;
