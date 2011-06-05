package Net::ActiveDirectory::DNSRecord::A;
use parent Net::ActiveDirectory::DNSRecord::Base;

sub zoneform{
    # IN A 172.16.0.2
    my $self = shift;
    return "IN A ".$self->ipaddress;
}

sub decode{
    my $self = shift;
    return undef unless $self->{'hexdata'};
    $self->{'ipaddress'}=$self->n2ip(unpack('N',pack('h*',$self->{'hexdata'})));
    return $self;
}

sub ipaddress  {        my $self = shift; $self->{'ipaddress'}   = shift if @_;        return $self->{'ipaddress'};        }
1;
