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

sub encode{
    my $self = shift;
    return undef unless $self->{'textdata'};
    $self->{'ipaddress'}=$self->{'textdata'};
    $self->{'hexdata'} = unpack("h*",pack('N',$self->ip2n($self->{'textdata'})));
    return $self;
}

sub ipaddress  { my $self = shift; $self->{'ipaddress'} = shift if @_; return $self->{'ipaddress'}; }
sub hexdata  { my $self = shift; $self->{'hexdata'} = shift if @_; return $self->{'hexdata'}; }
1;
