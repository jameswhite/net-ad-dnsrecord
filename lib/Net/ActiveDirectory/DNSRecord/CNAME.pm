package Net::ActiveDirectory::DNSRecord::CNAME;
use parent Net::ActiveDirectory::DNSRecord::Base;

sub zoneform{ # this will need to be overridden
    my $self = shift;
    my $type = __PACKAGE__;
    $type=~s/.*:://;
    return "IN $type ".$self->{'cname'};
}

sub decode{
    my $self = shift;
    return undef unless $self->{'hexdata'};
    $self->{'cname'} = $self->unpack_text($self->{'hexdata'});
    return $self;
}

sub encode{
    my $self = shift;
    return undef unless $self->{'textdata'};
    $self->{'cname'}=$self->{'textdata'};
    $self->{'hexdata'} = $self->pack_text($self->{'textdata'});
    return $self;
}

sub cname  { my $self = shift; $self->{'cname'} = shift if @_; return $self->{'cname'}; }
sub hexdata  { my $self = shift; $self->{'hexdata'} = shift if @_; return $self->{'hexdata'}; }

1;
