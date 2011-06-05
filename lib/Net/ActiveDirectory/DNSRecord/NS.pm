package Net::ActiveDirectory::DNSRecord::NS;
use parent Net::ActiveDirectory::DNSRecord::Base;

sub zoneform{ # this will need to be overridden
    my $self = shift;
    my $type = __PACKAGE__;
    $type=~s/.*:://;
    return "IN $type ".$self->{'ns'}." ".$self->{'texthex'};
}

sub decode{
    my $self = shift;
    return undef unless $self->{'hexdata'};
    $self->{'ns'} = $self->unpack_text($self->{'hexdata'});
    return $self;
}

sub encode{
    my $self = shift;
    return undef unless $self->{'textdata'};
    $self->{'ns'}=$self->{'textdata'};
    $self->{'hexdata'} = $self->pack_text($self->{'textdata'});
    return $self;
}

sub ns  { my $self = shift; $self->{'ns'} = shift if @_; return $self->{'ns'}; }
sub hexdata  { my $self = shift; $self->{'hexdata'} = shift if @_; return $self->{'hexdata'}; }

1;
