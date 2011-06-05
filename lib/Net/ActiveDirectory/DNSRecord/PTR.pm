package Net::ActiveDirectory::DNSRecord::PTR;
use parent Net::ActiveDirectory::DNSRecord::Base;

sub zoneform{ # this will need to be overridden
    my $self = shift;
    my $type = __PACKAGE__;
    $type=~s/.*:://;
    return "IN $type ".$self->{'ptr'};
}

sub decode{  
    my $self = shift;
    return undef unless $self->{'hexdata'};
    $self->{'ptr'} = $self->unpack_text($self->{'hexdata'});
    return $self;
}

sub encode{
    my $self = shift;
    return undef unless $self->{'textdata'};
    $self->{'ptr'}=$self->{'textdata'};
    $self->{'hexdata'} = $self->pack_text($self->{'textdata'});
    return $self;
}

sub ptr  { my $self = shift; $self->{'ptr'} = shift if @_; return $self->{'ptr'}; }
sub hexdata  { my $self = shift; $self->{'hexdata'} = shift if @_; return $self->{'hexdata'}; }

1;
