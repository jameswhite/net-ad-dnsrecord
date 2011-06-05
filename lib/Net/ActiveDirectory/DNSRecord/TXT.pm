package Net::ActiveDirectory::DNSRecord::TXT;
use parent Net::ActiveDirectory::DNSRecord::Base;

sub zoneform{
    my $self = shift;
    my $type = __PACKAGE__;
    $type=~s/.*:://;
    return "IN $type $self->{'txt'}";
}

sub decode{
    my $self = shift;
    return undef unless $self->{'hexdata'};
    my ( $length, $remainder ) = unpack("c h*",pack("h*",$self->{'hexdata'}));
    $self->{'txt'} = unpack("a$length",pack("h*",$remainder));
    return $self;
}

sub encode{
    my $self = shift;
    return undef unless $self->{'textdata'};
    $self->{'txt'} = $self->{'textdata'};
    $self->{'hexdata'} = unpack("h*",pack("c a*",length($self->{'textdata'}),$self->{'textdata'}));
    return $self;
}

sub txt  { my $self = shift; $self->{'txt'} = shift if @_; return $self->{'txt'}; } 
sub hexdata  { my $self = shift; $self->{'hexdata'} = shift if @_; return $self->{'hexdata'}; }

1;
