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
    my ( $length, $remainder ) = unpack("n h*",pack("h*",$self->{'hexdata'}));
    $self->{'txt'} = unpack("a$length",pack("h*",$remainder));
    return $self;
}
1;
