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
1;
