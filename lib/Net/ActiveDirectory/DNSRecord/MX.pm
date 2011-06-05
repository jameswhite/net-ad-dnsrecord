package Net::ActiveDirectory::DNSRecord::MX;
use parent Net::ActiveDirectory::DNSRecord::Base;

sub zoneform{ # this will need to be overridden
    my $self = shift;
    my $type = __PACKAGE__;
    $type=~s/.*:://;
    return "unparsed: IN $type ".$self->hexdata;
}

1;
