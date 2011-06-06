package Net::ActiveDirectory::DNSRecord::Reserved_for_Private_Use;

use parent Net::ActiveDirectory::DNSRecord::Base;
sub zoneform{ # this will need to be overridden
    my $self = shift;
    my $type = __PACKAGE__;
    $type=~s/.*:://;
    return "unparsed: IN $type ".$self->hexdata;
}

sub hexdata  { my $self = shift; $self->{'hexdata'}  = shift if @_; return $self->{'hexdata'};  }

1;
