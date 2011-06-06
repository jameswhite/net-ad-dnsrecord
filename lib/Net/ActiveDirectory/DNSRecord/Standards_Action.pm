package Net::ActiveDirectory::DNSRecord::Standards_Action;
use parent Net::ActiveDirectory::DNSRecord::Base;

sub zoneform{ # this will need to be overridden
    my $self = shift;
    my $type = __PACKAGE__;
    $type=~s/.*:://;
    #return "unparsed: IN $type $self->{'number'} [$self->{'hexdata'}]";
    return "unparsed: IN $type $self->{'hexdata'}";
}

# No idea what this is...
#sub decode{
#    my $self = shift;
#    return undef unless $self->{'hexdata'};
#    $self->{'number'}=unpack('N',pack('h*',$self->{'hexdata'}));
#    return $self;
#}


sub hexdata  { my $self = shift; $self->{'hexdata'}  = shift if @_; return $self->{'hexdata'};  }

1;
