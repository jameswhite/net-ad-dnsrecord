package Net::ActiveDirectory::DNSRecord::SRV;
use parent Net::ActiveDirectory::DNSRecord::Base;

sub zoneform{ # this will need to be overridden
    my $self = shift;
    my $type = __PACKAGE__;
    $type=~s/.*:://;
    return "IN $type $self->{'priority'} $self->{'weight'} $self->{'port'} $self->{'srv'}";
}

sub decode{
    my $self = shift;
    return undef unless $self->{'hexdata'};
    ( 
      $self->{'priority'}, 
      $self->{'weight'}, 
      $self->{'port'}, 
      $remainder,
    ) = unpack("n n n h*", pack("h*",$self->{'hexdata'}));
    #$self->{'srv'} = $remainder;
    $self->{'srv'} = $self->unpack_text($remainder);
    return $self;
}


1;
