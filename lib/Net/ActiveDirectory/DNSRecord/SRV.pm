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
    #print STDERR "-=[ $self->{'priority'} $self->{'weight'} $self->{'port'} $self->{'srv'} ]=-\n";
    return $self;
}

sub encode{
    my $self = shift;
    return undef unless $self->{'textdata'};
    $self->{'srv'} = $self->{'textdata'};
    $self->{'priority'}=0;
    $self->{'weight'}=0;
    $self->{'port'}=0;
    $self->{'textpart'} .= $self->pack_text($self->{'textdata'});
    return $self;
}

sub hexdata{ 
    my $self = shift; 
    $self->{'hexdata'} = shift if @_; 
    if($self->{'textpart'}){ # should only exist on encode(() ergo only on craft()
        $self->{'hexdata'} = unpack(
                                     "h*",pack( 
                                                "n n n", 
                                                ( 
                                                  $self->{'priority'},
                                                  $self->{'weight'},
                                                  $self->{'port'},
                                                )
                                              )
                                   );
        $self->{'hexdata'}.=$self->{'textpart'};
    }
    return $self->{'hexdata'};
}


sub srv  { 
    my $self = shift; 
    $self->{'srv'} = shift if @_; 
    return $self->{'srv'}; 
}

sub priority  { 
    my $self = shift; 
    $self->{'priority'} = shift if @_; 
    return $self->{'priority'}; 
}

sub weight  { 
    my $self = shift; 
    $self->{'weight'} = shift if @_; 
    return $self->{'weight'}; 
}

sub port  { 
    my $self = shift; 
    $self->{'port'} = shift if @_; 
    return $self->{'port'}; 
}

sub textdata { 
    my $self = shift; 
    $self->{'textdata'} = shift if @_; 
    return $self->{'textdata'}; 
}

1;
