package Net::ActiveDirectory::DNSRecord::SOA;
use parent Net::ActiveDirectory::DNSRecord::Base;

sub zoneform{
    my $self = shift;
    return "IN SOA $self->{'soa_host'} $self->{'soa_email'} ( $self->{'serial'}; $self->{'refresh'}; $self->{'retry'}; $self->{'expire'}; $self->{'min_TTL'}; )";
}

sub decode{
    my $self = shift;
    return undef unless $self->{'hexdata'};
    my ( $chars, $length, $parts, $sizelabel, $remainder );
    my $nul = pack("h*","00");
    my $etx = pack("h*","30");
    my $tab = pack("h*","90");
    (
      $self->{'serial'},
      $self->{'refresh'},
      $self->{'retry'},
      $self->{'expire'},
      $self->{'min_TTL'},
      $remainder,
    ) = unpack("N N N N N h*", pack("h*",$self->{'hexdata'}));

    ############################################################################
    # get the host string
    ( $length, $parts, $remainder ) = unpack("c c h*", pack("h*",$remainder));
    for (my $i=0;$i<$parts;$i++){
        ($label_length, $remainder) = unpack("c h*", pack("h*",$remainder));
        ($append, $remainder) = unpack("a$label_length h*",pack("h*",$remainder));
        $text.="$append.";
    #    print STDERR "Unpacked $label_length bytes of $remainder => [$text]\n";
    }
    $self->{'soa_host'}=$text;
    $text=undef;
    (my $null, $remainder) = unpack("h h*",pack("h*",$remainder));
    #
    ############################################################################
 
    ############################################################################
    # get the email string
    ( $length, $parts, $remainder ) = unpack("c c h*", pack("h*",$remainder));
    for (my $i=0;$i<$parts;$i++){
        ($label_length, $remainder) = unpack("c h*", pack("h*",$remainder));
        ($append, $remainder) = unpack("a$label_length h*",pack("h*",$remainder));
        $text.="$append.";
    #    print STDERR "Unpacked $label_length bytes of $remainder => [$text]\n";
    }
    $self->{'soa_email'}=$text;
    $text=undef;
    #
    ############################################################################
    return $self;
}

sub hexdata   { 
    my $self = shift; 
    $self->{'hexdata'} = shift if @_;   
    if($self->{'crafted'}){
        $self->{'hexdata'} = unpack("h*",pack("N N N N N",(
                                                           $self->{'serial'},
                                                           $self->{'refresh'},
                                                           $self->{'retry'},
                                                           $self->{'expire'},
                                                           $self->{'min_TTL'},
                                                         ))
                                 );
        my $host = $self->{'soa_host'};
        $host=~s/\.$//;
        my $hex_host = $self->pack_text($host);
        $self->{'hexdata'}.= $hex_host;
        my $email = $self->{'soa_email'};
        $email=~s/\.$//;
        my $hex_email = $self->pack_text($email);
        $self->{'hexdata'}.= $hex_email;
    }
    return $self->{'hexdata'};   
}

sub encode{
    # this is a null function, all attrs need to be set manually
    my $self = shift;
    $self->{'crafted'}=1;
    return $self;
}

sub textraw   { my $self = shift; $self->{'textraw'} = shift if @_;   return $self->{'textraw'};   }
sub soa_host  { my $self = shift; $self->{'soa_host'} = shift if @_;  return $self->{'soa_host'};  }
sub soa_email { my $self = shift; $self->{'soa_email'} = shift if @_; return $self->{'soa_email'}; }
sub serial    { my $self = shift; $self->{'serial'} = shift if @_;    return $self->{'serial'};    }
sub refresh   { my $self = shift; $self->{'refresh'} = shift if @_;   return $self->{'refresh'};   }
sub retry     { my $self = shift; $self->{'retry'} = shift if @_;     return $self->{'retry'};     }
sub expire    { my $self = shift; $self->{'expire'} = shift if @_;    return $self->{'expire'};    }
sub min_TTL   { my $self = shift; $self->{'min_TTL'} = shift if @_;   return $self->{'min_TTL'};   }


1;
