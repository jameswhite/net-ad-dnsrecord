package Net::ActiveDirectory::DNSRecord::Base;
sub new{
    my $class = shift;
    my $cnstr = shift if @_;
    my $self = {};
    bless $self, $class;

    if($cnstr->{'hexdata'}){
        $self->hexdata($cnstr->{'hexdata'});
        $self->decode();
    }

    if($cnstr->{'textdata'}){
        $self->textdata($cnstr->{'textdata'});
        $self->encode();
    }
    return $self;
}

sub zoneform{ # this will need to be overridden
    my $self = shift;
    my $type = __PACKAGE__;
    $type=~s/.*:://;
    return "unparsed: IN $type ".$self->hexdata;
}

sub decode{ # this will need to be overridden
    my $self = shift;
    return undef unless $self->{'hexdata'};
    return $self;
}

# some common methods for packing, un-packing
sub ip2n{
    my $self=shift;
    my $ip=shift if @_;
    return unpack('N',pack('CCCC',split(/\./,$ip)));
}

sub n2ip{
    my $self=shift;
    return join('.',map { ($_[0] >> 8*(3-$_)) % 256 } 0 .. 3);
}

sub pack_text{
    my $self = shift;
    my $text = shift if @_;
    return undef unless $text;
    $text=~s/\.$//;
    my @parts=split(/\./,$text);
    my $fullhex='';
    my $full_length=0;

    foreach my $part (@parts){
        my $hexlength = unpack("h*",pack('c',length($part)));
        my $hex=$hexlength; 
        $full_length+=length($part);
        $hex.= unpack("h*",pack("a*",$part));
        $fullhex .= $hex;
    }

    #$fullhex = unpack("h*",pack("c c",$full_length + $#parts + 2, $#parts + 1)).$fullhex."00";
    my $adjusted_length = $full_length + $#parts + 2;
    $fullhex = unpack("h*",pack("c c",$adjusted_length , $#parts + 1)).$fullhex."00";
    return $fullhex;
}

sub unpack_text{
    my $self = shift;
    my $hex_text = shift if @_;
    return undef unless $hex_text;
    my $label_length;
    my ($length, $numlabels, $remainder) = unpack("c c h*", pack("h*",$hex_text));
    my ($trash1, $trash2, $rawtext) = unpack("c c a*", pack("h*",$hex_text));
    #print STDERR "$numlabels labels in $length bytes [$rawtext]\n";
    my $text='';
    my $append='';
    for(my $i=0;$i<$numlabels;$i++){
        ($label_length, $remainder) = unpack("c h*", pack("h*",$remainder));
        ($append, $remainder) = unpack("a$label_length h*",pack("h*",$remainder));
        $text.="$append.";
    #    print STDERR "Unpacked $label_length bytes of $remainder => [$text]\n";
    }
    return $text;
}

sub hexdata  { my $self = shift; $self->{'hexdata'}  = shift if @_; return $self->{'hexdata'};  }
sub textdata { my $self = shift; $self->{'textdata'} = shift if @_; return $self->{'textdata'}; }
1;
