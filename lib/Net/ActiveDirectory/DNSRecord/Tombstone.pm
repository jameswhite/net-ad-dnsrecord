package Net::ActiveDirectory::DNSRecord::Tombstone;
use parent Net::ActiveDirectory::DNSRecord::Base;

sub nt2unix{
    my $self = shift;
    my $nt_time = shift;
    my($lo,$hi) = unpack('VV',pack('h8h8',unpack('A8A8',pack('A16',$nt_time))));
    return ( ( ( ($hi * 2**32) + $lo ) - 116444736000000000 ) / 10000000 );
}

sub unix2nt{
    my $self = shift;
    my $unix_time = shift;
    my $bigtime=( ($unix_time * 10000000) + 116444736000000000 );
    my $hi = int($bigtime/2**32);
    my $lo = $bigtime - ($hi * 2**32);
    my $nt_time = unpack('A16',pack('A8A8',unpack("h8h8",pack('VV',($lo,$hi)))));
    return $nt_time;
}

sub zoneform{
    # IN A 172.16.0.2
    my $self = shift;
    return "; Tombstoned ". scalar localtime($self->{'unixtime'});
}

sub decode{
    my $self = shift;
    return undef unless $self->{'hexdata'};
    $self->{'unixtime'} = $self->nt2unix($self->{'hexdata'});
    return $self;
}

sub encode{
    my $self = shift;
    return undef unless $self->{'textdata'};
    $self->{'unixtime'}=$self->{'textdata'};
    $self->{'hexdata'} = $self->unix2nt($self->{'unixtime'});
    return $self;
}

sub unixtime  { my $self = shift; $self->{'unixtime'} = shift if @_; return $self->{'unixtime'}; }
sub hexdata  { my $self = shift; $self->{'hexdata'} = shift if @_; return $self->{'hexdata'}; }
1;
