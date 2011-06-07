package Net::ActiveDirectory::DNSRecord::WINS;
use parent Net::ActiveDirectory::DNSRecord::Base;
# This is incomplete. Apparently you can stack multiple wins IPs  
# and I'm not sure what the other fields are.
# 0000 1000 2000 0000 4830 0000 2000 0000 0c8a70a3 0c8a10e2
# |    |    |         |         |         |        |
# |    |    |         |         |         |        Second IP
# |    |    |         |         |         |
# |    |    |         |         |         First IP
# |    |    |         |         |
# |    |    |         |         Number of WINS Servers that follow: (removing one decreases this)
# |    |    |         |
# |    |    |         0x348 == 900 == 0D:0H:15M:0S (cache time-out) [DDDDD::HH.MM.SS]
# |    |    |
# |    |    0x0002 == 2 == 0D:0H:0M:2s [DDDDD::HH.MM.SS] (maybe?)
# |    |
# |    0x0001 == Do not replicate this data checked, so this may be a flag field
# |    
# no idea... flags maybe

sub zoneform{ # this will need to be overridden
    my $self = shift;
    my $type = __PACKAGE__;
    $type=~s/.*:://;
    #return "unparsed: IN $type $self->{'number'} [$self->{'hexdata'}]";
    return ";unparsed: IN $type $self->{'hexdata'}";
}

# No idea what this is...
#sub decode{
#    my $self = shift;
#    return undef unless $self->{'hexdata'};
#    $self->{'number'}=unpack('N',pack('h*',$self->{'hexdata'}));
#    return $self;
#}


sub hexdata  { my $self = shift; $self->{'hexdata'}  = shift if @_; return $self->{'hexdata'};  }

#sub zoneform{
#    # IN A 172.16.0.2
#    my $self = shift;
#    return ";IN WINS ".$self->wins;
#}
#
#sub decode{
#    my $self = shift;
#    return undef unless $self->{'hexdata'};
#    $self->{'wins'}=$self->n2ip(unpack('N',pack('h8',$self->{'hexdata'})));
#    return $self;
#}
#
#sub encode{
#    my $self = shift;
#    return undef unless $self->{'textdata'};
#    $self->{'wins'}=$self->{'textdata'};
#    $self->{'hexdata'} = unpack("h8",pack('N',$self->ip2n($self->{'textdata'})));
#    return $self;
#}
#
#sub wins  { my $self = shift; $self->{'wins'} = shift if @_; return $self->{'wins'}; }
#sub hexdata  { my $self = shift; $self->{'hexdata'} = shift if @_; return $self->{'hexdata'}; }
1;
