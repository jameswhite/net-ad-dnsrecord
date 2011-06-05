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

    ( $length, $parts, $sizelabel, $remainder ) = unpack("c c c h*", pack("h*",$remainder));
    $chars = 'a'.($length -1 );
    ( $self->{'soa_host'}, $remainder ) = unpack("$chars h*", pack("h*",$remainder));
    $self->{'soa_host'}=~s/$tab/\./g; $self->{'soa_host'}=~s/$etx/\./g; $self->{'soa_host'}=~s/$nul//g;
    $self->{'soa_host'}.='.';
 
    ( $length, $parts, $sizelabel, $remainder ) = unpack("c c c h*", pack("h*",$remainder));
    $chars = 'a'.($length -1 );
    ( $self->{'soa_email'}) = unpack("$chars", pack("h*",$remainder));
    $self->{'soa_email'}=~s/$tab/\./g; $self->{'soa_email'}=~s/$etx/\./g; $self->{'soa_email'}=~s/$nul//g;
    $self->{'soa_email'}.='.';

    #my $newline = pack("h*","a0");$textraw=~s/$newline/[NEWLINE]/g; # split on newline
    #my $nul = pack("h*","00");$textraw=~s/$nul/          /g;        #split on null
    #my $soh = pack("h*","10");$textraw=~s/$soh/[SOH]/g;
    #my $sub = pack("h*","a1");$textraw=~s/$sub/[SUB]/g;
    #my $ext = pack("h*","30");$textraw=~s/$ext/[ETX]/g;
    #my $enq = pack("h*","50");$textraw=~s/$enq/[ENQ]/g;
    #my $bel = pack("h*","70");$textraw=~s/$bel/[BEL]/g;
    #my $tab = pack("h*","90");$textraw=~s/$tab/[TAB]/g;
    #my $nak = pack("h*","51");$textraw=~s/$nak/[NAK]/g;
    #$textraw=~s/[^a-zA-Z0-9\[\]]/[??]/g;

    ######################################################################
    # Here are some of the soa record packs I've seen:     perhaps:  <length+1><numlabels><sizelabel>
    # <fqdn> [NULL]  [SUB][ETX][NEWLINE]  <fqemail>[NUL]    a130a0  hostmaster[TAB]eftdomain[ETX]net[NUL] : 26 char (inc null) 
    # <fqdn> [NULL]  [NAK][ETX][ENQ]      <fqemail>[NUL]    513050  admin[TAB]eftdomain[ETX]net[NUL]      : 20 char (inc null)
    # <fqdn> [NULL]  [BEL][SOH][ENQ]      <fqemail>[NUL]    701050  admin[NUL]                            : 06 char (inc null)
    #
    # where <fqdn> and <fqemail> take the form:
    #
    # host[TAB]domain[ETX]com  or  user[TAB]domain[ETX]org 
    # 
    ######################################################################
#print $self->zoneform."\n";
    return $self;
}

sub hexdata  { my $self = shift; $self->{'hexdata'} = shift if @_; return $self->{'hexdata'}; }
sub textraw  { my $self = shift; $self->{'textraw'} = shift if @_; return $self->{'textraw'}; }
sub soa_host  { my $self = shift; $self->{'soa_host'} = shift if @_; return $self->{'soa_host'}; }
sub soa_email  { my $self = shift; $self->{'soa_email'} = shift if @_; return $self->{'soa_email'}; }

1;
