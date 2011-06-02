#!/usr/bin/perl -w
# hat-tip http://www.indented.co.uk/index.php/2009/06/18/mapping-the-dnsrecord-attribute/
package DNS::ActiveDirectory::DNSRecord;
use strict;
use Data::Dumper;
use MIME::Base64;
use Config;

#my $debug=0;
#print "short == $Config{shortsize}\n" if $debug;
#print "int   == $Config{intsize}\n" if $debug;

sub new{
    my $class = shift;
    my $binarydata = shift if @_;
    my $self = {};
    bless $self, $class;
    $self->decode($binarydata) if $binarydata;
    return $self;
}

sub ip2n{
    my $self=shift;
    my $ip=shift if @_;
    return unpack('N',pack('CCCC',reverse(split(/\./,$ip))));
}

sub n2ip{
    my $self=shift;
    return join('.',map { ($_[0] >> 8*(3-$_)) % 256 } 0 .. 3);
}

############################################################################
# http://www.iana.org/assignments/dns-parameters
#
sub int_type{
    my $self = shift;
    my @types = ( "Standards Action", 'A', 'NS', 'MD', 'MF', 'CNAME', 'SOA', 
                  'MB', 'MG', 'MR', 'NULL', 'WKS', 'PTR', 'HINFO', 'MINFO', 
                  'MX', 'TXT', 'RP', 'AFSDB', 'X25', 'ISDN', 'RT', 'NSAP', 
                  'NSAP-PTR', 'SIG', 'KEY', 'PX', 'GPOS', 'AAAA', 'LOC', 
                  'NXT', 'EID', 'NIMLOC', 'SRV', 'ATMA', 'NAPTR', 'KX', 
                  'CERT', 'A6', 'DNAME', 'SINK', 'OPT', 'APL', 'DS', 'SSHFP', 
                  'IPSECKEY', 'RRSIG', 'NSEC', 'DNSKEY', 'DHCID', 'NSEC3', 
                  'NSEC3PARAM', 'Unassigned', 'Unassigned', 'Unassigned', 
                  'HIP', 'NINFO', 'RKEY', 'TALINK');
    for(my $i=0;$i<=$#types; $i++){
        return $i if(lc($self->type) eq lc($types[$i]));
    }
}

sub type{
    my $self = shift;
    return $self->{'type'} if $self->{'type'};
    my @types = ( "Standards Action", 'A', 'NS', 'MD', 'MF', 'CNAME', 'SOA', 
                  'MB', 'MG', 'MR', 'NULL', 'WKS', 'PTR', 'HINFO', 'MINFO', 
                  'MX', 'TXT', 'RP', 'AFSDB', 'X25', 'ISDN', 'RT', 'NSAP', 
                  'NSAP-PTR', 'SIG', 'KEY', 'PX', 'GPOS', 'AAAA', 'LOC', 
                  'NXT', 'EID', 'NIMLOC', 'SRV', 'ATMA', 'NAPTR', 'KX', 
                  'CERT', 'A6', 'DNAME', 'SINK', 'OPT', 'APL', 'DS', 'SSHFP', 
                  'IPSECKEY', 'RRSIG', 'NSEC', 'DNSKEY', 'DHCID', 'NSEC3', 
                  'NSEC3PARAM', 'Unassigned', 'Unassigned', 'Unassigned', 
                  'HIP', 'NINFO', 'RKEY', 'TALINK');
   my  $type = $types[$self->{'int_type'}];
   if (($self->{'int_type'} >= 1)&& ($self->{'int_type'} <= 127)){
       $type = "IETF Review" unless $type;
   }
   if (($self->{'int_type'} >= 128)&& ($self->{'int_type'} <= 253)){
       $type = "IETF Review" unless $type;
   }
   if (($self->{'int_type'} >= 256)&& ($self->{'int_type'} <= 32767)){
       $type = "IETF Review" unless $type;
   }
   if (($self->{'int_type'} >= 32768)&& ($self->{'int_type'} <= 57343)){
       $type = "Specification Required" unless $type;
   }
   if (($self->{'int_type'} >= 57344)&& ($self->{'int_type'} <= 65279)){
       $type = "Specification Required" unless $type;
   }
   if (($self->{'int_type'} >= 65280)&& ($self->{'int_type'} <= 65534)){
       $type = "Reserved for Privete Use" unless $type;
   }
   if ($self->{'int_type'} == 65535){
       $type = "Standards Action" unless $type;
   }
   return $type;
}

sub update_at_serial{
    my $self = shift;
    return $self->{'update_at_serial'} if $self->{'update_at_serial'};
    return undef;
}

sub a_record{
    my $self = shift; 
    my $ip = shift if @_;
    return undef unless $ip;
    my $record = {
                   'unknown_1' => 'e001',
                   'unknown_0' => '500f',
                   'rdata_len' => 4,
                   'timestamp' => 0,
                   'type' => 1,
                   'update_at_serial' => 2610102272,
                   'TTL' => 0,
                   'rdata' => unpack('h*',pack('N',$self->ip2n($ip)))
                 };
    my $rawdata = pack("S< S< h4 I< I> h4 I xxxx h*", 
                        ( $record->{'rdata_len'},
                          $record->{'type'},
                          $record->{'unknown_0'},
                          $record->{'update_at_serial'},
                          $record->{'TTL'},
                          $record->{'unknown_1'},
                          $record->{'timestamp'},
                          $record->{'rdata'},
                        ));
   my $hexdata = unpack("h*", $rawdata);
   my $mimedata = encode_base64(pack("h*",$hexdata));
   return $rawdata;
}

sub create{
    my $self = shift;
    my $cnstr = shift;
    if($cnstr->{'type'} eq 'A'){
        $self->{'rdata_len'} = 4;
        $self->{'int_type'} = 1;
        $self->{'unknown_0'} = '500f';
        $self->{'update_at_serial'} = $cnstr->{'serial'};
        $self->{'TTL'} = 0;
        $self->{'unknown_1'}='e001';
        $self->{'timestamp'}=0;
        $self->{'rdata_hex'} = unpack("h*",pack("I",$self->ip2n($cnstr->{'address'})));
    }
    my $rawdata = pack(
                        "S S h4 I N h4 I xxxx h*",
                        $self->{'rdata_len'},
                        $self->{'int_type'},
                        $self->{'unknown_0'},
                        $self->{'update_at_serial'},
                        $self->{'TTL'},
                        $self->{'unknown_1'},
                        $self->{'timestamp'},
                        $self->{'rdata_hex'},
                      );
    $self->{'hexdata'} = unpack("h*",$rawdata)."\n";
    chomp($self->{'hexdata'});
    return $self;
}

sub raw_record{ # just so we don't store rawdata and corrupt our tty 
    my $self = shift;
    return pack("h*",$self->{'hexdata'}) if $self->{'hexdata'};
    return undef;
}

sub attr{
    my $self = shift;
    my $attribute = shift if @_;
    return $self->{$attribute} if $self->{$attribute};
    return $self->{'rdata'}->{$attribute} if $self->{'rdata'}->{$attribute};
    return undef;
}


sub decode{
    my $self = shift;
    my $rawdata = shift if @_;
    return $self unless $rawdata;
    my $mimedata = encode_base64($rawdata);
    my $hexdata  = unpack("h*",$rawdata);
    $self->{'hexdata'} = $hexdata;
    (
      $self->{'rdata_len'},
      $self->{'int_type'},
      $self->{'unknown_0'},
      $self->{'update_at_serial'},
      $self->{'TTL'},
      $self->{'unknown_1'},
      $self->{'timestamp'},
      $self->{'rdata_hex'},
    ) = unpack("S S h4 I N h4 I xxxx h*", $rawdata);
#    #           2  2  4  4  4  4  4  4 == 32 bytes
#    ) = unpack("S< S< h4 I< I> h4 I xxxx h*", $rawdata); # perl 5.10 syntax
    $self->{'type'}=$self->type;
    if($self->{'type'} eq 'A'){
        $self->{'address'}=$self->n2ip(unpack('N',pack('h*',$self->{'rdata_hex'})));
    }elsif($self->type eq 'SOA'){
        (
          $self->{'rdata'}->{'serial'},
          $self->{'rdata'}->{'refresh'},
          $self->{'rdata'}->{'retry'},
          $self->{'rdata'}->{'expire'},
          $self->{'rdata'}->{'min_TTL'},
          $self->{'rdata'}->{'length'},
          $self->{'rdata'}->{'numlabels'},
          $self->{'rdata'}->{'labellen'},
          $self->{'rdata'}->{'soatext'},
#        ) = unpack("I> I> I> I> I> h h h h*", pack("h*",$self->{'record'}->{'rdata'}));
        ) = unpack("N N N N N h h h h*", pack("h*",$self->{'rdata_hex'}));
          my $textraw = unpack("a*",pack("h*",$self->{'rdata'}->{'soatext'}));
          ######################################################################
          # Here are some of the soa record packs I've seen:
          # foo<TAB>example<ETX>org<NULL><BEL><SOH><ENQ>admin<NULL>
          # foo<TAB>example<ETX>org<NULL><NAK><ETX><ENQ>admin<TAB>example<ETX>org<NULL>
          ######################################################################
          my $nul = pack("h*","00"); 
          my $soh = pack("h*","10"); 
          my $ext = pack("h*","30"); 
          my $enq = pack("h*","50"); 
          my $bel = pack("h*","70"); 
          my $tab = pack("h*","90"); 
          my $nak = pack("h*","51"); 

          # split on ENQ
          my ($host, $person) = split(/$enq/, $textraw);
          # tabs seem to separate host parts from domain parts
          $host=~s/$tab/\./g;  $person=~s/$tab/\./g;
          # ETX seems to delimit domains (e.g. example.org example<ETX>org)
          $host=~s/$ext/\./g;  $person=~s/$ext/\./g;
          # inore everything after the NUL character as they appear to terminate records
          $host=~s/$nul.*//g;  $person=~s/$nul.*//g; 
          # the rest of this is unknown, so we can't write an soa until we decode it
          #$host=~s/$soh/?/g;  $person=~s/$soh/?/g;
          #$host=~s/$enq/?/g;  $person=~s/$enq/?/g;
          #$host=~s/$bel/?/g;  $person=~s/$bel/?/g;
          #$host=~s/$nak/?/g;  $person=~s/$nak/?/g;
          $self->{'rdata'}->{'nameserver'}=$host.".";     # the trailing '.' seems to be implied
          $self->{'rdata'}->{'emailaddress'}=$person."."; # the trailing '.' seems to be implied
    }elsif($self->type eq 'CNAME'){
        (
          $self->{'rdata'}->{'length'}, # length of the first part?
          $self->{'rdata'}->{'numlabels'},
          $self->{'rdata'}->{'labellen'},
          $self->{'rdata'}->{'hexdata'},
        ) = unpack("h h h h*", pack("h*",$self->{'record'}->{'rdata'}));
          my $textraw = unpack("a*",pack("h*",$self->{'rdata'}->{'hexdata'}));
          my $ext=pack("h*","30"); $textraw=~s/$ext/\./g;
          my $null=pack("h*","00"); $textraw=~s/$null//g;
          my ($hostpart,$domainpart)=split(/\t/,$textraw);
          $self->{'cname'}="$hostpart.";
          $self->{'cname'}.="$domainpart." if $domainpart;;
    } 
    return $self;
}

sub cname { 
    my $self = shift; 
    return $self->{'cname'} if $self->{'cname'}; 
    return undef; 
}

sub rdata { 
    my $self = shift; 
    return $self->{'rdata'} if $self->{'rdata'}; 
    return undef; 
}

sub is_soa{ 
    my $self = shift; 
    if($self->type eq 'SOA'){return 1;}
}

sub is_a{ 
    my $self = shift; 
    if($self->type eq 'A'){return 1;}
}

sub is_cname{ 
    my $self = shift; 
    return undef unless $self->type;
    if($self->type eq 'CNAME'){return 1;}
    return 0;
}
1;
