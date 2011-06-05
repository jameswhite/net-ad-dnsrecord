package Net::ActiveDirectory::DNSRecord;
# hat-tip http://www.indented.co.uk/index.php/2009/06/18/mapping-the-dnsrecord-attribute/
use Net::ActiveDirectory::DNSRecord::Reserved_for_Private_Use;
use Net::ActiveDirectory::DNSRecord::Standards_Action;
use Net::ActiveDirectory::DNSRecord::A;
use Net::ActiveDirectory::DNSRecord::CNAME;
use Net::ActiveDirectory::DNSRecord::MX;
use Net::ActiveDirectory::DNSRecord::NS;
use Net::ActiveDirectory::DNSRecord::PTR;
use Net::ActiveDirectory::DNSRecord::SOA;
use Net::ActiveDirectory::DNSRecord::SRV;
use Net::ActiveDirectory::DNSRecord::TXT;
# We need a lot more sub-modules here but these are the ones I need to decode right now...

use Data::Dumper;
use MIME::Base64;
use strict;

sub new {
    my $class = shift;
    my $binarydata = shift if @_;
    my $self = {};
    bless $self, $class;
    $self->decode($binarydata) if $binarydata;
    return $self;
}

sub craft {
    my $class = shift;
    my $cnstr = shift if @_;
    my $self = {};
    bless $self, $class;
    $self->encode({'type' => $cnstr->{'type'}, 'textdata' => $cnstr->{'textdata'} }) if $cnstr;
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
    my @types = ( "Standards_Action", 'A', 'NS', 'MD', 'MF', 'CNAME', 'SOA', 
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
    my @types = ( "Standards_Action", 'A', 'NS', 'MD', 'MF', 'CNAME', 'SOA', 
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
       $type = "IETF_Review" unless $type;
   }
   if (($self->{'int_type'} >= 128)&& ($self->{'int_type'} <= 253)){
       $type = "IETF_Review" unless $type;
   }
   if (($self->{'int_type'} >= 256)&& ($self->{'int_type'} <= 32767)){
       $type = "IETF_Review" unless $type;
   }
   if (($self->{'int_type'} >= 32768)&& ($self->{'int_type'} <= 57343)){
       $type = "Specification_Required" unless $type;
   }
   if (($self->{'int_type'} >= 57344)&& ($self->{'int_type'} <= 65279)){
       $type = "Specification_Required" unless $type;
   }
   if (($self->{'int_type'} >= 65280)&& ($self->{'int_type'} <= 65534)){
       $type = "Reserved_for_Private_Use" unless $type;
   }
   if ($self->{'int_type'} == 65535){
       $type = "Standards_Action" unless $type;
   }
   return $type;
}

sub update_at_serial{
    my $self = shift;
    return $self->{'update_at_serial'} if $self->{'update_at_serial'};
    return undef;
}

sub raw_record{ # just so we don't store rawdata and corrupt our tty 
    my $self = shift;
    return pack("h*",$self->{'hexdata'}) if $self->{'hexdata'};
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
      $self->{'unknown_0'}, # not sure what this is for '500f' (0xf005)
      $self->{'update_at_serial'},
      $self->{'TTL'},
      $self->{'unknown_1'}, # not sure what this is for 'e001' (0x100e)
      $self->{'timestamp'}, ## 0 if static
      $self->{'rdata_hex'},
    ) = unpack("S S h4 I I h4 I xxxx h*", $rawdata);
#    #           2  2  4  4  4  4  4  4 == 32 bytes
#    ) = unpack("S< S< h4 I< I> h4 I xxxx h*", $rawdata); # perl 5.10 syntax
    $self->{'type'} = $self->type;
    my $record_pkg = __PACKAGE__.'::'.$self->{'type'};
    $self->{'rdata'} = $record_pkg->new({ hexdata => $self->{'rdata_hex'} });
    return $self;
}

sub encode{
    my $self = shift;
    my $args = shift if @_;
    my $record_pkg = undef;
    if($args->{'type'}){
        $self->{'type'} = $args->{'type'};
        $record_pkg = __PACKAGE__.'::'.$args->{'type'};
        $self->{'rdata'} = $record_pkg->new({ textdata => $args->{'textdata'} });
    }
    $self->{'rdata_len'}=length(pack("h*",$self->{'rdata'}->hexdata));
    $self->{'int_type'} = $self->int_type;
    $self->{'unknown_0'} = '500f';
    $self->{'update_at_serial'} = 0,
    $self->{'TTL'} = 0;
    $self->{'unknown_1'} = 'e001';
    $self->{'timestamp'} = 0;
    $self->{'rdata_hex'} = $self->{'rdata'}->hexdata;
    return $self;
}

sub hexdata  {
    my $self = shift; 
    #print Data::Dumper->Dump([$self]);
    my $rawdata = pack("S S h4 I I h4 I h4 h*", (
                                                    $self->{'rdata_len'},
                                                    $self->{'int_type'},
                                                    $self->{'unknown_0'},
                                                    $self->{'update_at_serial'},
                                                    $self->{'TTL'},
                                                    $self->{'unknown_1'},
                                                    $self->{'timestamp'},
                                                    '0000',
                                                    $self->{'rdata_hex'},
                                                ));
    $self->{'hexdata'} = unpack("h*",$rawdata);
    return $self->{'hexdata'};          
}

sub update_at_serial{ my $self = shift; $self->{'update_at_serial'} = shift if @_; return $self->{'update_at_serial'}; }
sub serial   {        my $self = shift; $self->{'update_at_serial'} = shift if @_; return $self->{'update_at_serial'}; }
sub rdata_len{        my $self = shift; $self->{'rdata_len'} = shift if @_;        return $self->{'rdata_len'};        }
sub rdata_hex{        my $self = shift; $self->{'rdata_hex'} = shift if @_;        return $self->{'rdata_hex'};        }
sub rdata    {        my $self = shift; $self->{'rdata'}     = shift if @_;        return $self->{'rdata'};            }
sub timestamp{        my $self = shift; $self->{'timestamp'} = shift if @_;        return $self->{'timestamp'};        }
sub rdata_hex{        my $self = shift; $self->{'rdata_hex'} = shift if @_;        return $self->{'rdata_hex'};        }
sub unknown_0{        my $self = shift; $self->{'unknown_0'} = shift if @_;        return $self->{'unknown_0'};        }
sub unknown_1{        my $self = shift; $self->{'unknown_1'} = shift if @_;        return $self->{'unknown_1'};        }
1;
