#!/usr/bin/perl -w
# hat-tip http://www.indented.co.uk/index.php/2009/06/18/mapping-the-dnsrecord-attribute/
use Net::LDAP;
use Data::Dumper;
use strict;

package DNS::ActiveDirectory;
use MIME::Base64;
use Config;
my $debug=0;
print "short == $Config{shortsize}\n" if $debug;
print "int   == $Config{intsize}\n" if $debug;

sub new{
    my $class = shift;
    my $cnstr = shift if @_;
    my $self = {};
    bless $self, $class;
    if($cnstr->{'username'}){ $self->username($cnstr->{'username'}) };
    if($cnstr->{'password'}){ $self->password($cnstr->{'password'}) };

    if($cnstr->{'domain'}){ $self->domain($cnstr->{'domain'}) };

    if($cnstr->{'dns_base'}){ 
        $self->dns_base($cnstr->{'dns_base'});
    }else{
        $self->dns_base("dc=".$self->domain.",cn=MicrosoftDNS,cn=System,".$self->basedn);
    }
    
    $self->{'ldap'} = Net::LDAP->new( $self->domain ) or return undef;
    $self->{'mesg'} = $self->{'ldap'}->bind( 
                                             $self->username.'@'.$self->domain, 
                                             password => $self->password
                                           );

    #if($cnstr->{'data'}){ $self->decode($cnstr->{'data'}); }
    return $self;
}

sub lookup{
    my $self=shift;
    my $query=shift if @_;
    return undef unless $query; 
    my $mesg = $ldap->search( 
                              base   => $creds->{'basedn'},
                              filter => "(&(objectClass=dnsNode)(dc=$query))",
                            );
    print STDERR $mesg->error if $mesg->code;
    foreach my $entry ($mesg->entries){
        my @dcs = $entry->get_value('dc');
        if($#dcs > 0){
            print STDERR "multiple ldap entries found for $query\n";
            #print Data::Dumper->Dump([@dcs]);
        }else{
            my @dnsrecords=$entry->get_value('dnsRecord');
            foreach my $dnsrecord (@dnsrecords){
                # decode the MS packed blobs
                my $decoded_record = $self->decode($dnsrecord);
                if($decoded_record->type){
                    if($decoded_record->is_soa){
                         print STDERR Data::Dumper->Dump([$decoded_record->{'rdata'}])."\n";
                    }
                }
            }
        }
    }
}

sub dns_base{
    my $self = shift;
    $self->{'dns_base'} = shift if @_;
    return $self->{'dns_base'};
}

sub basedn{
    my $self = shift;
    $self->{'basedn'} = shift if @_;
    return $self->{'basedn'};
}

sub password{
    my $self = shift;
    $self->{'password'} = shift if @_;
    return $self->{'password'};
}

sub dns_base{
    my $self = shift;
    $self->{'dns_base'} = shift if @_;
    return $self->{'dns_base'};
}

sub domain{
    my $self = shift;
    $self->{'domain'} = shift if @_;
    $self->basedn("dc=".join(",dc=",split(/\./,$self->{'domain'}))) if($self->{'domain'});
    return $self->{'domain'};
}

sub username{
    my $self = shift;
    $self->{'username'} = shift if @_;
    return $self->{'username'};
}

sub ip2n{
    my $self=shift;
    my $ip=shift if @_;
    return unpack('N',pack('CCCC',split(/\./,$ip)));
}

sub n2ip{
    my $self=shift;
    return join('.', map { ($_[0] >> 8*(3-$_)) % 256 } 0 .. 3);
}

############################################################################
# http://www.iana.org/assignments/dns-parameters
#
sub type{
    my $self = shift;
    my $typeint = shift if @_;
    my @types = ( undef, 'A', 'NS', 'MD', 'MF', 'CNAME', 'SOA', 'MB', 'MG', 'MR',
                  'NULL', 'WKS', 'PTR', 'HINFO', 'MINFO', 'MX', 'TXT', 'RP',
                  'AFSDB', 'X25', 'ISDN', 'RT', 'NSAP', 'NSAP-PTR', 'SIG',
                  'KEY', 'PX', 'GPOS', 'AAAA', 'LOC', 'NXT', 'EID', 'NIMLOC',
                  'SRV', 'ATMA', 'NAPTR', 'KX', 'CERT', 'A6', 'DNAME', 'SINK',
                  'OPT', 'APL', 'DS', 'SSHFP', 'IPSECKEY', 'RRSIG', 'NSEC',
                  'DNSKEY', 'DHCID', 'NSEC3', 'NSEC3PARAM', 'Unassigned',
                  'Unassigned', 'Unassigned', 'HIP', 'NINFO', 'RKEY', 'TALINK');
   my $type = $types[$typeint];
   return $type;
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
                   'updated_serial' => 2610102272,
                   'TTL' => 0,
                   'rdata' => unpack('h*',pack('N',$self->ip2n($ip)))
                 };
    my $rawdata = pack("S< S< h4 I< I> h4 I xxxx h*", 
                        ( $record->{'rdata_len'},
                          $record->{'type'},
                          $record->{'unknown_0'},
                          $record->{'updated_serial'},
                          $record->{'TTL'},
                          $record->{'unknown_1'},
                          $record->{'timestamp'},
                          $record->{'rdata'},
                        ));
   my $hexdata = unpack("h*", $rawdata);
   my $mimedata = encode_base64(pack("h*",$hexdata));
   print STDERR Data::Dumper->Dump([$record,$hexdata,$mimedata]); 
   return $rawdata;
}

sub decode{
    my $self = shift;
    my $record={};
    my $rawdata = shift if @_;
    return $self unless $rawdata;
    my $mimedata = encode_base64($rawdata);
    my $hexdata  = unpack("h*",$rawdata);
    (
      $record->{'rdata_len'},
      $record->{'type'},
      $record->{'unknown_0'},
      $record->{'updated_serial'},
      $record->{'TTL'},
      $record->{'unknown_1'},
      $record->{'timestamp'},
      $record->{'rdata'},
    ) = unpack("S< S< h4 I< I> h4 I xxxx h*", $rawdata);
    #           2  2  4  4  4  4  4  4 == 32 bytes

    if($self->type($record->{'type'}) eq 'A'){
        $self->{'a'}=$self->n2ip(unpack('I>4',pack('h*',$self->{'record'}->{'rdata'})));
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
        ) = unpack("I> I> I> I> I> h h h h*", pack("h*",$self->{'record'}->{'rdata'}));
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
