#!/usr/bin/perl -w
BEGIN { unshift(@INC,"../lib") if -d "../lib"; unshift(@INC,"lib") if -d "lib"; }
use Net::ActiveDirectory;
use Net::LDAP;
use Net::DNS;
use Data::Dumper;
use strict;

################################################################################
#                                                                              #
#                                                                              #
sub ip2n{
    return unpack N => pack CCCC => split /\./ => shift;
}

sub n2ip{
    return join('.',map { ($_[0] >> 8*(3-$_)) % 256 } 0 .. 3);
}

sub dig{
    my ($record, $type) = (@_);
    my $res   = Net::DNS::Resolver->new;
    my $query = $res->search($record);
    my $result = [];
    if ($query) {
        foreach my $rr ($query->answer) {
            next unless $rr->type eq $type;
            push(@{ $result },$rr->address) if($type eq 'A');
            push(@{ $result },$rr->ptrdname) if($type eq 'PTR');
        }
#    }else{
#        warn "query failed: ", $res->errorstring, "\n";
    }
    return join(",",@{ $result });
}

sub lab_ip{
    my $number = shift;
    my $start_lab=ip2n("192.168.16.0");
    return n2ip($start_lab+$number);
}

sub cao_ip{
    my $number = shift;
    my $start_cao=ip2n("10.100.1.0");
    return n2ip($start_cao+(($number-1)*4));
}

sub cao_gw{
    my $number = shift;
    my $start_cao=ip2n("10.100.1.0");
    return n2ip($start_cao+(($number-1)*4)+1);
}

sub cao_cl{
    my $number = shift;
    my $start_cao=ip2n("10.100.1.0");
    return n2ip($start_cao+(($number-1)*4)+2);
}

sub cao_bc{
    my $number = shift;
    my $start_cao=ip2n("10.100.1.0");
    return n2ip($start_cao+(($number-1)*4)+3);
}


sub network{
    my $number = shift;
    my $name;
    if($number < 10){ 
        $name="inst000$number"; 
    }elsif($number < 100){ 
        $name="inst00$number"; 
    }elsif($number < 1000){ 
        $name="inst0$number"; 
    }
    return $name;
}

sub soekris{
    my $number = shift;
    my $name;
    if($number < 10){ 
        $name="skrs000$number"; 
    }elsif($number < 100){ 
        $name="skrs00$number"; 
    }elsif($number < 1000){ 
        $name="skrs0$number"; 
    }
    return $name;
}

sub printer{
    my $number = shift;
    my $name;
    if($number < 10){ 
        $name="prnt000$number"; 
    }elsif($number < 100){ 
        $name="prnt00$number"; 
    }elsif($number < 1000){ 
        $name="prnt0$number"; 
    }
    return $name;
}

sub padded{
    my $number = shift;
    my $name;
    if($number < 10){ 
        $name="000$number"; 
    }elsif($number < 100){ 
        $name="00$number"; 
    }elsif($number < 1000){ 
        $name="0$number"; 
    }
    return $name;
}

sub remove{
    my ($name, $type, $expected)=(@_);
    my $domain="eftdomain.net";
    my $basedn="dc=".join(',dc=',split(/\./,$domain));
    my $userid=$ENV{'WINDOWS_USERNAME'};
    my $passwd=$ENV{'WINDOWS_PASSWORD'};
    my $ad = Net::ActiveDirectory->new({ 'domain'   => $domain, 'username' => $userid, 'password' => $passwd, });
    unless(defined($ad)){ print STDERR "$ad not defined\n"; return undef; }

    my $record = dig($name,$type);
    foreach my $r (split(/,/,$record)){
        if($r eq $expected){
            print STDERR "DELETE: $name IN $type $r\n";
            $ad->delrecord("$name IN $type $r");
        }
    }
}
#                                                                              #

sub ensure{
    my ($name, $type, $expected)=(@_);
    my $domain="eftdomain.net";
    my $basedn="dc=".join(',dc=',split(/\./,$domain));
    my $userid=$ENV{'WINDOWS_USERNAME'};
    my $passwd=$ENV{'WINDOWS_PASSWORD'};
    my $ad = Net::ActiveDirectory->new({ 'domain'   => $domain, 'username' => $userid, 'password' => $passwd, });
    unless(defined($ad)){ print STDERR "$ad not defined\n"; return undef; }
    my $record = dig($name,$type);
    if($record ne $expected){
        print $name."'s $type is '$record' not '$expected'\n";
        if( -z $record){
            print STDERR "ADD $name IN $type $expected";
            $ad->addrecord( "$name IN $type $expected");
        }else{
            # delete all the bad records
            foreach my $badrecord(split(/,/,$record)){
                print STDERR "DELETE: $name IN $type $badrecord\n";
                $ad->delrecord("$name IN $type $badrecord");
            }
            print STDERR "ADD $name IN $type $expected\n";
            $ad->addrecord("$name IN $type $expected");
        }
        print "\n";
    }
}
#                                                                              #
#                                                                              #
################################################################################


################################################################################
# Set up the AD (and ldap) connections
my $domain="eftdomain.net";
my $basedn="dc=".join(',dc=',split(/\./,$domain));
my $userid=$ENV{'WINDOWS_USERNAME'};
my $passwd=$ENV{'WINDOWS_PASSWORD'};

################################################################################
# Set up the AD (and ldap) connections

my $ldap = Net::LDAP->new("ldaps://ldap.${domain}");
my $mesg = $ldap->bind( "uid=$userid,ou=People,$basedn", password => $passwd );
if($mesg->code){ 
    print STDERR $mesg->error."\n";
    exit 0;
}

################################################################################
# enable debugging or this seems to hang forever with no output

my ($ad_dns, $ou_networks, $ou_hosts) = (1, 1, 0);
#for(my $number=1; $number<=213; $number++){
for(my $number=60; $number<=100; $number++){
    if($ad_dns){
        ############################################################################
        # fix dns, remove from prod, add to cao and lab
        #
        ############################################################################
        remove(soekris($number).".$domain",     "A",   lab_ip($number));
    
        ensure(soekris($number).".lab.$domain", "A",   lab_ip($number));
        ensure(lab_ip($number),                 "PTR", soekris($number).".lab.$domain");
    
        ensure(soekris($number).".cao.$domain", "A",   cao_gw($number));
        ensure(cao_gw($number),                 "PTR", soekris($number).".cao.$domain");
    
        ensure(printer($number).".cao.$domain", "A",   cao_cl($number));
        ensure(cao_cl($number),                 "PTR", printer($number).".cao.$domain");
    
    }
    if($ou_networks){
        ############################################################################
        # fix ou=Networks
        #
        ############################################################################
        my $network = network($number);
        my $result = $ldap->search( 'base' => "ou=networks,$basedn", 'filter' => "cn=$network", 'scope' => 'one' );
        my @entries = $result->entries;
        if($#entries > 0){ warn "multiple entries for cn=$network\n"; }
        if($#entries == 0){ 
            foreach my $entry (@entries) { 
                $entry->replace( 
                                 'objectClass'     => [ 'ipSubnet','top' ],
                                 'gatewayIpNumber' => cao_gw($number),
                                 'ipNetmaskNumber' => '255.255.255.252',
                                 'description'     => 'instant-issue network '.padded($number),
                                 'ipHostNumber'    => cao_ip($number),
                                 'cn'              => network($number),
                               );
                $entry->update ( $ldap );
            }
        }else{
            my $entry = Net::LDAP::Entry->new();
            $entry->dn("cn=$network,ou=Networks,$basedn");
            $entry->add( 
                         'objectClass'     => [ 'ipSubnet','top' ],
                         'gatewayIpNumber' => cao_gw($number),
                         'ipNetmaskNumber' => '255.255.255.252',
                         'description'     => 'instant-issue network '.padded($number),
                         'ipHostNumber'    => cao_ip($number),
                         'cn'              => network($number),
                       );
               $entry->update ( $ldap );
        }
    }
    if($ou_hosts){
        ############################################################################
        # fix ou=Hosts
        #
        ############################################################################
        my $soekris = soekris($number);
        my $result = $ldap->search( 'base' => "ou=hosts,$basedn", 'filter' => "cn=$soekris", 'scope' => 'one' );
        my @entries = $result->entries;
        if($#entries > 0){ warn "multiple entries for cn=$soekris\n"; }
        if($#entries == 0){ 
            foreach my $entry (@entries) { 
    #            $entry->replace( 
    #                             'objectClass'     => [ 'ipSubnet','top' ],
    #                             'gatewayIpNumber' => cao_gw($number),
    #                             'ipNetmaskNumber' => '255.255.255.252',
    #                             'description'     => 'instant-issue network '.padded($number),
    #                             'ipHostNumber'    => cao_ip($number),
    #                             'cn'              => network($number),
    #                           );
    #            $entry->update ( $ldap );
                $entry->dump;
            }
        }else{
            my $entry = Net::LDAP::Entry->new();
            $entry->dn("cn=$soekris,ou=Hosts,$basedn");
    #        $entry->add( 
    #                     'objectClass'     => [ 'ipSubnet','top' ],
    #                     'gatewayIpNumber' => cao_gw($number),
    #                     'ipNetmaskNumber' => '255.255.255.252',
    #                     'description'     => 'instant-issue network '.padded($number),
    #                     'ipHostNumber'    => cao_ip($number),
    #                     'cn'              => network($number),
    #                   );
    #       $entry->update ( $ldap );
            $entry->dump;
        }
    }

}
