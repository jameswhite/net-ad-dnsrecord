#!/usr/bin/perl
# This works for an unpack("h*",data), if you use 'H*' 
# you'll need to unpack("h*",pack("H*", $it)) first.

my @times=(
            "008ed247b4ea2a10",
            "0a1281077252cc10",
            "2ddd47377252cc10",
            "cbc541777252cc10",
            "624cfba77252cc10",
            "44d89ee77252cc10",
            "cc9a68287252cc10",
            "ea6048587252cc10",
            "60ae7e887252cc10",
);

sub nt2unix{
    my $nt_time = shift;
    my($lo,$hi) = unpack('VV',pack('h8h8',unpack('A8A8',pack('A16',$nt_time))));
    return ( ( ( $hi * 2**32 + $lo ) - 116444736e9 ) / 1e7 );
}

sub unix2nt{
    my $unix_time = shift;
    print STDERR "::::::::::::::::::::::::::::: ". $unix_time ."\n";
    my $bigtime=(($unix_time * 1e7) + 116444736e9);
    print STDERR "::::::::::::::::::::::::::::: ". $bigtime ."\n";
    my $hi = int($bigtime/2**32);
    print STDERR "::::::::::::::::::::::::::::: ". $hi ."\n";
    my $lo = $bigtime - ($hi * 2**32);
    print STDERR "::::::::::::::::::::::::::::: ". $lo ."\n";
    my $nt_time = unpack('A16',pack('A8A8',unpack("h8h8",pack('VV',($lo,$hi)))));
    return $nt_time;
}

#sub unix2nt{
#    my $unix_time=shift;
#    my $bigtime=(($unix_time * 1e7) + 116444736e9);
#    my $hi = int($bigtime/2**32);
#    my $lo = $bigtime - ($hi * 2**32);
#    my $nt_time = unpack('A16',pack('A8A8',unpack("h8h8",pack('VV',($lo,$hi)))));
#    return $nt_time;
#}

foreach my $time (@times){
    print $time." -> ".int(nt2unix($time))." -> ".scalar(localtime(int(nt2unix($time))))." -> ".unix2nt(nt2unix($time))."\n";
}

