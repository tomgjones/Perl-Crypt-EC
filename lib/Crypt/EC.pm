package Crypt::EC;

use strict;
use bignum;
use feature 'say';

use base 'Exporter';
our @EXPORT_OK = qw(int_to_padded_byte_array);

sub int_to_padded_byte_array {
    my ($x, $len) = @_;

    my @r = int_to_byte_array($x);
    if (@r < $len) {
        unshift @r, map { 0 } (scalar(@r) .. $len - 1);
    }
    return @r;
}

# Convert to bigendian byte array.
# FIXME: think about negative numbers.
sub int_to_byte_array {
    my ($n) = @_;

    if ($n < 0) {
        die "can't do negative numbers yet";
    }

    my @r;
    while ($n > 0) {
        unshift(@r, $n % 256);
        $n = $n >> 8;
    }
    return @r;
}

1;
