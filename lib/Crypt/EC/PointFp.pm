package Crypt::EC::PointFp;

=head1 NAME

Crypt::EC::PointFp - Point on an elliptic curve.

=head1 SYNOPSIS

=head1 DESCRIPTION

A Crypt::EC::PointFp represents a point on an elliptic curve.

All the arithmetic operations such as add() and multiply() return
new Crypt::EC::PointFp objects; they are not mutators.

It stringifies to a comma-separated list of its integer coordinates.

=head2 new($curve, $x, $y, $z)

Constructor.  Takes a Crypt::EC::CurveFp $curve, which is the elliptic
curve on which this point lies; a pair of Crypt::EC::FieldElementFp
coordinates $x and $y which are the x and y field elements; 
and a big integer $z, which is the z coordinate (terminology?) of the point.

=head2 x

Returns the Crypt::EC::FieldElementFp representing the x field element
of this point.

=head2 y

Returns the Crypt::EC::FieldElementFp representing the y field element
of this point.

=head2 z

Returns the big integer representing the z coordinate (terminology?) of 
this point.

=head2 get_x

Returns an integer which is a function of the x coordinate.  
FIXME: what is the meaning or name of this value.

=head2 get_y

Returns an integer which is a function of the y coordinate.  
FIXME: what is the meaning or name of this value.

=head2 multiply($k)

Returns this point multiplied by the integer $k, as a Crypt::EC::PointFp.

=head2 add($b)

Returns the Crypt::EC::PointFp that is the result of adding the
Crypt::EC::PointFp $b to this point.

=head2 negate

Returns the Crypt::EC::PointFp that is the negation of this point.

=head2 twice

Returns the Crypt::EC::PointFp that is the result of the "twice"
operation on this point.

=head2 encode([$compressed])

Returns an array of 8 bit integers encoding this point.  If $compressed
is given (and true), then only the x coordinate is included in the
encoding (the y coordinate can be inferred, so the information is
redundant).  FIXME: this needs more details on what the encoding is.

=head2 curve

Returns the curve on which this point lies, as a Crypt::EC::CurveFp
object.

=head2 is_infinity

Returns true if this point is infinite, and false otherwise.

=cut

use strict;
use bignum;
use integer;
use overload '""' => "to_string";

use Class::InsideOut qw(id readonly private register);
use Crypt::EC qw(int_to_padded_byte_array);

# CurveFp
private curve => my %curve;
# FieldElementFp
private x => my %x;
# FieldElementFp
private y => my %y;
# Just an integer.
private z => my %z;
readonly zinv => my %zinv;

sub new {
    my ($class, $curve, $x, $y, $z) = @_;

    my $self = register $class;
    my $id = id $self;

    $curve{$id} = $curve;
    $x{$id} = $x;
    $y{$id} = $y;
    $z{$id} = $z // 1;
    $zinv{$id} = undef;
    # TODO: compression flag

    return $self;
}

sub x {
    my ($self) = @_;

    return $x{id $self};
}

sub y {
    my ($self) = @_;

    return $y{id $self};
}

sub z {
    my ($self) = @_;

    return $z{id $self};
}

sub to_string {
    my ($self) = @_;

    return join(", ", $self->x->to_int, $self->y->to_int, $self->z);
}

# $k is an integer.
sub multiply {
    my ($self, $k) = @_;
    my $id = id $self;

    return $self if $self->is_infinity;

    return $self->curve->infinity if $k == 0;

    my $h = $k * 3;

    my $r = $self;

    my $neg = $self->negate;

    for (my $i = bitlength($h) - 2; $i > 0; $i--) {

        $r = $r->twice;

        my $hbit = testbit($h, $i);

        my $kbit = testbit($k, $i);

        if ($hbit != $kbit) {
            $r = $r->add($hbit ? $self: $neg);
        }
    }
    return $r;
}

# $b is another PointFp.  Returns a PointFp.
sub add {
    my ($self, $b) = @_;

    # Wouldn't it be safer to return a new object rather than one of the args?
    return $b if $self->is_infinity;
    return $self if $b->is_infinity;

    my $u = (($b->y->to_int * $self->z) - ($self->y->to_int * $b->z))
        % $self->curve->q;

    my $v = (($b->x->to_int * $self->z) - ($self->x->to_int * $b->z))
        % $self->curve->q;

    if ($v == 0) {
        if ($u == 0) {
            return $self->twice;
        }
        return $self->curve->infinity;
    }

    my $x1 = $self->x->to_int;
    my $y1 = $self->y->to_int;
    my $x2 = $b->x->to_int;
    my $y2 = $b->y->to_int;

    # XXX: to implement
    my $v2 = $v ** 2;
    my $v3 = $v2 * $v;
    my $x1v2 = $x1 * $v2;
    my $zu2 = $u ** 2 * $self->z;

    my $x3 = ((($zu2 - ($x1v2 << 1)) * $b->z - $v3) * $v) % $self->curve->q;
    my $y3 = (($x1v2 * 3 * $u - $y1 * $v3 - $zu2 * $u) * $b->z + $u * $v3)
      % $self->curve->q;
    my $z3 = ($v3 * $self->z * $b->z) % $self->curve->q;

    return Crypt::EC::PointFp->new(
        $self->curve, $self->curve->fe_from_integer($x3),
        $self->curve->fe_from_integer($y3), $z3
    );
}

# Does this work for negative numbers?  Private.
sub bitlength {
    my ($n) = @_;

    my $binstr = $n->as_bin;
    $binstr =~ s/0b//;
    $binstr =~ s/-//;
    return length($binstr);
}

# Does this work for negative numbers?  Private.
sub testbit {
    my ($n, $pos) = @_;

    if ($n < 0) {
        die "not implemented for negative numbers";
    }

    return (($n & (1 << $pos)) != 0);
}

sub is_infinity {
    my ($self) = @_;
    my $id = id $self;

    if (!defined($x{$id}) and !defined($y{$id})) {
        return 1;
    }
    if ($z{$id} == 0 and $y{$id}->to_int == 0) {
        return 1;
    }
    return;
}

sub curve {
    my ($self) = @_;
    return $curve{id $self};
}

sub negate {
    my ($self) = @_;

    return Crypt::EC::PointFp->new(
       $self->curve, $self->x, $self->y->negate, $self->z
    );
}

sub twice {
    my ($self) = @_;
    my $id = id $self;

    return $self if $self->is_infinity;
    return $self->curve->infinity if $y{$id}->to_int == 0;

    my $x1 = $self->x->to_int;
    my $y1 = $self->y->to_int;
    my $y1z1 = $y1 * $self->z;
    my $y1sqz1 = ($y1z1 * $y1) % $self->curve->q;
    my $w = $x1 ** 2 * 3;
    unless ($self->curve->a == 0) {
        $w = $w + $z{$id} ** 2 * $self->curve->a;
    }
    $w = $w % $self->curve->q;

    my $x3 = ((($w ** 2 - (($x1 << 3) * $y1sqz1)) << 1) * $y1 
        * $z{$id}) % $self->curve->q;

    my $y3 = ((($w * 3 * $x1 - ($y1sqz1 << 1)) << 2) * $y1sqz1
        - $w ** 3) % $self->curve->q;

    my $z3 = (($y1z1 ** 3) << 3) % $self->curve->q;

    return Crypt::EC::PointFp->new(
        $self->curve, 
        $self->curve->fe_from_integer($x3),
        $self->curve->fe_from_integer($y3),
        $z3,
    );
}

# Returns array of 8 bit integers.
sub encode {
    my ($self, $compressed) = @_;

    my $id = id $self;

    my $x = $self->get_x->to_int;
    my $y = $self->get_y->to_int;
    my $len = 32;

    # XXX: implement int_to_bytes, based on ec.integerToBytes
    my @enc = int_to_padded_byte_array($x, $len);

    if ($compressed) {
        if ($y % 2 == 0) {
            unshift(@enc, 0x02);
        }
        else {
            unshift(@enc, 0x03);
        }
    } 
    else {
        unshift(@enc, 0x04);
        # uncompressed public key appends the bytes of the y point
        push(@enc, int_to_padded_byte_array($y, $len)); 
    }
    return @enc;
}

sub get_x {
    my ($self) = @_;

    if (!defined($self->zinv)) {
        $zinv{id $self} = $self->z->copy->bmodinv($self->curve->q);
    }
    return $self->curve->fe_from_integer(
        ($self->x->to_int * $self->zinv) % $self->curve->q
    );
}

sub get_y {
    my ($self) = @_;

    if (!defined($self->zinv)) {
        $zinv{id $self} = $self->z->copy->bmodinv($self->curve->q);
    }
    return $self->curve->fe_from_integer(
        ($self->y->to_int * $self->zinv) % $self->curve->q
    );
}

1;
