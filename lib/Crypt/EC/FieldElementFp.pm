package Crypt::EC::FieldElementFp;

=head1 NAME

Crypt::EC::FieldElementFp - Elliptic curve field element.

=head1 SYNOPSIS

=head1 DESCRIPTION

All the arithmetic operations such as add() and multiply() return
new Crypt::EC::FieldElementFp objects; they are not mutators.

=head2 new($q, $x)

Constructor.  $q and $x are big integers representing the q and x
values of the field element, respectively.

=head2 q

Returns the q value of this field element (a big integer).

=head2 x, to_int

Returns the x value of this field element (a big integer).

=head negate

Returns a Crypt::EC::FieldElementFp representing the negation of this
field element.

=head2 add($b)

Returns the Crypt::EC::FieldElementFp that is the result of adding
the Crypt::EC::FieldElementFp $b to this field element.

=head2 subtract($b)

Returns the Crypt::EC::FieldElementFp that is the result of subtracting
the Crypt::EC::FieldElementFp $b from this field element.

=head2 multiply

Returns the product of this field element and the Crypt::EC::FieldElementFp
$b, as a Crypt::EC::FieldElementFp.

=head2 square

Returns the square of this field element, as a Crypt::EC::FieldElementFp.

=head2 divide($b)

Returns this field element divided by the Crypt::EC::FieldElementFp $b,
as a Crypt::EC::FieldElementFp.

=cut

use strict;
use bignum;
use integer;

use Class::InsideOut qw(id register private);

# Integer
private x => my %x;
# Integer
private q => my %q;

sub new {
    my ($class, $q, $x) = @_;

    my $self = register $class;
    my $id = id $self;

    $x{$id} = $x;
    $q{$id} = $q;
    return $self;
}

sub q {
    my ($self) = @_;

    return $q{id $self};
}

sub x {
    my ($self) = @_;

    return $x{id $self};
}

sub to_int {
    my ($self) = @_;

    return $x{id $self};
}

sub negate {
    my ($self) = @_;

    return Crypt::EC::FieldElementFp->new($self->q, -$self->x % $self->q);
}

sub add {
    my ($self, $b) = @_;

    return Crypt::EC::FieldElementFp->new(
        $self->q, ($self->x + $b->to_int) % $self->q
    );
}

sub subtract {
    my ($self, $b) = @_;

    return Crypt::EC::FieldElementFp->new(
        $self->q, ($self->x - $b->to_int) % $self->q
    );
}

sub multiply {
    my ($self, $b) = @_;

    return Crypt::EC::FieldElementFp->new(
        $self->q, ($self->x * $b->to_int) % $self->q
    );
}

sub square {
    my ($self) = @_;

    return Crypt::EC::FieldElementFp->new(
        $self->q, ($self->x ** 2) % $self->q
    );
}

sub divide {
    my ($self, $b) = @_;

    return Crypt::EC::FieldElementFp->new(
        $self->q, ($self->x * $b->to_int->bmodinv($self->q)) % $self->q
    );
}


1;
