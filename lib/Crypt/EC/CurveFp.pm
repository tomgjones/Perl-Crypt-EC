package Crypt::EC::CurveFp;

=head1 NAME

Crypt::EC::CurveFp - Elliptic curve for cryptography.

=head1 SYNOPSIS

=head1 DESCRIPTION

=head2 new($q, $a, $b)

Constructor.  $q, $a and $b are integers specifying the curve paramaters
q, a and b respectively.

=head2 fe_from_integer($x)

Given an integer $x, returns a Crypt::EC::FieldElementFp
representing the corresponding field element on this curve.

=head2 decode_point_hex($hexstr)

Given a string $hexstr representing a hexadecimal number, return
a Crypt::EC::PointFp respresenting the corresponding point on
this curve.  Returns false if it's unable

=head2 infinity

Returns the Crypt::EC::PointFp representing this curve's infinity point.

=head2 q

Returns this curve's q parameter as a big integer.

=head2 a

Returns this curve's a parameter as a big integer.

=head2 b

Returns this curve's b parameter as a big integer.

=cut

use strict;
use bignum;
use integer;

use Class::InsideOut qw(id private register);
use Crypt::EC::FieldElementFp;
use Crypt::EC::PointFp;

# q is just an integer
private q => my %q;
# a is just an integer
private a => my %a;
# b is just an integer
private b => my %b;
private infinity => my %infinity;

sub new {
    my ($class, $q, $a, $b) = @_;

    if (!defined($q) or !defined($a) or !defined($b)) {
        die "not enough args passed to Crypt::EC::CurveFp->new $q $a $b E\n";
    }

    my $self = register $class;
    my $id = id $self;

    $q{$id} = $q;
    $a{$id} = $a;
    $b{$id} = $b;
    $infinity{$id} = Crypt::EC::PointFp->new($self, undef, undef);
    return $self;
}

sub fe_from_integer {
    my ($self, $x) = @_;

    return Crypt::EC::FieldElementFp->new($self->q, $x);
}



# Returns Crypt::EC::PointFp or false.
sub decode_point_hex {
    my ($self, $str) = @_;
    my $id = id $self;

    my $firstbyte = hex(substr($str, 0, 2));
    if ($firstbyte == 0) {
        return $infinity{$id};
    }
    elsif ($firstbyte == 2 or $firstbyte == 3) {
        # point compression not supported yet
        die "point compression not supported yet";
    }
    elsif ($firstbyte == 4 or $firstbyte == 6 or $firstbyte == 7) {
        my $halflen = (length($str) - 2)/2;
        my $x_hex = substr($str, 2, $halflen);
        my $y_hex = substr($str, $halflen + 2, $halflen);

        return Crypt::EC::PointFp->new(
            $self, 
            $self->fe_from_integer(hex($x_hex)), 
            $self->fe_from_integer(hex($y_hex)),
        );
    }
    else {
        die "unsupported";
    }
}

sub infinity {
    my ($self) = @_;

    return $infinity{id $self};
}

sub q {
    my ($self) = @_;

    return $q{id $self};
}

sub a {
    my ($self) = @_;

    return $a{id $self};
}

sub b {
    my ($self) = @_;

    return $b{id $self};
}

1;
