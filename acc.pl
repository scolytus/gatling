#!/usr/bin/perl
while (<>) {
  chomp;
  my @x=split(" ");
  if ($x[0] =~ m/^\d{4}-\d\d-\d\d$/) {
    my $tmp = "$x[0]|$x[1]";
    shift @x;
    $x[0]=$tmp;
  }
  if ($x[1] eq "accept") {
    $ip{$x[2]} = $x[3];
  } elsif ($#x == 7) {
    $x[2] = $ip{$x[2]};
    $x[2] = "0.0.0.0" if ($x[2] eq "");
    print join(" ",@x),"\n";
  }
}
