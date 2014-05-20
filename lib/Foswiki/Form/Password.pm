# See bottom of file for license and copyright information
package Foswiki::Form::Password;

use strict;
use warnings;

use Foswiki::Form::FieldDefinition ();
use Foswiki::Plugins::PasswordPlugin ();
our @ISA = ('Foswiki::Form::FieldDefinition');

sub new {
  my $class = shift;
  my $this = $class->SUPER::new(@_);
  my $size = $this->{size} || '';
  $size =~ s/\D//g;
  $size = 10 if (!$size || $size < 1);
  $this->{size} = $size;
  return $this;
}

sub renderForEdit {
  my ($this, $topicObject, $value) = @_;

  my $id = $value;

  if ($value =~ /^password\-(.*)$/) {
    my $id = $1;
    $value = Foswiki::Plugins::PasswordPlugin::getPasswordById($id);
  }

  return (
    '',
    CGI::textfield(
      -class => $this->cssClasses('foswikiPasswordField'),
      -name => $this->{name},
      -size => $this->{size},
      -value => $value
    )
  );
}

sub renderForDisplay {
    my ( $this, $format, $value, $attrs ) = @_;

    $value = $this->getDisplayValue($value); # always hide
    $format =~ s/\$value\(display\)/$value/g;
    return $this->SUPER::renderForDisplay( $format, $value, $attrs );
}

sub getDisplayValue {
  my ($this, $value) = @_;

  return '&bull;' x 8;
}

1;
__END__
Foswiki - The Free and Open Source Wiki, http://foswiki.org/

Copyright (C) 2014 Foswiki Contributors. Foswiki Contributors
are listed in the AUTHORS file in the root of this distribution.
NOTE: Please extend that file, not this notice.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version. For
more details read LICENSE in the root of this distribution.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

As per the GPL, removal of this notice is prohibited.
