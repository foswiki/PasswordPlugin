# Plugin for Foswiki - The Free and Open Source Wiki, http://foswiki.org/
#
# PasswordPlugin is Copyright (C) 2014 Michael Daum http://michaeldaumconsulting.com
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details, published at
# http://www.gnu.org/copyleft/gpl.html

package Foswiki::Plugins::PasswordPlugin::Core;

use strict;
use warnings;

use Foswiki::Func ();
use Foswiki::Form ();
use Foswiki::Meta ();
use Foswiki::OopsException ();
use Foswiki::AccessControlException ();
use Error qw( :try );
use DBI ();
use MIME::Base64 ();
use Crypt::CBC ();
use Digest::MD5;
#use Data::Dump qw(dump);

use constant TRACE => 0; # toggle me

###############################################################################
# static
sub writeDebug {
  Foswiki::Func::writeDebug("PasswordPlugin::Core - $_[0]") if TRACE;
}

###############################################################################
sub new {
  my $class = shift;

  my $this = bless({
      dsn => $Foswiki::cfg{PasswordPlugin}{Database}{DSN} || 'dbi:SQLite:dbname=' . Foswiki::Func::getWorkArea('PasswordPlugin') . '/passwords.db',
      username => $Foswiki::cfg{PasswordPlugin}{Database}{UserName},
      password => $Foswiki::cfg{PasswordPlugin}{Database}{Password},
      tablePrefix => $Foswiki::cfg{PasswordPlugin}{Database}{TablePrefix} || 'foswiki_',
      keyPhrase => $Foswiki::cfg{PasswordPlugin}{KeyPhrase} || 'default key', 
      cipherAlgorithm => $Foswiki::cfg{PasswordPlugin}{CipherAlgorithm} || 'Blowfish', 
    @_
  }, $class);

  $this->{passwordsTable} = $this->{tablePrefix}.'passwords';
  $this->{passwordsIndex} = $this->{tablePrefix}.'passwords_index';

  return $this;
}

###############################################################################
sub finish {
  my $this = shift;

  if ($this->{sths}) {
    foreach my $sth (values %{$this->{sths}}) {
      $sth->finish;
    }
    $this->{sths} = undef;
  }

  $this->{dbh}->disconnect if defined $this->{dbh};
  $this->{dbh} = undef;
  $this->{cipher} = undef;
}

###############################################################################
sub getStatementHandler {
  my ($this, $id) = @_;

  my $sth = $this->{sths}{$id};
  return $sth if defined $sth;

  my $statement;

  if ($id eq 'insert_password') {
    $statement = <<HERE;
      replace into $this->{passwordsTable} 
        (id, web, topic, field, password) values 
        (?, ?, ?, ?, ?)
HERE
  } elsif ($id eq 'select_password') {
    $statement = <<HERE;
      select password from $this->{passwordsTable} where web = ? and topic = ? and field = ?
HERE
  } elsif ($id eq 'select_password_by_id') {
    $statement = <<HERE;
      select password from $this->{passwordsTable} where rowid = ?
HERE
  } elsif ($id eq 'select_id_of_web_topic') {
    $statement = <<HERE;
      select rowid from $this->{passwordsTable} where web = ? and topic = ? and field = ?
HERE
  } elsif ($id eq 'select_all') {
    $statement = <<HERE;
      select * from $this->{passwordsTable}
HERE
  }

  throw Error::Simple("Unknown statement id '$id'") unless defined $statement;

  $this->{sths}{$id} = $sth = $this->{dbh}->prepare($statement);

  return $sth;
}

###############################################################################
sub initDatabase {
  my $this = shift;

  unless (defined $this->{dbh}) {

    writeDebug("connect database");
    $this->{dbh} = DBI->connect(
      $this->{dsn},
      $this->{username},
      $this->{password},
      {
        PrintError => 0,
        RaiseError => 1,
        AutoCommit => 1,
        ShowErrorStatement => 1,
      }
    );

    throw Error::Simple("Can't open database $this->{dsn}: " . $DBI::errstr)
      unless defined $this->{dbh};

    # test whether the table exists
    #writeDebug("test database");
    try { 
      $this->{dbh}->do("select * from $this->{passwordsTable} limit 1");
    } otherwise {

        writeDebug("creating $this->{passwordsTable} database");

        $this->{dbh}->do(<<HERE);
        create table $this->{passwordsTable} (
          id integer primary key,
          web char(255),
          topic char(255),
          field char(255),
          password char(255)
        )
HERE

        $this->{dbh}->do("create unique index $this->{passwordsIndex} on $this->{passwordsTable} (web, topic, field)");
    };
  };


  return $this;
}


###############################################################################
sub beforeEditHandler {
  my ($this, $text, $topic, $web, $meta) = @_;

  writeDebug("called beforeEditHandler($web.$topic)");

  my @passwordFields = $this->getPasswordFields($meta);
  return unless @passwordFields;

  $this->initDatabase;

  # process password fields
  foreach my $fieldDef (@passwordFields) {

    # fetch from database
    my $name = $fieldDef->{name};
    my $field = $meta->get('FIELD', $name);
    my $id = $field->{value};

    next if $id =~ /^password\-(.*)$/;
    $id =~ $1;

    my $value = $this->getPasswordById($id) || '';

    $field->{value} = $value;
  }
}

###############################################################################
sub beforeMetaDataSaveHandler {
  my ($this, $web, $topic, $metaDataName, $record) = @_;

  writeDebug("called beforeMetaDataSaveHandler($web, $topic, $metaDataName, $record)");
  #writeDebug(dump($record));

  my $metaDataDef = $Foswiki::Meta::VALIDATE{$metaDataName};
  return unless defined $metaDataDef;

  return unless defined $metaDataDef->{form};

  writeDebug("form=$metaDataDef->{form}");

  my $formDef = $this->getFormDefinition(undef, $metaDataDef->{form});
  return unless defined $formDef;

  writeDebug("got formDef");

  $this->initDatabase;

  foreach my $fieldDef (@{$formDef->getFields()}) {
    next unless $fieldDef->{type} =~ /password/;

    # store to database
    my $fieldName = $fieldDef->{name};
    my $value = $record->{$fieldName};

    writeDebug("record: $fieldName=$value");

    next if $value eq '&bull;';

    my $name = $metaDataName.':'.$record->{name}.':'.$fieldName;

    my $id = $this->setPassword($web, $topic, $name, $value);
    $record->{$fieldName} = "password-".$id;
  }
}

###############################################################################
sub beforeSaveHandler {
  my ($this, $text, $topic, $web, $meta) = @_;

  writeDebug("called beforeSaveHandler($web.$topic)");

  my @passwordFields = $this->getPasswordFields($meta);
  return unless @passwordFields;

  $this->initDatabase;

  # process password fields
  foreach my $fieldDef (@passwordFields) {

    # store to database
    my $name = $fieldDef->{name};
    my $field = $meta->get('FIELD', $name);
    my $value = $field->{value};

    next if !defined($value) || $value eq '&bull;';

    my $id = $this->setPassword($web, $topic, $name, $value);
    $field->{value} = "password-".$id;
  }
}

###############################################################################
sub getPasswordFields {
  my ($this, $meta) = @_;

  my $formName = $meta->getFormName();
  return () unless $formName;

  my @passwordFields = ();
  my $formDef= $this->getFormDefinition($meta->web, $formName);

  if ($formDef) {
    foreach my $fieldDef (@{$formDef->getFields()}) {
      if ($fieldDef->{type} =~ /password/) {
        push @passwordFields, $fieldDef;
      }
    }
  }

  return @passwordFields;
}

###############################################################################
sub getFormDefinition {
  my ($this, $web, $topic) = @_;

  ($web, $topic) = Foswiki::Func::normalizeWebTopicName($web, $topic);

  return unless Foswiki::Func::topicExists($web, $topic);

  my $formDef;
  try {
    my $session = $Foswiki::Plugins::SESSION;
    $formDef = new Foswiki::Form($session, $web, $topic);
  } catch Foswiki::OopsException with {
    my $e = shift;
    print STDERR "ERROR: can't read form definition $web.$topic\n";
  };

  return $formDef;
}

###############################################################################
sub setPassword {
  my ($this, $web, $topic, $name, $value) = @_;

  my $sth_id = $this->getStatementHandler("select_id_of_web_topic");
  my ($id) = $this->{dbh}->selectrow_array($sth_id, undef, $web, $topic, $name);

  my $sth_insert = $this->getStatementHandler("insert_password");

  $value = $this->encrypt($value);

  writeDebug("set password $web, $topic, $name, $value");

  $sth_insert->execute($id, $web, $topic, $name, $value);

  ($id) = $this->{dbh}->selectrow_array($sth_id, undef, $web, $topic, $name)
    unless defined $id;

  return $id;
}

###############################################################################
sub getPassword {
  my ($this, $web, $topic, $name) = @_;

  writeDebug("get password $web, $topic, $name");

  my $sth = $this->getStatementHandler("select_password");
  my ($value) = $this->{dbh}->selectrow_array($sth, undef, $web, $topic, $name);

  return unless defined $value;
  return $this->decrypt($value);;
}


###############################################################################
sub getPasswordById {
  my ($this, $id) = @_;

  writeDebug("get password by id $id");

  my $sth = $this->getStatementHandler("select_password_by_id");
  my ($value) = $this->{dbh}->selectrow_array($sth, undef, $id);

  return unless defined $value;
  return $this->decrypt($value);;
}

###############################################################################
sub getCipher {
  my ($this, $keyPhrase, $algorithm) = @_;

  $keyPhrase ||= $this->{keyPhrase};
  $algorithm ||= $this->{cipherAlgorithm};

  my $md5 = Digest::MD5::md5_hex($keyPhrase, $algorithm);

  unless (defined $this->{cipher}{$md5}) {

    $this->{cipher}{$md5} = Crypt::CBC->new(
      -key => $keyPhrase,
      -cipher =>$algorithm,
    );

    #writeDebug("cipher algorithm ".$this->{cipher}{$md5}->cipher);
  }

  return $this->{cipher}{$md5};
}

###############################################################################
sub encrypt {
  my ($this, $value, $cipher) = @_;

  $cipher ||= $this->getCipher;

  return MIME::Base64::encode($cipher->encrypt($value));
}

###############################################################################
sub decrypt {
  my ($this, $value, $cipher) = @_;

  $cipher ||= $this->getCipher;

  return $cipher->decrypt(MIME::Base64::decode($value));
}

###############################################################################
sub changeKeyPhrase {
  my ($this, $session, $subject, $verb, $response ) = @_;

  throw Error::Simple("only admins can call this handler")
    unless Foswiki::Func::isAnAdmin();

  my $request = Foswiki::Func::getRequestObject();

  my $oldKeyPhrase = $request->param("oldkey");
  throw Error::Simple("'oldkey' required") unless defined $oldKeyPhrase;

  my $newKeyPhrase = $request->param("newkey") || $this->{keyPhrase};
  my $oldAlgo = $request->param("oldalgo") || $this->{cipherAlgorithm};
  my $newAlgo = $request->param("newalgo") || $this->{cipherAlgorithm};

  my $oldCipher = $this->getCipher($oldKeyPhrase, $oldAlgo);
  my $newCipher = $this->getCipher($newKeyPhrase, $newAlgo);

  $this->initDatabase;

  my $selectHandler = $this->getStatementHandler("select_all");
  my $insertHandler = $this->getStatementHandler("insert_password");

  $this->{dbh}->begin_work;
  
  $selectHandler->execute();

  my $error;
  my $count = 0;
  try {
    while (my $row = $selectHandler->fetchrow_hashref()) {

      my $oldPasswd = $this->decrypt($row->{password}, $oldCipher);

      # SMELL: any other way to detect proper decryption?
      throw Error::Simple ("wrong keyphrase: $oldPasswd") unless $oldPasswd =~ /^[[:print:]]*$/;

      my $newPasswd = $this->encrypt($oldPasswd, $newCipher);

      $insertHandler->execute($row->{id}, $row->{web}, $row->{topic}, $row->{field}, $newPasswd);

      $count++;
    }
  } catch Error::Simple with {
    $error = shift;
    $this->{dbh}->rollback;
  };

  throw Error::Simple("Error during changeKeyPhrase: ".$error)
    if $error;

  $this->{dbh}->commit;
 
  return $count;
}


1
