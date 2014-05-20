# ---+ Extensions
# ---++ PasswordPlugin
# This is the configuration used by the <b>PasswordPlugin</b>.

# **STRING**
# <h3>Setup databases connections</h3>
# Configuration info for the database to be used to store ratings.
$Foswiki::cfg{PasswordPlugin}{Database}{DSN} = 'dbi:SQLite:dbname=$Foswiki::cfg{WorkingDir}/work_areas/PasswordPlugin/passwords.db';

# **STRING 80 **
# Prefix used naming tables and indexes generated in the database.
$Foswiki::cfg{PasswordPlugin}{Database}{TablePrefix} = 'foswiki_';

# **STRING 80 **
# Username to access the database
$Foswiki::cfg{PasswordPlugin}{Database}{{UserName} = '';

# **PASSWORD 80 **
# Credentials for the user accessing the database
$Foswiki::cfg{PasswordPlugin}{Database}{Password} = '';

# **PASSWORD 80 **
# Key Phrase to encrypt passwords in the database. WARNING: only set this once before using the plugin. Once you've set
# the key phrase, never change it again. Your database will be unreadable otherwise.
$Foswiki::cfg{PasswordPlugin}{KeyPhrase} = 'default key';


# **SELECT DES, DES_EDE3, IDEA, Blowfish, CAST5, Rijndael EXPERT**
# Block cipher algorith
$Foswiki::cfg{PasswordPlugin}{CipherAlgorithm} = 'Blowfish';

1;
