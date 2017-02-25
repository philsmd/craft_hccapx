#!/usr/bin/env perl

# Author: philsmd
# License: public domain
# First released: February 2017

# Note: this is an adapted version of https://github.com/philsmd/analyze_hccap.pl which works with .hccapx files

use strict;
use warnings;

#
# Constants
#

my $DEFAULT_OUTFILE = "m02500.hccapx";

my $DEFAULT_HCCAPX_VERSION = 4;
my $DEFAULT_MESSAGE_PAIR   = 0;

my $HCCAPX_STRUCT_MAGIC = "\x48\x43\x50\x58"; # HCPX

#
# Helper functions
#

sub usage ()
{
  print "Usage: $0 [OPTIONS]\n\n";

  print "where the available OPTIONS are:\n";
  print "-h | --help            show this usage information\n";
  print "-o | --outfile         output file (default is $DEFAULT_OUTFILE)\n";
  print "-H | --hccapx-version  version number of the hccapx file structure\n";
  print "-M | --message-pair    message pair value (0 = M1+M2, 1 = M1+M4, 2 = M2+M3, 3 = M2+M3 (EAPOL from M3), 4 = M3+M4, 5 = M3+M4 (EAPOL from M4))\n";
  print "-e | --essid           ESSID (network name) of the access point\n";
  print "-v | --key-version     WPA key version, 1 = WPA, other = WPA2\n";
  print "-k | --key-mic         MD5 or SHA1 hash value, depending on the key version (truncated to 16 bytes)\n";
  print "-b | --bssid           BSSID (MAC address)  of the access point\n";
  print "-a | --anonce          nonce-value (random salt) send by the access point\n";
  print "-m | --mac_sta         MAC address of the client\n";
  print "-s | --snonce          nonce-value (random salt) send by the client\n";
  print "-E | --eapol           EAPOL\n\n";

  print "NOTE: all arguments except --help and --outfile can be repeated multiple times, if you want to craft a .hccapx\n";
  print "file which contains several networks (i.e. which contains several hccapx files, a so-called multi hccapx file)\n";
}

sub is_valid_hex
{
  my $hex = shift;
  my $min = shift;
  my $max = shift;

  my $ret = 0;

  $$hex =~ s/[: ]//g;

  if ($$hex =~ m/^[0-9a-fA-F]{$min,$max}$/)
  {
    $ret = 1;
  }

  $$hex = lc ($$hex);

  return $ret;
}

sub check_version
{
  my $version = shift;
  my $error_msg = shift;

  my $ret = 1;

  if ($$version !~ m/^[0-9]+$/)
  {
    $$error_msg = "hccapx version number invalid. It must be a number";

    $ret = 0;
  }
  elsif ($$version < 4)
  {
    $$error_msg = "hccapx version number invalid. It must be greater than 3";

    $ret = 0;
  }

  return $ret;
}

sub check_message_pair
{
  my $message_pair = shift;
  my $error_msg = shift;

  my $ret = 1;

  if ($$message_pair !~ m/^[0-9]+$/)
  {
    $$error_msg = "the message pair must be a valid number";

    $ret = 0;
  }
  elsif (($$message_pair < 0) || ($$message_pair > 5))
  {
    $$error_msg = "the message pair must be a number from 0 (included) to 5 (included)";

    $ret = 0;
  }

  return $ret;
}

sub check_essid
{
  my $essid = shift;
  my $error_msg = shift;

  my $ret = 1;

  if (length ($$essid) < 1)
  {
    $$error_msg = "ESSID is too short, it must be at least of length 1";

    $ret = 0;
  }

  if (length ($$essid) > 32)
  {
    $$error_msg = "ESSID '$$essid' is too long, it can't be longer than 32 characters long";

    $ret = 0;
  }

  return $ret;
}

sub check_mac_address
{
  my $mac = shift;
  my $error_msg = shift;

  my $ret = 1;

  if (! is_valid_hex ($mac, 12, 12))
  {
    $$error_msg = "'$$mac' is not a valid MAC address, it must be of this hexadecimal format: [a-fA-F0-9]{12}";

    $ret = 0;
  }

  return $ret;
}

sub check_nonce
{
  my $nonce = shift;
  my $error_msg = shift;

  my $ret = 1;

  if (! is_valid_hex ($nonce, 64, 64))
  {
    $$error_msg = "'$$nonce' is not a valid nonce value, it must be of hexadecimal format: [a-fA-f0-9]{64}";

    $ret = 0;
  }

  return $ret;
}

sub check_eapol
{
  my $eapol = shift;
  my $error_msg = shift;

  my $ret = 1;

  if (! is_valid_hex ($eapol, 2, 512))
  {
    $$error_msg = "the EAPOL is not in the correct hexadecimal format: [a-fA-F0-9]{2, 512}";

    $ret = 0;
  }

  return $ret;
}

sub check_eapol_len
{
  my $eapol_len = shift;
  my $error_msg  = shift;

  my $ret = 1;

  if (length ($$eapol_len) < 1)
  {
    $$error_msg = "the EAPOL lenght is too small";

    $ret = 0;
  }
  else
  {
    if ($$eapol_len < 1)
    {
      $$error_msg = "the EAPOL length is too small";

      $ret = 0;
    }
    elsif ($$eapol_len > 255)
    {
      $$error_msg = "the EAPOL length is too large";

      $ret = 0;
    }
  }

  return $ret;
}

sub check_keyver
{
  my $version = shift;
  my $error_msg = shift;

  my $ret = 1;

  if (length ($$version) < 1)
  {
    $$error_msg = "the WPA key '$$version' is not numeric";

    $ret = 0;
  }
  else
  {
    if ($$version !~ m/^[0-9]+$/)
    {
      $$error_msg = "the WPA key '$$version' is not numeric";

      $ret = 0;
    }

    if ($$version < 1)
    {
      $$error_msg = "the WPA key version must be at least 1";

      $ret = 0;
    }
    elsif (($$version != 1) && ($$version != 2))
    {
      print STDERR "WARNING: the WPA key version should normally be either 1 or 2\n";
    }
  }

  return $ret;
}

sub check_keymic
{
  my $mic = shift;
  my $error_msg = shift;

  my $ret = 1;

  if (! is_valid_hex ($mic, 32, 32))
  {
    $$error_msg = "the WPA key mic '$$mic' is not in the correct hexadecimal format: [a-fA-F0-9]{32}";

    $ret = 0;
  }

  return $ret;
}

sub add_item
{
  my $hccapxs = shift;
  my $type    = shift;
  my $value   = shift;

  $hccapxs->{$type} = $value;
}

sub check_item
{
  my $type = shift;
  my $value = shift;
  my $error_msg = shift;

  my $ret = 0;

  if ($type eq "version")
  {
    $ret = check_version ($value, $error_msg);
  }
  elsif ($type eq "message_pair")
  {
    $ret = check_message_pair ($value, $error_msg);
  }
  elsif ($type eq "essid")
  {
    $ret = check_essid ($value, $error_msg);
  }
  elsif ($type eq "keyver")
  {
    $ret = check_keyver ($value, $error_msg);
  }
  elsif ($type eq "keymic")
  {
    $ret = check_keymic ($value, $error_msg);
  }
  elsif ($type eq "mac_ap")
  {
    $ret = check_mac_address ($value, $error_msg);
  }
  elsif ($type eq "nonce_ap")
  {
    $ret = check_nonce ($value, $error_msg);
  }
  elsif ($type eq "mac_sta")
  {
    $ret = check_mac_address ($value, $error_msg);
  }
  elsif ($type eq "nonce_sta")
  {
    $ret = check_nonce ($value, $error_msg);
  }
  elsif ($type eq "eapol_len")
  {
    $ret = check_eapol_len ($value, $error_msg);
  }
  elsif ($type eq "eapol")
  {
    $ret = check_eapol ($value, $error_msg);
  }

  return $ret;
}

sub create_new_item
{
  my %new_hccapx_item =
  (
    version => $DEFAULT_HCCAPX_VERSION,
    message_pair => $DEFAULT_MESSAGE_PAIR,
    essid => "",
    keyver => "",
    keymic => "",
    mac_ap => "",
    nonce_ap => "",
    mac_sta => "",
    nonce_sta => "",
    eapol_len => "",
    eapol => ""
  );

  return \%new_hccapx_item;
}

sub add_to_hccapxs
{
  my $hccapxs = shift;
  my $input_type  = shift;
  my $input_value = shift;

  my $found = 0;
  my $count = 1;

  foreach my $key (keys %$hccapxs)
  {
    if (length ($hccapxs->{$key}{$input_type}) < 1)
    {
      add_item ($hccapxs->{$key}, $input_type, $input_value);

      $found = 1;

      last;
    }

    $count++;
  }

  # if not found, add a new set of items

  if ($found == 0)
  {
    $hccapxs->{$count} = create_new_item ();

    add_item ($hccapxs->{$count}, $input_type, $input_value);
  }
}

# return values:
# 0 -> everything is okay
# 1 -> empty (no arguments supplied)
# 2 -> error

sub check_hccapxs
{
  my $hccapxs = shift;
  my $error_msg = shift;

  my $ret = 1;

  my $length = scalar (keys %$hccapxs);

  if ($length == 0)
  {
    $ret = 1;
  }
  else
  {
    foreach my $num (keys %$hccapxs)
    {
      my $item = %$hccapxs{$num};

      foreach my $key (keys %$item)
      {
        if (! check_item ($key, \$item->{$key}, $error_msg))
        {
          if (length ($item->{$key}) < 1)
          {
            $$error_msg = "$key was not set for network number $num";
          }

          $ret = 2;
        }

        last if ($ret == 2);
      }

      last if ($ret == 2);
    }

    # everything was okay if not 2
    $ret = 0 if ($ret != 2);
  }

  return $ret;
}

sub get_user_input
{
  my $msg = shift;

  print $msg;

  my $input = <STDIN>;

  chomp ($input);

  return $input;
}

sub get_interactive_input
{
  my $hccapxs = shift;

  my $count = 1;

  my $error_msg = "";
  my $msg = "";

  while (1)
  {
    # should we continue to ask the user for the inputs

    if ($count > 1)
    {
      $msg = "Would you like to add further networks [y/N]? ";

      my $answer = get_user_input ($msg);

      last if ($answer !~ m/^[yY]/);
    }

    $hccapxs->{$count} = create_new_item ();

    # version
    my $version;
    $msg = "Please specify the .hccapx version number: ";

    $version = get_user_input ($msg);

    while (! check_item ("version", \$version, \$error_msg))
    {
      if ($error_msg)
      {
        print STDERR "ERROR: $error_msg\n";
      }

      $version = get_user_input ($msg);
    }

    add_item ($hccapxs->{$count}, "version", $version);

    # message pair
    my $message_pair;
    $msg = "Please specify the message pair value i.e. the number indicating which exchanges are involved in the handshake (0 to 5): ";

    $message_pair = get_user_input ($msg);

    while (! check_item ("message_pair", \$message_pair, \$error_msg))
    {
      if ($error_msg)
      {
        print STDERR "ERROR: $error_msg\n";
      }

      $message_pair = get_user_input ($msg);
    }

    add_item ($hccapxs->{$count}, "message_pair", $message_pair);

    # essid
    my $essid;
    $msg = "Please specify the network name (ESSID): ";

    $essid = get_user_input ($msg);

    while (! check_item ("essid", \$essid, \$error_msg))
    {
      if ($error_msg)
      {
        print STDERR "ERROR: $error_msg\n";
      }

      $essid = get_user_input ($msg);
    }

    add_item ($hccapxs->{$count}, "essid", $essid);

    # keyver
    my $keyver;
    $msg = "Please specify the WPA version (1 = WPA, 2 = WPA2): ";

    $keyver = get_user_input ($msg);

    while (! check_item ("keyver", \$keyver, \$error_msg))
    {
      if ($error_msg)
      {
        print STDERR "ERROR: $error_msg\n";
      }

      $keyver = get_user_input ($msg);
    }

    add_item ($hccapxs->{$count}, "keyver", $keyver);

    # keymic
    my $keymic;
    $msg = "Please specify the key mic (the MD5 or truncated SHA1 hash), 32 hex characters: ";

    $keymic = get_user_input ($msg);

    while (! check_item ("keymic", \$keymic, \$error_msg))
    {
      if ($error_msg)
      {
        print STDERR "ERROR: $error_msg\n";
      }

      $keymic = get_user_input ($msg);
    }

    add_item ($hccapxs->{$count}, "keymic", $keymic);

    # mac_ap
    my $mac_ap;
    $msg = "Please specify the MAC of the access point (BSSID/mac_ap) in hex: ";

    $mac_ap = get_user_input ($msg);

    while (! check_item ("mac_ap", \$mac_ap, \$error_msg))
    {
      if ($error_msg)
      {
        print STDERR "ERROR: $error_msg\n";
      }

      $mac_ap = get_user_input ($msg);
    }

    add_item ($hccapxs->{$count}, "mac_ap", $mac_ap);

    # nonce_ap
    my $nonce_ap;
    $msg = "Please input the nonce of the access point (anonce), 64 hex characters: ";

    $nonce_ap = get_user_input ($msg);

    while (! check_item ("nonce_ap", \$nonce_ap, \$error_msg))
    {
      if ($error_msg)
      {
        print STDERR "ERROR: $error_msg\n";
      }

      $nonce_ap = get_user_input ($msg);
    }

    add_item ($hccapxs->{$count}, "nonce_ap", $nonce_ap);

    # mac_sta (mac address of STA, i.e. client)
    my $mac_sta;
    $msg = "Please specify the MAC of the client (mac_sta) in hex: ";

    $mac_sta = get_user_input ($msg);

    while (! check_item ("mac_sta", \$mac_sta, \$error_msg))
    {
      if ($error_msg)
      {
        print STDERR "ERROR: $error_msg\n";
      }

      $mac_sta = get_user_input ($msg);
    }

    add_item ($hccapxs->{$count}, "mac_sta", $mac_sta);

    # nonce_sta
    my $nonce_sta;
    $msg = "Please input the nonce of the client (snonce), 64 hex characters: ";

    $nonce_sta = get_user_input ($msg);

    while (! check_item ("nonce_sta", \$nonce_sta, \$error_msg))
    {
      if ($error_msg)
      {
        print STDERR "ERROR: $error_msg\n";
      }

      $nonce_sta = get_user_input ($msg);
    }

    add_item ($hccapxs->{$count}, "nonce_sta", $nonce_sta);

    # eapol
    my $eapol;
    $msg = "Please input the full EAPOL in hex: ";

    $eapol = get_user_input ($msg);

    while (! check_item ("eapol", \$eapol, \$error_msg))
    {
      if ($error_msg)
      {
        print STDERR "ERROR: $error_msg\n";
      }

      $eapol = get_user_input ($msg);
    }

    add_item ($hccapxs->{$count}, "eapol", $eapol);

    # eapol len
    add_item ($hccapxs->{$count}, "eapol_len", length ($eapol) / 2);

    $count++;
  }
}

sub write_hccapx
{
  my $fp = shift;
  my $hccapxs = shift;

  foreach my $item (keys %$hccapxs)
  {
    # first the signature:
    print $fp $HCCAPX_STRUCT_MAGIC;

    # hccapx version
    my $version = $hccapxs->{$item}{version};
    print $fp pack ("L<", $version);

    # message_pair
    my $message_pair = $hccapxs->{$item}{message_pair};
    print $fp pack ("C", $message_pair);

    # essid length
    my $essid = $hccapxs->{$item}{essid};
    my $essid_length = length ($essid);

    print $fp pack ("C", $essid_length);

    # essid
    if ($essid_length > 32) # shouldn't be possible but you never know
    {
      $essid_length = 32;
    }

    my $essid_padding_length = 32 - $essid_length;

    print $fp substr ($essid, 0, 32) . ("\x00" x $essid_padding_length);

    # keyver
    my $keyver = $hccapxs->{$item}{keyver};
    print $fp pack ("C", $keyver);

    # keymic
    my $keymic = $hccapxs->{$item}{keymic};
    my $keymic_bin = pack ("H*", $keymic);

    print $fp substr ($keymic_bin, 0, 16);

    # mac_ap
    my $mac_ap = $hccapxs->{$item}{mac_ap};
    my $mac_ap_bin = pack ("H*", $mac_ap);

    print $fp substr ($mac_ap_bin, 0, 8);

    # nonce_ap
    my $nonce_ap = $hccapxs->{$item}{nonce_ap};
    my $nonce_ap_bin = pack ("H*", $nonce_ap);

    print $fp substr ($nonce_ap_bin, 0, 32);

    # mac_sta (mac address of the STA, i.e. the client)
    my $mac_sta = $hccapxs->{$item}{mac_sta};
    my $mac_sta_bin = pack ("H*", $mac_sta);

    print $fp substr ($mac_sta_bin, 0, 8);

    # nonce_sta
    my $nonce_sta = $hccapxs->{$item}{nonce_sta};
    my $nonce_sta_bin = pack ("H*", $nonce_sta);

    print $fp substr ($nonce_sta_bin, 0, 32);

    # eapol length
    my $eapol_len = $hccapxs->{$item}{eapol_len};

    print $fp pack ("S<", $eapol_len);

    # eapol
    my $eapol = $hccapxs->{$item}{eapol};
    my $eapol_bin = pack ("H*", $eapol);
    my $eapol_padding_length = 256 - $eapol_len;

    print $fp substr ($eapol_bin, 0, $eapol_len) . ("\x00" x $eapol_padding_length);
  }
}

#
# START
#

my $outfile = "";

my $arg_size = scalar (@ARGV);

my %hccapx_contents = ();


my $switch = "";

foreach my $arg (@ARGV)
{
  if ($switch ne "")
  {
    if ($switch eq "outfile")
    {
      $outfile = $arg;
    }
    elsif ($switch eq "version")
    {
      add_to_hccapxs (\%hccapx_contents, $switch, $arg);
    }
    elsif ($switch eq "message_pair")
    {
      add_to_hccapxs (\%hccapx_contents, $switch, $arg);
    }
    elsif ($switch eq "essid")
    {
      add_to_hccapxs (\%hccapx_contents, $switch, $arg);
    }
    elsif ($switch eq "keyver")
    {
      add_to_hccapxs (\%hccapx_contents, $switch, $arg);
    }
    elsif ($switch eq "keymic")
    {
      add_to_hccapxs (\%hccapx_contents, $switch, $arg);
    }
    elsif ($switch eq "mac_ap")
    {
      add_to_hccapxs (\%hccapx_contents, $switch, $arg);
    }
    elsif ($switch eq "nonce_ap")
    {
      add_to_hccapxs (\%hccapx_contents, $switch, $arg);
    }
    elsif ($switch eq "mac_sta")
    {
      add_to_hccapxs (\%hccapx_contents, $switch, $arg);
    }
    elsif ($switch eq "nonce_sta")
    {
      add_to_hccapxs (\%hccapx_contents, $switch, $arg);
    }
    elsif ($switch eq "eapol_len")
    {
      add_to_hccapxs (\%hccapx_contents, $switch, $arg);
    }
    elsif ($switch eq "eapol")
    {
      add_to_hccapxs (\%hccapx_contents, $switch, $arg);

      # special case: automatically add the length too:
      add_to_hccapxs (\%hccapx_contents, "eapol_len", length ($arg) / 2);
    }

    $switch = "";
  }
  else
  {
    if (($arg eq "-h") || ($arg eq "--help"))
    {
      usage ();

      exit (0);
    }
    elsif (($arg eq "-o") || ($arg eq "--outfile"))
    {
      $switch = "outfile";
    }
    elsif (($arg eq "-H") || ($arg eq "--hccapx-version"))
    {
      $switch = "version";
    }
    elsif (($arg eq "-M") || ($arg eq "--message-pair"))
    {
      $switch = "message_pair";
    }
    elsif (($arg eq "-e") || ($arg eq "--essid"))
    {
      $switch = "essid";
    }
    elsif (($arg eq "-v") || ($arg eq "--key-version"))
    {
      $switch = "keyver";
    }
    elsif (($arg eq "-k") || ($arg eq "--key-mic"))
    {
      $switch = "keymic";
    }
    elsif (($arg eq "-b") || ($arg eq "--bssid"))
    {
      $switch = "mac_ap";
    }
    elsif (($arg eq "-a") || ($arg eq "--anonce"))
    {
      $switch = "nonce_ap";
    }
    elsif (($arg eq "-m") || ($arg eq "--mac-sta"))
    {
      $switch = "mac_sta";
    }
    elsif (($arg eq "-s") || ($arg eq "--snonce"))
    {
      $switch = "nonce_sta";
    }
    elsif (($arg eq "-E") || ($arg eq "--eapol"))
    {
      $switch = "eapol";
    }
    else
    {
      print STDERR "ERROR: unknown command line argument. Please check the usage: \n\n";

      usage ();

      exit (1);
    }
  }
}

# check if hccapx_contents was correctly set

my $error_msg = "";
my $check = check_hccapxs (\%hccapx_contents, \$error_msg);

if ($check == 1)
{
  get_interactive_input (\%hccapx_contents);

  my $check_again = check_hccapxs (\%hccapx_contents, \$error_msg);

  if ($check_again != 0)
  {
    if (length ($error_msg))
    {
      print STDERR "ERROR: $error_msg\n";
    }
    else
    {
      print STDERR "ERROR: an unexpected error occurred\n";
    }

    exit (1);
  }
}
elsif ($check == 2)
{
  # not empty, but we have detected some error(s)

  print STDERR "ERROR: $error_msg\n";

  exit (1);
}


# output file handling

my $fp;

if ($outfile eq "")
{
  $outfile = $DEFAULT_OUTFILE;

  my $warning_shown = 0;

  while (-e $outfile)
  {
    $outfile .= "_new.hccapx";

    if ($warning_shown == 0)
    {
      print STDERR "WARNING: the default output file does already exist. Therefore, '$outfile' was used as outfile, otherwise the file would be overridden\n";
      print STDERR "(if you want to disable this behavior you should set the --outfile argument)\n";

      $warning_shown = 1;
    }
  }
}

if (! open ($fp, ">$outfile"))
{
  print STDERR "ERROR: could not open the output file '$outfile'\n";

  exit (1);
}

# write to hccapx file

write_hccapx ($fp, \%hccapx_contents);

# done / cleanup

print ".hccapx file '$outfile' was successfully written\n";

close ($fp);

exit (0);
