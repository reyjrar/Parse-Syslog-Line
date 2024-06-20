# This file is generated by Dist::Zilla::Plugin::CPANFile v6.032
# Do not edit this file directly. To change prereqs, edit the `dist.ini` file.

requires "Carp" => "0";
requires "Const::Fast" => "0";
requires "Data::Printer" => "0";
requires "English" => "0";
requires "Exporter" => "0";
requires "Getopt::Long::Descriptive" => "0";
requires "HTTP::Date" => "0";
requires "JSON::MaybeXS" => "0";
requires "Module::Load" => "0";
requires "Module::Loaded" => "0";
requires "POSIX" => "0";
requires "Pod::Usage" => "0";
requires "Ref::Util" => "0";
requires "YAML::XS" => "0";
requires "perl" => "5.014";
requires "strict" => "0";
requires "warnings" => "0";
recommends "Cpanel::JSON::XS" => "0";

on 'test' => sub {
  requires "CLI::Helpers" => "0";
  requires "Data::Dumper" => "0";
  requires "DateTime" => "1.23";
  requires "DateTime::TimeZone" => "2.13";
  requires "Digest::MD5" => "0";
  requires "File::Spec" => "0";
  requires "FindBin" => "0";
  requires "IO::Handle" => "0";
  requires "IPC::Open3" => "0";
  requires "Path::Tiny" => "0";
  requires "Storable" => "0";
  requires "Test::Deep" => "0";
  requires "Test::MockTime" => "0";
  requires "Test::More" => "0";
  requires "Time::Moment" => "0";
  requires "YAML" => "0";
  requires "bignum" => "0";
  requires "lib" => "0";
  requires "perl" => "5.014";
};

on 'configure' => sub {
  requires "ExtUtils::MakeMaker" => "0";
  requires "perl" => "5.014";
};

on 'develop' => sub {
  requires "Pod::Coverage::TrustPod" => "0";
  requires "Test::EOL" => "0";
  requires "Test::More" => "0.88";
  requires "Test::NoTabs" => "0";
  requires "Test::Pod" => "1.41";
  requires "Test::Pod::Coverage" => "1.08";
};
