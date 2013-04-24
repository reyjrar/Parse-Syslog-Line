

# Installer for probe_summ

use strict;

use ExtUtils::MakeMaker 6.630;

WriteMakefile(
  NAME              => 'Parse::Syslog::Line',
  ABSTRACT          => 'Simple syslog line parser',
  VERSION           => '1.2',
  MIN_PERL_VERSION  => 5.012,
  SIGN              => 1,
  PREREQ_PM         => {
        'POSIX'                   => 1.300,
        'Time::Local'             => 1.200,
        'DateTime::Format::HTTP'  => 0.400,
  }
);
