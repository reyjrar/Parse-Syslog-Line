use inc::Module::Install;

# Module Information
name			'Parse-Syslog-Line';
perl_version	'5.008';
all_from		'lib/Parse/Syslog/Line.pm';

# Requirements
test_requires	'Test::More'				=> 0;
requires		'Readonly'					=> 0;
requires		'DateTime'					=> 0;
requires		'DateTime::Format::HTTP'	=> 0;

WriteAll();
