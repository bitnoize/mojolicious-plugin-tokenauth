#!/usr/bin/env perl

use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
  NAME          => "Mojolicious::Plugin::TokenAuth",
  VERSION_FROM  => "lib/Mojolicious/Plugin/TokenAuth.pm",
  ABSTRACT      => "JWT authentication for your Mojolicious app",
  LICENSE       => 'artistic_2',
  AUTHOR        => "Dmitry Krutikov <mitya\@whteam.net>",
  PREREQ_PM     => {
    "Mojolicious" => '8.12',
    "Mojo::JWT"   => '0.08'
  },
  test => { TESTS => 't/*.t' }
);
