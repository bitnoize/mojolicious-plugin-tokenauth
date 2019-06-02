package Mojolicious::Plugin::TokenAuth;
use Mojo::Base "Mojolicious::Plugin";

our $VERSION = "1.02_001";
$VERSION = eval $VERSION;

use Scalar::Util qw/looks_like_number/;
use Mojo::JWT;

use constant {
  VALIDATE_REGEX  => qr/^[a-zA-Z0-9\-_.]{16,1024}$/,
  DEFAULT_EXPIRES => 900
};


sub register {
  my ($self, $app, $conf) = @_;

  my $encode  = $conf->{encode}   ||= sub { {} };
  my $decode  = $conf->{decode}   ||= sub { {} };
  my $expires = $conf->{expires}  ||= DEFAULT_EXPIRES;

  #
  # Helpers
  #

  $app->helper(jwt => sub {
    my ($c) = @_;

    my $secret = $c->app->secrets->[0] || die "Unknown JWT secret";
    Mojo::JWT->new(set_iat => 1, secret => $secret);
  });

  $app->helper(token_verify => sub {
    my ($c, $token_type, $access_token) = @_;

    $c->render(status => 401) and return 0
      unless $token_type and lc $token_type eq 'bearer';

    $c->render(status => 401) and return 0
      unless $access_token and $access_token =~ VALIDATE_REGEX;

    my $claims = eval { $c->jwt->decode($access_token) };

    $c->render(status => 401) and return 0
      unless $claims and ref $claims eq 'HASH';

    die "Wrong access token service\n"
      unless $claims->{iss} and $claims->{iss} eq $app->moniker;

    die "Wrong access token created\n"
      unless looks_like_number $claims->{iat};

    die "Wrong access token expires\n"
      unless looks_like_number $claims->{exp};

    my $custom = $decode->($claims);

    die "Failed access token custom decode\n"
      unless $custom and ref $custom eq 'HASH';

    $c->stash(token => {
      expires => $claims->{exp},
      created => $claims->{iat},
      %$custom
    });

    return 1;
  });

  $app->helper(token_issue => sub {
    my ($c, $token) = @_;

    my $custom = $encode->($token);

    die "Failed access token custom encode\n"
      unless $custom and ref $custom eq 'HASH';

    my $jwt = $c->jwt->claims({
      iss => $app->moniker,
      %$custom
    });

    $jwt->expires($jwt->now + $expires);

    ($jwt->encode, $jwt->expires);
  });
}

1;
