package Mojolicious::Plugin::TokenAuth;
use Mojo::Base "Mojolicious::Plugin";

## no critic
our $VERSION = '1.05_008';
$VERSION = eval $VERSION;
## use critic

use Scalar::Util qw/looks_like_number/;
use Mojo::JWT;

sub VALIDATE_REGEX  { qr/^[a-z0-9\-_.]{16,4096}$/i }
sub DEFAULT_EXPIRES { 900 }

sub register {
  my ($self, $app, $conf) = @_;

  $conf->{encode}   //= sub { {} };
  $conf->{decode}   //= sub { {} };
  $conf->{expires}  //= DEFAULT_EXPIRES;
  $conf->{secret}   //= $app->secrets->[-1] // $app->moniker;

  $app->log->warn("JWT default secret is not secure!")
    if $conf->{secret} eq $app->moniker;

  $app->helper(token_verify => sub {
    my ($c, $credentials, %opts) = @_;

    my $secret = $opts{secret} // $conf->{secret};

    $app->log->debug("Token verify malformed credentials") and return
      unless $credentials and $credentials =~ VALIDATE_REGEX;

    my $jwt = Mojo::JWT->new(secret => $secret);

    my $claims = eval { $jwt->decode($credentials) };

    $app->log->debug("Token verify decode error: $@") and return if $@;

    $app->log->debug("Token verify broken decode") and return
      unless $claims and ref $claims eq 'HASH';

    $app->log->error("Token verify wrong service") and return
      unless $claims->{iss} and $claims->{iss} eq $app->moniker;

    $app->log->error("Token verify wrong created") and return
      unless looks_like_number $claims->{iat};

    $app->log->error("Token verify wrong expires") and return
      unless looks_like_number $claims->{exp};

    my $decode = eval { $conf->{decode}->($claims) };

    $app->log->debug("Token verify decode error: $@") and return if $@;

    $app->log->debug("Token verify broken decode") and return
      unless $decode and ref $decode eq 'HASH';

    my $token = {
      expires => $claims->{exp},
      created => $claims->{iat},
      %$decode
    };

    return $token;
  });

  $app->helper(token_issue => sub {
    my ($c, $token, %opts) = @_;

    my $secret  = $opts{secret}   // $conf->{secret};
    my $expires = $opts{expires}  // $conf->{expires};

    my $encode = eval { $conf->{encode}->($token) };

    $app->log->debug("Token issue encode error: $@") and return if $@;

    $app->log->debug("Token issue broken encode") and return
      unless $encode and ref $encode eq 'HASH';

    my $jwt = Mojo::JWT->new(secret => $secret, set_iat => 1);

    $jwt->claims({ iss => $app->moniker, %$encode });
    $jwt->expires($jwt->now + $expires);

    return $jwt->encode, $jwt->expires;
  });
}

1;
