package Mojolicious::Plugin::TokenAuth;
use Mojo::Base "Mojolicious::Plugin";

## no critic
our $VERSION = '1.05_001';
$VERSION = eval $VERSION;
## use critic

use Scalar::Util qw/looks_like_number/;
use Mojo::JWT;

sub VALIDATE_REGEX { qr/^[a-z0-9\-_.]{16,4096}$/i }
sub DEFAULT_EXPIRE { 900 }

sub register {
  my ($self, $app, $conf) = @_;

  $conf->{encode} //= sub { {} };
  $conf->{decode} //= sub { {} };
  $conf->{expire} //= DEFAULT_EXPIRE;
  $conf->{secret} //= $app->secrets->[-1];

  $app->log->warn("JWT secret is not secure!")
    if $conf->{secret} eq $app->moniker;

  $app->helper(token_verify => sub {
    my ($c, $access) = @_;

    return unless $access and $access =~ VALIDATE_REGEX;

    my $jwt = Mojo::JWT->new(
      secret  => $conf->{secret}
    );

    my $claims = eval { $c->jwt->decode($access) };

    $app->log->warn("Token verify decode error: $@") and return if $@;

    $app->log->warn("Token verify broken decode") and return
      unless $claims and ref $claims eq 'HASH';

    $app->log->error("Token verify wrong service") and return
      unless $claims->{iss} and $claims->{iss} eq $app->moniker;

    $app->log->error("Token verify wrong created") and return
      unless looks_like_number $claims->{iat};

    $app->log->error("Token verify wrong expires") and return
      unless looks_like_number $claims->{exp};

    my $custom = eval { $conf->{decode}->($claims) };

    $app->log->warn("Token verify custom error: $@") and return if $@;

    $app->log->warn("Token verify broken custom") and return
      unless $custom and ref $custom eq 'HASH';

    my $token = {
      expires => $claims->{exp},
      created => $claims->{iat},
      %$custom
    };

    return $token;
  });

  $app->helper(token_issue => sub {
    my ($c, $token) = @_;

    my $custom = eval { $conf->{encode}->($token) };

    $app->log->warn("Token issue custom error: $@") and return if $@;

    $app->log->warn("Token issue broken custom") and return
      unless $custom and ref $custom eq 'HASH';

    my $jwt = Mojo::JWT->new(
      secret  => $conf->{secret},
      set_iat => 1
    );

    $jwt->claims({
      iss => $app->moniker,
      %$custom
    });

    $jwt->expires($jwt->now + $conf->{expire});

    return ($jwt->encode, $jwt->expires);
  });
}

1;
