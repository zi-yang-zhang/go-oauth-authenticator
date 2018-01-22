# go-oauth-authenticator
Go OAuth authenticator

Supports Google JWT token Authentication

Need to pass in
```
{
  google:<clientID>
}
```
to
```New(authParams map[string]interface{})``` for creating `AuthenticationProvider`.

Customized `Authenticator` can be added through `AuthenticationProvider.Authenticators`.

Parsed JWT info(`AuthenticationInfo`) is returned through `AuthenticationProvider.Authenticate(authorization_header)`
