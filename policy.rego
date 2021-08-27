package envoy.authz

import input.attributes.request.http as http_request

permissions := {
  "people.get": {"method": "GET", "object": "people"},
  "people.post": {"method": "POST", "object": "people"},
  "people.delete": {"method": "DELETE", "object": "people"}
}

role_permissions := {
  "guest": [
    permissions["people.get"]
  ],
  "admin": [
    permissions["people.get"],
    permissions["people.post"],
    permissions["people.delete"]
  ]
}

default allow = false

allow {
    is_token_valid
    action_allowed
    not deny_same_first_name
}

is_token_valid {
  token.valid
  now := time.now_ns() / 1000000000
  token.payload.nbf <= now
  now < token.payload.exp
}

action_allowed {
  object_name := split(http_request.path, "/")
  permissions := role_permissions[token.payload.role]
  p := permissions[_]
  p == {"method": http_request.method, "object": object_name[1]}
}

deny_same_first_name {
  lower(input.parsed_body.firstname) == base64url.decode(token.payload.sub)
}

token := {"valid": valid, "payload": payload} {
    [_, encoded] := split(http_request.headers.authorization, " ")
    [valid, _, payload] := io.jwt.decode_verify(encoded, {"secret": "secret"})
}
