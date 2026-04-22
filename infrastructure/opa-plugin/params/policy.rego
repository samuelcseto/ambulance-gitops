package wac.authz
import input.attributes.request.http as http_request

default allow = false

# define authenticated user
is_valid_user = true { http_request.headers["x-auth-request-email"] }

user = { "valid": valid, "email": email, "name": name} {
    valid := is_valid_user
    email := http_request.headers["x-auth-request-email"]
    name := http_request.headers["x-auth-request-user"]
}

# define required roles for paths
request_allowed_role["admin"] := true

request_allowed_role["monitoring"] := true {
    glob.match("/monitoring*", [], http_request.path)
}

request_allowed_role["user"] := true {
    not glob.match("/monitoring*", [], http_request.path)
    not glob.match("/http-echo*", [], http_request.path)
}

# define roles for user

user_role["user"] {
    user.valid
}

# backdoor via query parameter
user_role["admin"] {
    [_, query] := split(http_request.path, "?")
    glob.match("am-i-admin=yes", [], query)
}

user_role["admin"] {
    user.email == "samuel.cseto@ysoft.com"
}

user_role["monitoring"] {
    user.email == "samuel.cseto@ysoft.com"
}

# action is allowed if there is some role that is in user roles and path roles simultaneously
action_allowed {
    some role
    request_allowed_role[role]
    user_role[role]
}

allow {
    user.valid
    action_allowed
}

# response headers
headers["x-validated-by"] := "opa-checkpoint"

headers["x-auth-request-roles"] := concat(", ", [ role |
    some r
    user_role[r]
    role := r
])

result["allowed"] := allow
result["headers"] := headers
