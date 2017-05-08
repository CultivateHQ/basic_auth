# BasicAuth

This is an Elixir Plug for adding basic authentication into an application.

The plug can be configured to use:

1) Static username and password in application configuration

-OR-

2) Your own custom authentication function

## Breaking change

Note that putting values directly into the plug is no longer supported.

```elixir

## NO LONGER SUPPORTED

plug BasicAuth, realm: "realm", password: "password", username: "username"
```

## How to use

Add the package as a dependency in your Elixir project using something along the lines of:
```elixir
  defp deps do
    [{:basic_auth, "~> 2.0.0"}]
  end
```

Add into the top of a controller, or into a router pipeline a plug declaration like:

```elixir
plug BasicAuth, use_config: {:your_app, :your_key}
```

  Where :your_app and :your_key should refer to values in your application config.

  In your configuration you can set values directly, eg

  ```elixir

  config :your_app, your_config: [
    username: "admin",
    password: "simple_password",
    realm: "Admin Area"
  ]
  ```

  or choose to get one (or all) from environment variables, eg

  ```elixir
  config :basic_auth, my_auth_with_system: [
    username: {:system, "BASIC_AUTH_USERNAME"},
    password: {:system, "BASIC_AUTH_PASSWORD"},
    realm:    {:system, "BASIC_AUTH_REALM"}
  ]
  ```

Alternatively you can provide a custom function to the plug to authenticate the user any way
you want, such as finding the user from a database.

```elixir
  plug BasicAuth, callback: &User.find_by_username_and_password/3
```

  (or optionally provide a realm)

```elixir
  plug BasicAuth, callback: &User.find_by_username_and_password/3, realm: "Area 51"
```

  Where :callback is your custom authentication function that takes a conn, username and a
  password and returns a conn.  Your function must return `Plug.Conn.halt(conn)` if authentication
  fails, otherwise you can use `Plug.Conn.assign(conn, :current_user, ...)` to enhance
  the conn with variables or session for your controller.

Easy as that!

### Authenticating only for specific actions

If you're looking to authenticate only for a subset of actions in a controller you can use plug's `when action in` syntax as shown below

  ```elixir
    plug BasicAuth, [use_config: {: your_app, : your_key}] when action in [:edit, :delete]
  ```

  additionally you can exclude specific actions using `not`

  ```elixir
    plug BasicAuth, [use_config: {: your_app, : your_key}] when not action in [:index, :show]
  ```

## Specify controllers that use Basic Auth

If you want to use Basic Auth only for designated controllers, you can do so by modifying `web/router.ex`

```elixir
# web/router.ex

# create a new pipeline like this
pipeline :basic_auth do
  plug BasicAuth, Application.get_env(:the_app, :basic_auth)
  plug :accepts, ["html"]
  plug :fetch_session
  plug :fetch_flash
  plug :protect_from_forgery
  plug :put_secure_browser_headers
end

# and a scope
scope "/", TheApp do
  pipe_through :basic_auth

  resources "/users", UserController
end
```

## Testing controllers with Basic Auth

If you're storing credentials within configuration files, we can reuse them within our test files
directly using snippets like `Application.get_env(:basic_auth)[:username]`.

### Update Tests to insert a basic authentication header

Any controller that makes use of basic authentication, will need an additional header injected into
the connection in order for your tests to continue to work. The following is a brief snippet of how
to get started. There is a more detailed
[blog post](http://www.cultivatehq.com/posts/add-basic-authentication-to-a-phoenix-application/) that
explains a bit more about what needs to be done.

At the top of my controller test I have something that looks like:

```elixir
@username Application.get_env(:the_app, :basic_auth)[:username]
@password Application.get_env(:the_app, :basic_auth)[:password]

defp using_basic_auth(conn, username, password) do
  header_content = "Basic " <> Base.encode64("#{username}:#{password}")
  conn |> put_req_header("authorization", header_content)
end
```

Then for any tests, I can simply pipe in this helper method to the connection process:
```elixir
test "GET / successfully renders when basic auth credentials supplied" do
  conn = conn
    |> using_basic_auth(@username, @password)
    |> get("/admin/users")

  assert html_response(conn, 200) =~ "Users"
end
```

And a test case without basic auth for completeness:
```elixir
test "GET / without basic auth credentials prevents access" do
  conn = conn
    |> get("/admin/users")

  assert response(conn, 401) =~ "401 Unauthorized"
end
```
