# BasicAuth

This is an Elixir Plug for adding basic authentication into an application.

## How to use

Add the package as a dependency in your Elixir project using something along the lines of:
```elixir
  defp deps do
    [{:basic_auth, "~> 1.0.0"}]
  end
```

Add into the top of a controller, or into a router pipeline a plug declaration like:
```elixir
plug BasicAuth, realm: "Admin Area", username: "admin", password: "secret"
```

Easy as that!

## Storing credentials for deployment / testing

The above example is great to get going with basic auth, and depending on your use case,
might be everything you need. Generally speaking, we don't want to store credentials in version
control for security reasons.

### Store credentials in config files

Instead of passing credentials into the plug directly, we can pass a `use_config` option to the plug to tell
it we want to use some variables we've stored in config files:

```elixir
  # inside router or controller file
  plug BasicAuth, Application.get_env(:the_app, :basic_auth)
```

And then we can setup some configuration using something like the following:

```elixir
# dev.exs, test.exs
config :the_app, :basic_auth, [
  realm: "Admin Area",
  username: "sample",
  password: "sample"
]
```

```elixir
# config/prod.secret.exs
config :the_app, :basic_auth, [
  realm: "Admin Area",
  username: System.get_env("BASIC_AUTH_USER"),
  password: System.get_env("BASIC_AUTH_PASSWORD")
]
```

The example above for `config/prod.exs` makes use of system ENV vars. You could use String objects
if your `config/prod.exs` is outside of version control, but for environments like Heroku, it's easier
to use ENV vars for storing configuration.

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

  assert html_response(conn, 401) =~ "401 Unauthorized"
end
```
