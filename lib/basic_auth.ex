defmodule BasicAuth do

  @moduledoc """
  Plug for adding basic authentication. Usage:

  plug BasicAuth, use_config: {:your_app, :your_key}

  Where :your_app and :your_key should refer to values in your application config.

  In your configuration you can set values directly, eg

  ```

  config :your_app, your_config: [
    username: "admin",
    password: "simple_password",
    realm: "Admin Area"
  ]
  ```

  or choose to get one (or all) from environment variables, eg

  ```
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
  plug BasicAuth, callback: &User.find_by_username_and_password/3, realm: "My super realm"
  ```

  Where :callback is your custom authentication function that takes a conn, username and a
  password and returns a conn.  Your function must return `Plug.Conn.halt(conn)` if authentication
  fails, otherwise you can use `Plug.Conn.assign(conn, :current_user, ...)` to enhance
  the conn with variables or session for your controller.
  """

  defstruct username: nil, password: nil, realm: nil

  def init([use_config: {app, config_key} = config_options]) do
    configuration = Application.fetch_env!(app, config_key)

    %__MODULE__{username: config_option(config_options, configuration, :username),
                password: config_option(config_options, configuration, :password),
                realm:    config_option(config_options, configuration, :realm)}
  end

  def init([callback: callback, realm: realm]) do
    %{callback: callback, realm: realm}
  end

  def init([callback: callback]) do
    %{callback: callback, realm: "Basic Authentication"}
  end

  def init(_) do
    raise ArgumentError, """

    Usage of BasicAuth using application config:
    plug BasicAuth, use_config: {:your_app, :your_key}

    -OR-
    Using custom authentication function:
    plug BasicAuth, callback: &MyCustom.function/3

    Where :callback takes a conn, username and password and returns a conn.
    """
  end

  def call(conn, options) do
    header_content = Plug.Conn.get_req_header(conn, "authorization")
    respond(conn, header_content, options)
  end

  defp respond(conn, ["Basic " <> encoded_string], options) do
    [username, password] = encoded_string
    |> Base.decode64!
    |> String.split(":")
    respond(conn, username, password, options)
  end

  defp respond(conn, _, options) do
    send_unauthorized_response(conn, options)
  end

  defp respond(conn, username, password, %{callback: callback}) do
    conn = callback.(conn, username, password)
    if conn.halted do
      send_unauthorized_response(conn, %{})
    else
      conn
    end
  end

  defp respond(conn, username, password, %{username: config_usr, password: config_pwd, realm: realm}) do
    if {username, password} == {to_value(config_usr), to_value(config_pwd)} do
      conn
    else
      send_unauthorized_response(conn, %{realm: realm})
    end
  end

  defp config_option({app, config_key}, configuration, key) do
    Keyword.get(configuration, key) ||
      raise ArgumentError, """
      BasicAuth configuration value missing, in #{inspect app}, #{inspect config_key}, for option #{inspect key}.
      """
  end

  defp send_unauthorized_response(conn, %{realm: realm}) do
    conn
    |> Plug.Conn.put_resp_header("www-authenticate", "Basic realm=\"#{to_value(realm)}\"")
    |> Plug.Conn.send_resp(401, "401 Unauthorized")
    |> Plug.Conn.halt
  end

  defp send_unauthorized_response(conn, _) do
    conn
    |> Plug.Conn.send_resp(401, "401 Unauthorized")
    |> Plug.Conn.halt
  end

  defp to_value({:system, env_var}), do: System.get_env(env_var)
  defp to_value(value), do: value
end
