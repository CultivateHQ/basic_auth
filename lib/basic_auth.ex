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

  """

  defstruct username: nil, password: nil, realm: nil

  def init([use_config: {app, config_key} = config_options]) do
    configuration = Application.fetch_env!(app, config_key)

    %__MODULE__{username: config_option(config_options, configuration, :username),
                password: config_option(config_options, configuration, :password),
                realm:    config_option(config_options, configuration, :realm)}
  end

  def init([callback: callback]) do
    %{callback: callback}
  end

  def init(_) do
    raise ArgumentError, """

    Usage of BasicAuth is:
    plug BasicAuth, use_config: {:your_app, :your_key}

    Where :your_app and :your_key should refer to values in your application config. 

    OR

    plug BasicAuth, callback: &your_function/2

    Where your_function takes a username and password and returns a boolean.  Your your_function
    can check a database for example.
    """
  end

  def call(conn, options) do
    header_content = Plug.Conn.get_req_header(conn, "authorization")
    respond(valid_credentials?(header_content, options), conn, options)
  end

  defp respond(true, conn, _), do: conn
  defp respond(false, conn, options), do: send_unauthorized_response(conn, options)

  defp config_option({app, config_key}, configuration, key) do
    Keyword.get(configuration, key) ||
      raise ArgumentError, """
      BasicAuth configuration value missing, in #{inspect app}, #{inspect config_key}, for option #{inspect key}.
      """
  end

  defp valid_credentials?(["Basic " <> encoded_string], %{callback: callback}) do
    [username, password] = Base.decode64!(encoded_string) |> String.split(":")
    callback.(username, password)
  end
  defp valid_credentials?(["Basic " <> encoded_string], %{username: username, password: password}) do
    Base.decode64!(encoded_string) == "#{to_value(username)}:#{to_value(password)}"
  end
  defp valid_credentials?(_,_), do: false

  defp send_unauthorized_response(conn, %{realm: realm}) do
    conn
    |> Plug.Conn.put_resp_header("www-authenticate", "Basic realm=\"#{to_value(realm)}\"")
    |> Plug.Conn.send_resp(401, "401 Unauthorized")
    |> Plug.Conn.halt
  end

  defp send_unauthorized_response(conn, %{}) do
    conn
    |> Plug.Conn.send_resp(401, "401 Unauthorized")
    |> Plug.Conn.halt
  end

  defp to_value({:system, env_var}), do: System.get_env(env_var)
  defp to_value(value), do: value
end
