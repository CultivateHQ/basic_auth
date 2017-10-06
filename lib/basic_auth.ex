defmodule BasicAuth do

  @moduledoc """
  Plug for adding basic authentication.
  """

  @default_realm "Basic Authentication"

  defmodule Configuration do
    @moduledoc false
    defstruct  config_options: nil
  end

  defmodule Callback do
    @moduledoc false
    defstruct callback: nil, realm: nil
  end

  defmodule TokenCallback do
    @moduledoc false
    defstruct callback: nil, realm: nil
  end


  def init([use_config: config_options]) do
    %Configuration{config_options: config_options}
  end

  def init(options) when is_list(options) do
    callback = Keyword.fetch!(options, :callback)
    realm = Keyword.get(options, :realm, @default_realm)
    case :erlang.fun_info(callback)[:arity] do
      2 -> %TokenCallback{callback: callback, realm: realm}
      3 -> %Callback{callback: callback, realm: realm}
      _ -> raise(ArgumentError, "Callback must be of arity 2 (for connection and key) or 3 (for connection, username, and password).")
    end
  end

  def init(_) do
    raise ArgumentError, """

    Usage of BasicAuth using application config:
    plug BasicAuth, use_config: {:your_app, :your_config}

    -OR-
    Using custom authentication function:
    plug BasicAuth, callback: &MyCustom.function/3

    Where :callback takes either
    * a conn, username and password and returns a conn.
    * a conn and a key and returns a conn
    """
  end

  def call(conn, options) do
    header_content = Plug.Conn.get_req_header(conn, "authorization")
    respond(conn, header_content, options)
  end

  defp respond(conn, ["Basic " <> encoded], options) do
    case Base.decode64(encoded) do
      {:ok, token} -> check_token(conn, token, options)
      _ ->
        send_unauthorized_response(conn, options)
    end
  end

  defp respond(conn, _, options) do
    send_unauthorized_response(conn, options)
  end

  defp check_token(conn, token, options = %Callback{callback: callback}) do
    case String.split(token, ":", parts: 2) do
      [username, password] ->
        conn
        |> callback.(username, password)
        |> check_callback_response(options)
      _ ->
        send_unauthorized_response(conn, options)
    end
  end
  defp check_token(conn, token, options = %TokenCallback{callback: callback}) do
    conn
    |> callback.(token)
    |> check_callback_response(options)
  end
  defp check_token(conn, token, %Configuration{config_options: config_options}) do
    if token  == configured_token(config_options) do
      conn
    else
      send_unauthorized_response(conn, %{realm: realm(config_options)})
    end
  end

  defp check_callback_response(conn, config_options) do
    if conn.halted do
      send_unauthorized_response(conn, config_options)
    else
      conn
    end
  end


  defp send_unauthorized_response(conn, %Configuration{config_options: config_options}) do
    conn
    |> Plug.Conn.put_resp_header("www-authenticate", "Basic realm=\"#{realm(config_options)}\"")
    |> Plug.Conn.send_resp(401, "401 Unauthorized")
    |> Plug.Conn.halt
  end

  defp send_unauthorized_response(conn, %{realm: realm}) do
    conn
    |> Plug.Conn.put_resp_header("www-authenticate", "Basic realm=\"#{realm}\"")
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

  defp configured_token(config_options) do
    case credential_part(config_options, :token, nil) do
      nil -> username(config_options) <> ":" <> password(config_options)
      token -> token
    end
  end

  defp username(config_options), do: credential_part(config_options, :username)

  defp password(config_options), do: credential_part(config_options, :password)

  defp realm(config_options), do: credential_part(config_options, :realm, @default_realm)

  defp credential_part({app, key}, part, default) do
    value = app
    |> Application.fetch_env!(key)
    |> Keyword.get(part)
    |> to_value()
    value || default
  end

  defp credential_part(config_options, part) do
    case credential_part(config_options, part, nil) do
      nil -> raise(ArgumentError, "Missing #{inspect(part)} or :token from #{inspect(config_options)}")
      value -> value
    end
  end
end
