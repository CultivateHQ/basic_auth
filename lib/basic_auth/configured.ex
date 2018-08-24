defmodule BasicAuth.Configured do
  @moduledoc """
  Basic auth plugin functions that retrieve credentials from application config.
  """

  import BasicAuth.Response, only: [unauthorise: 2]

  defstruct config_options: nil

  alias Plug.Crypto

  def init(config_options) do
     %__MODULE__{config_options: config_options}
  end

  def respond(conn, params, options) do
    if skip_authentication?(options) do
      conn
    else
      authenticate(conn, params, options)
    end
  end

  def authenticate(conn, ["Basic " <> encoded], options) do
    case Base.decode64(encoded) do
      {:ok, token} -> check_token(conn, token, options)
      _ ->
        send_unauthorised_response(conn, options)
    end
  end
  def authenticate(conn, _, options) do
    send_unauthorised_response(conn, options)
  end

  defp check_token(conn, token, options = %__MODULE__{config_options: config_options}) do
    if Crypto.secure_compare(token, configured_token(config_options)) do
      conn
    else
      send_unauthorised_response(conn, options)
    end
  end

  defp send_unauthorised_response(conn, %__MODULE__{config_options: config_options}) do
    conn
    |> unauthorise(realm(config_options))
    |> Plug.Conn.halt()
  end

  defp to_value({:system, env_var}), do: System.get_env(env_var)
  defp to_value(value), do: value

  defp configured_token(config_options) do
    username!(config_options) <> ":" <> password!(config_options)
  end

  defp username(config_options), do: credential_part(config_options, :username)
  defp username!(config_options), do: credential_part!(config_options, :username)

  defp password(config_options), do: credential_part(config_options, :password)
  defp password!(config_options), do: credential_part!(config_options, :password)

  defp realm(config_options), do: credential_part(config_options, :realm)

  defp skip_if_no_credentials_configured(config_options), do: credential_part(config_options, :skip_if_no_credentials_configured)

  defp credential_part({app, key}, part) do
    app
    |> Application.fetch_env!(key)
    |> Keyword.get(part)
    |> to_value()
  end

  defp credential_part!(config_options, part) do
    case credential_part(config_options, part) do
      nil -> raise(ArgumentError, "Missing #{inspect(part)} from #{inspect(config_options)}")
      value -> value
    end
  end

  defp skip_authentication?(%__MODULE__{config_options: config_options}) do
    skip_if_no_credentials_configured(config_options) &&
      !username(config_options) &&
      !password(config_options)
  end
end
