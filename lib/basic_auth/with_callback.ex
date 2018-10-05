defmodule BasicAuth.WithCallback do
  @moduledoc """
  Basic auth plugin functions callback to a provided function with credentials
  """

  import BasicAuth.Response, only: [unauthorise: 3]

  defstruct callback: nil, realm: nil, custom_response: nil

  def init(options) when is_list(options) do
    callback = Keyword.fetch!(options, :callback)
    realm = Keyword.get(options, :realm)
    custom_response = Keyword.get(options, :custom_response)

    case :erlang.fun_info(callback)[:arity] do
      3 ->
        %__MODULE__{callback: callback, realm: realm, custom_response: custom_response}

      _ ->
        raise(
          ArgumentError,
          "Callback must be of arity 3 for connection, username, and password."
        )
    end
  end

  def respond(conn, ["Basic " <> encoded], options) do
    case Base.decode64(encoded) do
      {:ok, token} ->
        check_token(conn, token, options)

      _ ->
        halt_and_unauthorise_response(conn, options)
    end
  end

  def respond(conn, _, options) do
    halt_and_unauthorise_response(conn, options)
  end

  defp check_token(conn, token, options = %__MODULE__{callback: callback}) do
    case String.split(token, ":", parts: 2) do
      [username, password] ->
        conn
        |> callback.(username, password)
        |> check_callback_response(options)

      _ ->
        halt_and_unauthorise_response(conn, options)
    end
  end

  defp check_callback_response(conn, config_options) do
    if conn.halted do
      send_unauthorised_response(conn, config_options)
    else
      conn
    end
  end

  defp send_unauthorised_response(conn, %{realm: realm, custom_response: custom_response}) do
    unauthorise(conn, realm, custom_response)
  end

  defp halt_and_unauthorise_response(conn, %{realm: realm, custom_response: custom_response}) do
    conn
    |> unauthorise(realm, custom_response)
    |> Plug.Conn.halt()
  end
end
