defmodule BasicAuth.Response do
  @moduledoc """
  Adds unauthorised headers to the connection.
  """

  @default_realm "Basic Authentication"

  def unauthorise(conn, realm) do
    conn
    |> Plug.Conn.put_resp_header("www-authenticate", "Basic realm=\"#{realm || @default_realm}\"")
    |> Plug.Conn.put_resp_content_type("text/plain")
    |> Plug.Conn.send_resp(401, "401 Unauthorized")
  end
end
