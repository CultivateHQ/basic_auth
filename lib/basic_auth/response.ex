defmodule BasicAuth.Response do
  @moduledoc """
  Adds unauthorised headers to the connection.
  """

  @default_realm "Basic Authentication"

  def unauthorise(conn, realm, custom_response) do
    conn
    |> Plug.Conn.put_resp_header("www-authenticate", "Basic realm=\"#{realm || @default_realm}\"")
    |> set_header_with_body(custom_response)
  end

  defp set_header_with_body(conn, custom_response) when is_function(custom_response) do
    custom_response.(conn)
  end
  defp set_header_with_body(conn, _) do
    conn
    |> Plug.Conn.put_resp_content_type("text/plain")
    |> Plug.Conn.send_resp(401, "401 Unauthorized")
  end

end
