defmodule BasicAuth.TestHelper do
  use Plug.Test

  @moduledoc """
  Adds some helper functions for use in tests.
  """

  def call_with_credentials(plug, authentication) do
    header_content = "Basic " <> Base.encode64(authentication)

    :get
    |> conn("/")
    |> put_req_header("authorization", header_content)
    |> plug.call([])
  end

  def call_without_credentials(plug) do
    :get
    |> conn("/")
    |> plug.call([])
  end

  def custom_response(conn) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(401, ~s[{"message": "Unauthorized"}])
  end
end
