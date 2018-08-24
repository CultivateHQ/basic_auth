defmodule BasicAuth.TestHelper do
  use Plug.Test

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
end
