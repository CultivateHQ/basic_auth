defmodule BasicAuth.ResponseTest do
  use ExUnit.Case, async: true
  use Plug.Test
  alias Plug.Conn
  alias BasicAuth.Response

  describe "unauthorise" do
    test "www-authenticate with supplied realm" do
      header =
        :get
        |> conn("/")
        |> Response.unauthorise("Freddy's Kingdom")
        |> Conn.get_resp_header("www-authenticate")

      assert ["Basic realm=\"Freddy's Kingdom\""] == header
    end

    test "www-authenticate with default realm" do
      header =
        :get
        |> conn("/")
        |> Response.unauthorise(nil)
        |> Conn.get_resp_header("www-authenticate")

      assert ["Basic realm=\"Basic Authentication\""] == header
    end

    test "content type header" do
      header =
        :get
        |> conn("/")
        |> Response.unauthorise(nil)
        |> Conn.get_resp_header("content-type")

      assert ["text/plain; charset=utf-8"] == header
    end

    test "connection status" do
      conn =
        :get
        |> conn("/")
        |> Response.unauthorise(nil)

      assert conn.status == 401
    end
  end
end
