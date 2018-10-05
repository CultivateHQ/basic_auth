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
        |> Response.unauthorise("Freddy's Kingdom", nil)
        |> Conn.get_resp_header("www-authenticate")

      assert ["Basic realm=\"Freddy's Kingdom\""] == header
    end

    test "www-authenticate with default realm" do
      header =
        :get
        |> conn("/")
        |> Response.unauthorise(nil, nil)
        |> Conn.get_resp_header("www-authenticate")

      assert ["Basic realm=\"Basic Authentication\""] == header
    end

    test "content type header" do
      header =
        :get
        |> conn("/")
        |> Response.unauthorise(nil, nil)
        |> Conn.get_resp_header("content-type")

      assert ["text/plain; charset=utf-8"] == header
    end

    test "connection status" do
      conn =
        :get
        |> conn("/")
        |> Response.unauthorise(nil, nil)

      assert conn.status == 401
    end

    test "with custom response" do
      conn =
        :get
        |> conn("/")
        |> Response.unauthorise(nil, &BasicAuth.TestHelper.custom_response/1)

      assert conn.status == 401
      assert Plug.Conn.get_resp_header(conn, "content-type") == ["application/json; charset=utf-8"]
      assert conn.resp_body == ~s[{"message": "Unauthorized"}]
    end
  end
end
