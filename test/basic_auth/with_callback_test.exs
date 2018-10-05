defmodule BasicAuth.WithCallbackTest do
  use ExUnit.Case, async: true
  use Plug.Test
  import BasicAuth.TestHelper,
    only: [
      call_without_credentials: 1,
      call_with_credentials: 2,
      custom_response: 1
    ]

  defmodule User do
    def find_by_username_and_password(conn, "robert", "secret:value"), do: conn
    def find_by_username_and_password(conn, _, _), do: Plug.Conn.halt(conn)
  end

  defmodule PlugWithCallback do
    use DemoPlug, callback: &User.find_by_username_and_password/3
  end

  defmodule PlugWithCallbackAndRealm do
    use DemoPlug, callback: &User.find_by_username_and_password/3, realm: "Bob's Kingdom"
  end

  defmodule PlugWithCallbackAndCustomResponse do
    use DemoPlug, callback: &User.find_by_username_and_password/3, custom_response: &custom_response/1
  end

  test "no credentials provided" do
    conn = call_without_credentials(PlugWithCallback)
    assert conn.status == 401

    assert Plug.Conn.get_resp_header(conn, "www-authenticate") == [
             "Basic realm=\"Basic Authentication\""
           ]
  end

  test "with custom realm" do
    conn = call_with_credentials(PlugWithCallbackAndRealm, "wrong:wrong")

    assert Plug.Conn.get_resp_header(conn, "www-authenticate") == [
             "Basic realm=\"Bob's Kingdom\""
           ]
  end

  test "wrong credentials provided" do
    conn = call_with_credentials(PlugWithCallback, "wrong:password")
    assert conn.status == 401
  end

  test "right credentials provided" do
    conn = call_with_credentials(PlugWithCallback, "robert:secret:value")
    assert conn.status == 200
  end

  test "incorrect basic auth formatting returns a 401" do
    conn = call_with_credentials(PlugWithCallback, "robert")
    assert conn.status == 401
  end

  test "unauthorised with custom response return a 401 and custom header and body" do
    conn = call_with_credentials(PlugWithCallbackAndCustomResponse, "wrong:wrong")

    assert conn.status == 401
    assert Plug.Conn.get_resp_header(conn, "content-type") == ["application/json; charset=utf-8"]
    assert conn.resp_body == ~s[{"message": "Unauthorized"}]
  end
end
