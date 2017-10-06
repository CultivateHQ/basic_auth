defmodule BasicAuthTest do
 use ExUnit.Case, async: true
  use Plug.Test

  defmodule SimplePlug do
    use DemoPlug, use_config: {:basic_auth, :my_auth}
  end

  setup do
    Application.delete_env(:basic_auth, :my_auth)
    :ok
  end

  defp call_with_credentials(plug, authentication) do
    header_content = "Basic " <> Base.encode64(authentication)
    :get
    |> conn("/")
    |> put_req_header("authorization", header_content)
    |> plug.call([])
  end

  defp call_without_credentials(plug) do
    :get
    |> conn("/")
    |> plug.call([])
  end

  describe "custom function" do
    defmodule User do
      def find_by_username_and_password(conn, "robert", "secret:value"), do: conn
      def find_by_username_and_password(conn, _, _), do: Plug.Conn.halt(conn)
      def find_by_key(conn, "correctkey"), do: conn
      def find_by_key(conn, _), do: Plug.Conn.halt(conn)
    end

    defmodule PlugWithCallback do
      use DemoPlug, callback: &User.find_by_username_and_password/3
    end

    defmodule PlugWithCallbackAndRealm do
      use DemoPlug, callback: &User.find_by_username_and_password/3, realm: "Bob's Kingdom"
    end

    defmodule PlugWithKeyCallback do
      use DemoPlug, callback: &User.find_by_key/2
    end

    defmodule PlugWithKeyCallbackAndRealm do
      use DemoPlug, callback: &User.find_by_key/2, realm: "Bob's Kingdom"
    end

    test "no credentials provided" do
      conn = call_without_credentials(PlugWithCallback)
      assert conn.status == 401
      assert Plug.Conn.get_resp_header(conn, "www-authenticate") == [ "Basic realm=\"Basic Authentication\""]
    end

    test "with custom realm" do
      conn = call_with_credentials(PlugWithCallbackAndRealm, "wrong:wrong")
      assert Plug.Conn.get_resp_header(conn, "www-authenticate") == [ "Basic realm=\"Bob's Kingdom\""]
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

    test "with valid key callback" do
      conn = call_with_credentials(PlugWithKeyCallback, "correctkey")
      assert conn.status == 200
    end

    test "with invalid key callback" do
      conn = call_with_credentials(PlugWithKeyCallback, "wrongkey")
      assert conn.status == 401
    end

    test "key callback custom realm" do
      conn = call_with_credentials(PlugWithKeyCallbackAndRealm, "wrongkey")
      assert Plug.Conn.get_resp_header(conn, "www-authenticate") == [ "Basic realm=\"Bob's Kingdom\""]
    end
  end

  describe "with username and password from configuration" do

    setup do
      Application.put_env(:basic_auth, :my_auth, username: "admin",
        password: "simple:password", realm: "Admin Area")
    end

    test "no credentials returns a 401" do
      conn = call_without_credentials(SimplePlug)
      assert conn.status == 401
      assert Plug.Conn.get_resp_header(conn, "www-authenticate") == [ "Basic realm=\"Admin Area\""]
    end

    test "default realm" do
      Application.put_env(:basic_auth, :my_auth, username: "admin", password: "simple:password")
      conn = call_without_credentials(SimplePlug)
      assert Plug.Conn.get_resp_header(conn, "www-authenticate") == [ "Basic realm=\"Basic Authentication\""]
    end

    test "invalid credentials returns a 401" do
      conn = call_with_credentials(SimplePlug, "wrong:password")
      assert conn.status == 401
    end

    test "incorrect header returns a 401" do
      header_content = "Banana " <> Base.encode64("admin:simple:password")

      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> SimplePlug.call([])

      assert conn.status == 401
    end

    test "incorrect basic auth formatting returns a 401" do
      conn = call_with_credentials(SimplePlug, "bob")
      assert conn.status == 401
    end

    test "invalid basic auth base64 encoding returns a 401" do
      header_content = "Basic " <> "malformed base64"

      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> SimplePlug.call([])

      assert conn.status == 401
    end

    test "valid credentials returns a 200" do
      conn = call_with_credentials(SimplePlug, "admin:simple:password")
      assert conn.status == 200
    end
  end

  describe "using configured key instead of username and password" do
    setup do
      Application.put_env(:basic_auth, :my_auth, token: "mysecurekey")
    end

    test "is successful" do
      conn = call_with_credentials(SimplePlug, "mysecurekey")
      assert conn.status == 200
    end
  end

  describe "configured to get username and password from System" do

    setup do
      Application.put_env(:basic_auth, :my_auth, [
            username: {:system, "USERNAME"},
            password: {:system, "PASSWORD"},
            realm: {:system, "REALM"},
          ])
      :ok
    end

    test "username and password" do
      System.put_env("USERNAME", "bananauser")
      System.put_env("PASSWORD", "banana:password")

      conn = call_with_credentials(SimplePlug, "bananauser:banana:password")
      assert conn.status == 200
    end

    test "realm" do
      System.put_env("REALM", "Banana")
      conn = call_without_credentials(SimplePlug)
      assert Plug.Conn.get_resp_header(conn, "www-authenticate") == [ "Basic realm=\"Banana\""]
    end
  end

  describe "missing configuration" do

    setup do
      header_content = "Basic " <> Base.encode64("doesnotreallymatter")
      conn = :get
      |> conn("/")
      |> put_req_header("authorization", header_content)
      {:ok, conn: conn}
    end

    test "no configuration at all", %{conn: conn} do
      assert_raise(ArgumentError, fn -> SimplePlug.call(conn, []) end)
    end

    test "no key, no username", %{conn: conn} do
      Application.put_env(:basic_auth, :my_auth, password: "simple:password")
      assert_raise(ArgumentError, ~r/Missing/, fn -> SimplePlug.call(conn, []) end)
    end

    test "no key, no password", %{conn: conn} do
      Application.put_env(:basic_auth, :my_auth, username: "admin")
      assert_raise(ArgumentError, ~r/Missing/, fn -> SimplePlug.call(conn, []) end)
    end
  end
end
