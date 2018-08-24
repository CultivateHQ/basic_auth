defmodule BasicAuth.ConfiguredTest do
  use ExUnit.Case, async: true
  use Plug.Test
  import BasicAuth.TestHelper, only: [
    call_without_credentials: 1,
    call_with_credentials: 2,
  ]

  defmodule SimplePlug do
    use DemoPlug, use_config: {:basic_auth, :my_auth}
  end

  setup do
    Application.delete_env(:basic_auth, :my_auth)
    :ok
  end

  describe "with username and password directly from configuration" do

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

  describe "with skip_if_no_credentials_configured option" do
    test "skips authentication if no credentials configured" do
      Application.put_env(:basic_auth, :my_auth,
        username: nil,
        password: nil,
        realm: "Admin Area",
        skip_if_no_credentials_configured: true
      )

      conn = call_without_credentials(SimplePlug)
      assert conn.status == 200
    end

    test "doesn't authenticate if credentials don't match" do
      Application.put_env(:basic_auth, :my_auth,
        username: "admin",
        password: "simple:password",
        realm: "Admin Area",
        skip_if_no_credentials_configured: true
      )

      conn = call_without_credentials(SimplePlug)
      assert conn.status == 401
    end

    test "authenticates if credentials match" do
      Application.put_env(:basic_auth, :my_auth,
        username: "admin",
        password: "simple:password",
        realm: "Admin Area",
        skip_if_no_credentials_configured: true
      )

      conn = call_with_credentials(SimplePlug, "admin:simple:password")
      assert conn.status == 200
    end
  end
end
