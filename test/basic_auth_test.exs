defmodule BasicAuthTest do
  use ExUnit.Case, async: true
  use Plug.Test

  defmodule DemoPlug do
    defmacro __using__(args) do
      quote bind_quoted: [args: args] do
        use Plug.Builder
        plug BasicAuth, args
        plug :index
        defp index(conn, _opts), do: conn |> send_resp(200, "OK")
      end
    end
  end

  describe "custom function" do
    defmodule User do
      def find_by_username_and_password(conn, username, password) do
        if username == "robert" && password == "secret" do
          Plug.Conn.assign(conn, :current_user, %{name: "robert"})
        else
          Plug.Conn.halt(conn)
        end
      end
    end

    defmodule PlugWithCallback do
      use DemoPlug, callback: &User.find_by_username_and_password/3
    end

    defmodule PlugWithCallbackAndRealm do
      use DemoPlug, callback: &User.find_by_username_and_password/3, realm: "Bob's Kingdom"
    end

    test "no credentials provided" do
      conn = conn(:get, "/")
      |> PlugWithCallback.call([])
      assert conn.status == 401
      assert Plug.Conn.get_resp_header(conn, "www-authenticate") == [ "Basic realm=\"Basic Authentication\""]
    end

    test "no credentials provided with custom realm" do
      conn = conn(:get, "/")
      |> PlugWithCallbackAndRealm.call([])
      assert conn.status == 401
      assert Plug.Conn.get_resp_header(conn, "www-authenticate") == [ "Basic realm=\"Bob's Kingdom\""]
    end

    test "wrong credentials provided" do
      header_content = "Basic " <> Base.encode64("bad:credentials")

      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> PlugWithCallback.call([])
      assert conn.status == 401
    end

    test "right credentials provided" do
      header_content = "Basic " <> Base.encode64("robert:secret")

      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> PlugWithCallback.call([])
      assert conn.status == 200
    end
  end

  describe "credential checking" do
    defmodule SimplePlug do
      use DemoPlug, use_config: {:basic_auth, :my_auth}
    end

    test "no credentials returns a 401" do
      conn = conn(:get, "/")
      |> SimplePlug.call([])

      assert conn.status == 401
      assert Plug.Conn.get_resp_header(conn, "www-authenticate") == [ "Basic realm=\"Admin Area\""]
    end

    test "invalid credentials returns a 401" do
      header_content = "Basic " <> Base.encode64("bad:credentials")

      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> SimplePlug.call([])

      assert conn.status == 401
    end

    test "incorrect header returns a 401" do
      header_content = "Banana " <> Base.encode64("admin:simple_password")

      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> SimplePlug.call([])

      assert conn.status == 401
    end

    test "valid credentials returns a 200" do
      header_content = "Basic " <> Base.encode64("admin:simple_password")

      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> SimplePlug.call([])

      assert conn.status == 200
    end
  end

  describe "reading config from System environment" do
    defmodule SimplePlugWithSystem do
      use DemoPlug, use_config: {:basic_auth, :my_auth_with_system}
    end


    test "username and password" do
      System.put_env("USERNAME", "bananauser")
      System.put_env("PASSWORD", "bananapassword")

      header_content = "Basic " <> Base.encode64("bananauser:bananapassword")
      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> SimplePlugWithSystem.call([])

      assert conn.status == 200
    end

    test "realm" do
      System.put_env("REALM", "Banana")
      conn = conn(:get, "/")
      |> SimplePlugWithSystem.call([])
      assert Plug.Conn.get_resp_header(conn, "www-authenticate") == [ "Basic realm=\"Banana\""]
    end
  end
end
