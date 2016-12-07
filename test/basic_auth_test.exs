defmodule BasicAuthTest do
  use ExUnit.Case, async: true
  use Plug.Test

  defmodule DemoPlug do
    defmacro __using__(auth_config) do
      quote bind_quoted: [auth_config: auth_config] do
        use Plug.Builder
        plug BasicAuth, use_config: {:basic_auth, auth_config}
        plug :index
        defp index(conn, _opts), do: conn |> send_resp(200, "OK")
      end
    end
  end

  defmodule DemoPlugWithModule do
    defmacro __using__(function) do
      quote bind_quoted: [function: function] do
        use Plug.Builder
        plug BasicAuth, callback: function
        plug :index
        defp index(conn, _opts), do: conn |> send_resp(200, "OK")
      end
    end
  end

  describe "custom function" do
    defmodule User do
      def find_by_username_and_password(username, password) do
        username == "robert" && password == "secret"
      end
    end

    defmodule SimpleDemoPlugWithModule do
      use DemoPlugWithModule, &User.find_by_username_and_password/2
    end

    test "no credentials provided" do
      conn = conn(:get, "/")
      |> SimpleDemoPlugWithModule.call([])
      assert conn.status == 401
    end

    test "wrong credentials provided" do
      header_content = "Basic " <> Base.encode64("bad:credentials")

      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> SimpleDemoPlugWithModule.call([])
      assert conn.status == 401
    end

    test "right credentials provided" do
      header_content = "Basic " <> Base.encode64("robert:secret")

      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> SimpleDemoPlugWithModule.call([])
      assert conn.status == 200
    end
    
  end

  describe "credential checking" do
    defmodule SimpleDemoPlug do
      use DemoPlug, :my_auth
    end

    test "no credentials returns a 401" do
      conn = conn(:get, "/")
      |> SimpleDemoPlug.call([])

      assert conn.status == 401
      assert Plug.Conn.get_resp_header(conn, "www-authenticate") == [ "Basic realm=\"Admin Area\""]
    end

    test "invalid credentials returns a 401" do
      header_content = "Basic " <> Base.encode64("bad:credentials")

      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> SimpleDemoPlug.call([])

      assert conn.status == 401
    end

    test "incorrect header returns a 401" do
      header_content = "Banana " <> Base.encode64("admin:simple_password")

      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> SimpleDemoPlug.call([])

      assert conn.status == 401
    end

    test "valid credentials returns a 200" do
      header_content = "Basic " <> Base.encode64("admin:simple_password")

      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> SimpleDemoPlug.call([])

      assert conn.status == 200
    end
  end

  describe "reading config from System environment" do
    defmodule SimpleDemoPlugWithSystem do
      use DemoPlug, :my_auth_with_system
    end


    test "username and password" do
      System.put_env("USERNAME", "bananauser")
      System.put_env("PASSWORD", "bananapassword")

      header_content = "Basic " <> Base.encode64("bananauser:bananapassword")
      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> SimpleDemoPlugWithSystem.call([])

      assert conn.status == 200
    end

    test "realm" do
      System.put_env("REALM", "Banana")
      conn = conn(:get, "/")
      |> SimpleDemoPlugWithSystem.call([])
      assert Plug.Conn.get_resp_header(conn, "www-authenticate") == [ "Basic realm=\"Banana\""]
    end
  end
end
