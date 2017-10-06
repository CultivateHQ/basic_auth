defmodule DemoPlug do
  @moduledoc """
  Plug for basic auth testing. Basic auth is configured with the provided args.

  Usage:

  ```
  defmodule SimplePlug do
     use DemoPlug, use_config: {:basic_auth, :my_auth}
  end
  ```
  """

  defmacro __using__(args) do
    quote bind_quoted: [args: args] do
      use Plug.Builder
      plug BasicAuth, args
      plug :index
      defp index(conn, _opts), do: conn |> send_resp(200, "OK")
    end
  end
end
