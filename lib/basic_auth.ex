defmodule BasicAuth do
  def init([use_config: _] = options) do
    options
  end

  def init(options) do
    # Better to fail at compile time if keys are incorrect
    [:password, :realm, :username] = Keyword.keys(options) |> Enum.sort
    options
  end

  def call(conn, options) do
    header_content = Plug.Conn.get_req_header(conn, "authorization")

    if header_content |> valid_credentials?(options) do
      conn
    else
      conn
      |> send_unauthorized_response(option_value(options, :realm))
    end
  end

  defp valid_credentials?(["Basic " <> encoded_string], options) do
    Base.decode64!(encoded_string) == "#{option_value(options, :username)}:#{option_value(options, :password)}"
  end

  # Handle scenarios where there are no basic auth credentials supplied
  defp valid_credentials?(_credentials, _options) do
    false
  end

  defp send_unauthorized_response(conn, realm) do
    Plug.Conn.put_resp_header(conn, "www-authenticate", "Basic realm=\"#{realm}\"")
    |> Plug.Conn.send_resp(401, "401 Unauthorized")
    |> Plug.Conn.halt
  end

  defp option_value([use_config: otp_app], key) do
    Application.get_env(otp_app, :basic_auth)[key]
  end

  defp option_value(options, key) do
    options[key]
  end
end
