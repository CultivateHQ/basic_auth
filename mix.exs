defmodule BasicAuth.Mixfile do
  use Mix.Project

  def project do
    [app: :basic_auth,
     description: "Basic Authentication Plug",
     package: package(),
     version: "2.2.0",
     elixir: "~> 1.0",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     elixirc_paths: elixirc_paths(Mix.env),
     deps: deps(),
     docs: [
       main: "readme",
       extras: ["README.md"],
     ],
    ]
  end

  def application do
    [applications: [:logger, :cowboy, :plug]]
  end

  defp deps do
    [
     {:plug, "~> 0.14 or ~> 1.0"},
     {:ex_doc, ">= 0.0.0", only: :dev},
     {:cowboy, "~> 1.0"},
     {:credo, ">= 0.0.0", only: [:dev, :test]},
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_),     do: ["lib"]

  defp package do
    [
      contributors: ["Mark Connell", "Paul Wilson"],
      maintainers: ["Paul Wilson"],
      licenses: ["MIT"],
      links: %{github: "https://github.com/cultivatehq/basic_auth"},
      files: ~w(lib LICENSE.md mix.exs README.md),
    ]
  end
end
