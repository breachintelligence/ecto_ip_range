defmodule EctoIPRange.IPRange do
  @moduledoc """
  Struct for PostgreSQL `:iprange`.

  """

  use Ecto.Type

  alias EctoIPRange.Util.{CIDR, Inet}

  @type t :: %__MODULE__{
    range: binary(),
    first_ip: :inet.ip4_address() | :inet.ip6_address(),
    last_ip: :inet.ip4_address() | :inet.ip6_address()
  }

  defstruct [:range, :first_ip, :last_ip]

  @impl Ecto.Type
  def type, do: :iprange

  @impl Ecto.Type
  def cast({_, _, _, _} = ip4_address) do
    case Inet.ntoa(ip4_address) do
      address when is_binary(address) ->
        {:ok,
         %__MODULE__{
           range: address <> "/32",
           first_ip: ip4_address,
           last_ip: ip4_address
         }}

      _ ->
        :error
    end
  end

  def cast({_, _, _, _, _, _, _, _} = ip6_address) do
    case Inet.ntoa(ip6_address) do
      address when is_binary(address) ->
        {:ok,
         %__MODULE__{
           range: address <> "/128",
           first_ip: ip6_address,
           last_ip: ip6_address
         }}
      _ ->
        :error
    end
  end

  def cast(address) when is_binary(address) do
    cond do
      String.contains?(address, "-") -> cast_range(address)
      String.contains?(address, "/") -> cast_cidr(address)
      true -> cast_binary(address)
    end
  end

  def cast(%__MODULE__{} = address), do: {:ok, address}
  def cast(_), do: :error

  @impl Ecto.Type
  def load(%__MODULE__{} = address), do: {:ok, address}
  def load(_), do: :error

  @impl Ecto.Type
  def dump(%__MODULE__{} = address), do: {:ok, address}
  def dump(_), do: :error

  defp cast_binary(address) do
    case Inet.parse_binary(address) do
      {:ok, {_, _, _, _} = ip4_address} ->
        {:ok,
         %__MODULE__{
           range: address <> "/32",
           first_ip: ip4_address,
           last_ip: ip4_address
         }}
      {:ok, {_, _, _, _, _, _, _, _} = ip6_address} ->
        {:ok,
          %__MODULE__{
            range: address <> "/128",
            first_ip: ip6_address,
            last_ip: ip6_address
          }}
      _ ->
        :error
    end
  end

  defp cast_cidr(cidr) do
    with [address, maskstring] <- String.split(cidr, "/", parts: 2),
    {first_ip_address, last_ip_address} <- cast_ip4_or_ip6_cidr(address, maskstring) do
      {:ok,
         %__MODULE__{
           range: cidr,
           first_ip: first_ip_address,
           last_ip: last_ip_address
         }}
    end
  end

  defp cast_range(range) do
    with [first_ip, last_ip] <- String.split(range, "-", parts: 2),
         {:ok, first_ip_address} <- Inet.parse_binary(first_ip),
         {:ok, last_ip_address} <- Inet.parse_binary(last_ip) do
      {:ok,
       %__MODULE__{
         range: range,
         first_ip: first_ip_address,
         last_ip: last_ip_address
       }}
    else
      _ -> :error
    end
  end

  defp cast_ip4_or_ip6_cidr(address, maskstring) do
    case Inet.parse_binary(address) do
      {:ok, {_, _, _, _}} -> cast_ip4_cidr(address, maskstring)
      {:ok, {_, _, _, _, _, _, _, _}} -> cast_ip6_cidr(address, maskstring)
      _ -> :error
    end
  end

  defp cast_ip4_cidr(address, maskstring) do
    case Integer.parse(maskstring) do
      {maskbits, ""} when maskbits in 0..32 -> CIDR.parse_ipv4(address, maskbits)
      _ -> :error
    end
  end

  defp cast_ip6_cidr(address, maskstring) do
    case Integer.parse(maskstring) do
      {maskbits, ""} when maskbits in 0..128 -> CIDR.parse_ipv6(address, maskbits)
      _ -> :error
    end
  end
end
