val af_inet : int
val af_inet6 : int

module Key : sig
  type t = Unsigned.uchar Ctypes_static.carray

  val generate_private_key : unit -> t
  val generate_public_key : Unsigned.uchar Ctypes_static.carray -> t
  val generate_preshared_key : unit -> t
  val to_string : t -> string
end

module Allowed_ip : sig
  module Ip = Ipaddr

  type t = { ip : Ip.t; cidr : Unsigned.uint8 }
end

module Peer : sig
  type t = {
    public_key : Key.t option;
    preshared_key : Key.t option;
    endpoint : Unix.sockaddr option;
    last_handshake_time : float;
    rx_bytes : int;
    tx_bytes : int;
    persistent_keepalive_interval : int option;
    allowed_ips : Allowed_ip.t list;
  }

  val create :
    ?public_key:Key.t ->
    ?preshared_key:Key.t ->
    ?endpoint:Unix.sockaddr ->
    ?persistent_keepalive_interval:int ->
    ?allowed_ips:Allowed_ip.t list ->
    unit ->
    t
end

module Device : sig
  type t = {
    name : string;
    ifindex : int;
    public_key : Key.t option;
    private_key : Key.t option;
    fwmark : int option;
    listen_port : int option;
    peers : Peer.t list;
  }

  val create :
    name:string ->
    ?public_key:Key.t ->
    ?private_key:Key.t ->
    ?fwmark:int ->
    ?listen_port:int ->
    ?peers:Peer.t list ->
    unit ->
    t

  (* TODO: remove this once it is used *)
  val of_wg_device :
    (Wireguard.Wg_device.wg_device, [ `Struct ]) Ctypes_static.structured -> t

  val add_peers : 'a -> 'b -> 'c
  val set_peers : 'a -> 'b -> 'c
  val set_device : t -> (unit, [> `Msg of string ]) result
  val configure_peer : 'a -> 'b
  val remove_peer : 'a -> 'b
  val configure_peers : 'a -> 'b
  val remove_peers : 'a -> 'b
end
