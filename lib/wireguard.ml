open Ctypes

type wg_key

let wg_key = ptr uint8_t

type wg_device_flags

module Wg_endpoint = struct
  (* typedef union wg_endpoint { *)
  (* 	struct sockaddr addr; *)
  (* 	struct sockaddr_in addr4; *)
  (* 	struct sockaddr_in6 addr6; *)
  (* } wg_endpoint; *)
  type wg_endpoint

  let wg_endpoint : wg_endpoint union typ = union "wg_endpoint"
  let addr = field wg_endpoint "addr" Socket.Sockaddr.sockaddr
  let addr4 = field wg_endpoint "addr4" Socket.Sockaddr_in.sockaddr_in
  let addr6 = field wg_endpoint "addr6" Socket.Sockaddr_in6.sockaddr_in6
  let () = seal wg_endpoint
end

module Wg_peer = struct
  (* typedef struct wg_peer { *)
  (* 	enum wg_peer_flags flags; *)
  (* 	wg_key public_key; *)
  (* 	wg_key preshared_key; *)
  (* 	wg_endpoint endpoint; *)
  (* 	struct timespec64 last_handshake_time;  <- TODO*)
  (* 	uint64_t rx_bytes, tx_bytes;  <- TODO*)
  (* 	uint16_t persistent_keepalive_interval;  <- TODO*)
  (* 	struct wg_allowedip *first_allowedip, *last_allowedip;  <- TODO*)
  (* 	struct wg_peer *next_peer;  <- TODO*)
  (* } wg_peer; *)
  type wg_peer

  let wg_peer : wg_peer structure typ = structure "wg_peer"
  let flags = field wg_peer "flags" uint32_t
  let public_key = field wg_peer "public_key" wg_key
  let preshared_key = field wg_peer "preshared_key" wg_key
  let endpoint = field wg_peer "endpoint" Wg_endpoint.wg_endpoint
  let () = seal wg_peer
end

module Wg_device = struct
  (* typedef struct wg_device { *)
  (* 	char name[IFNAMSIZ]; *)
  (* 	enum wg_device_flags flags; *)
  (* 	wg_key public_key; *)
  (* 	wg_key private_key; *)
  (* 	uint16_t listen_port; *)
  (* 	struct wg_peer *first_peer, *last_peer; *)
  (* } wg_device; *)

  type wg_device

  let wg_device : wg_device structure typ = structure "wg_device"
  let name = field wg_device "name" string
  let wg_device_flags = field wg_device "flags" uint32_t
  let public_key = field wg_device "public_key" wg_key
  let private_key = field wg_device "private_key" wg_key
  let listen_port = field wg_device "listen_port" uint16_t
  let first_peer = field wg_device "first_peer" (ptr Wg_peer.wg_peer)
  let last_peer = field wg_device "last_peer" (ptr Wg_peer.wg_peer)
  let () = seal wg_device
end

open Foreign
open Wg_device

(* int wg_set_device(wg_device *dev); *)
let wg_set_device = foreign "wg_set_device" (ptr wg_device @-> returning int)

let wg_get_device =
  foreign "wg_get_device" (ptr wg_device @-> string @-> returning int)

let wg_add_device = foreign "wg_add_device" (string @-> returning int)
let wg_del_device = foreign "wg_del_device" (string @-> returning int)
let wg_free_device = foreign "wg_free_device" (wg_device @-> returning void)

let wg_list_device_names =
  foreign "wg_list_device_names" (void @-> returning string)

(* void wg_key_to_base64(wg_key_b64_string base64, const wg_key key); *)
(* int wg_key_from_base64(wg_key key, const wg_key_b64_string base64); *)
(* bool wg_key_is_zero(const wg_key key); *)

let wg_generate_public_key =
  foreign "wg_generate_public_key"
    (wg_key @-> Ctypes_static.const wg_key @-> returning void)

let wg_generate_private_key =
  foreign "wg_generate_private_key" (wg_key @-> returning void)

let wg_generate_preshared_key =
  foreign "wg_generate_preshared_key" (wg_key @-> returning void)
