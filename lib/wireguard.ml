open Ctypes

type wg_key

let wg_key = ptr uchar

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

  (* enum wg_peer_flags { *)
  (* 	WGPEER_REMOVE_ME = 1U << 0, *)
  (* 	WGPEER_REPLACE_ALLOWEDIPS = 1U << 1, *)
  (* 	WGPEER_HAS_PUBLIC_KEY = 1U << 2, *)
  (* 	WGPEER_HAS_PRESHARED_KEY = 1U << 3, *)
  (* 	WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL = 1U << 4 *)
  (* }; *)
  module Wg_peer_flags = struct
    let wgpeer_remove_me = 1 lsl 0
    let wgpeer_replace_allowedips = 1 lsl 1
    let wgpeer_has_public_key = 1 lsl 2
    let wgpeer_has_preshared_key = 1 lsl 3
    let wgpeer_has_persistent_keepalive_interval = 1 lsl 4
  end
end

module Wg_device = struct
  (* typedef struct wg_device { *)
  (* 	char name[IFNAMSIZ]; *)
  (* 	uint32_t ifindex; *)

  (* enum wg_device_flags flags; *)

  (* wg_key public_key; *)
  (* wg_key private_key; *)

  (* uint32_t fwmark; *)
  (* uint16_t listen_port; *)

  (* 	struct wg_peer *first_peer, *last_peer; *)
  (* } wg_device; *)

  type wg_device

  let wg_device : wg_device structure typ = structure "wg_device"

  (* let name = field wg_device "name" char *)
  (* let name1 = field wg_device "name" char *)
  (* let name2 = field wg_device "name" char *)
  (* let name3 = field wg_device "name" char *)
  (* let name4 = field wg_device "name" char *)
  (* let name5 = field wg_device "name" char *)
  (* let name6 = field wg_device "name" char *)
  (* let name7 = field wg_device "name" char *)
  (* let name8 = field wg_device "name" char *)
  (* let name9 = field wg_device "name" char *)
  (* let name10 = field wg_device "name" char *)
  (* let name11 = field wg_device "name" char *)
  (* let name12 = field wg_device "name" char *)
  (* let name13 = field wg_device "name" char *)
  (* let name14 = field wg_device "name" char *)
  (* let name15 = field wg_device "name" char *)
  (* let name16 = field wg_device "name" char *)
  let name = Array.init 16 (fun _ -> field wg_device "name" char)
  let ifindex = field wg_device "ifindex" uint32_t
  let flags = field wg_device "flags" uint16_t
  let public_key = field wg_device "public_key" wg_key
  let private_key = field wg_device "private_key" wg_key
  let fwmark = field wg_device "fwmark" uint32_t
  let listen_port = field wg_device "listen_port" uint16_t
  let first_peer = field wg_device "first_peer" (ptr Wg_peer.wg_peer)
  let last_peer = field wg_device "last_peer" (ptr Wg_peer.wg_peer)
  let () = seal wg_device

  (* enum wg_device_flags { *)
  (* 	WGDEVICE_REPLACE_PEERS = 1U << 0, *)
  (* 	WGDEVICE_HAS_PRIVATE_KEY = 1U << 1, *)
  (* 	WGDEVICE_HAS_PUBLIC_KEY = 1U << 2, *)
  (* 	WGDEVICE_HAS_LISTEN_PORT = 1U << 3, *)
  (* 	WGDEVICE_HAS_FWMARK = 1U << 4 *)
  (* }; *)
  module Wg_device_flags = struct
    let wgdevice_replace_peers = 1 lsl 0
    let wgdevice_has_private_key = 1 lsl 1
    let wgdevice_has_public_key = 1 lsl 2
    let wgdevice_has_listen_port = 1 lsl 3
    let wgdevice_has_fwmark = 1 lsl 4
  end
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

(* void wg_key_to_base64(wg_key_b64_string base64, const wg_key key); *)
let wg_key_to_base64 =
  foreign "wg_key_to_base64"
    (ptr Ctypes.char @-> Ctypes.const wg_key @-> returning void)

let wg_device_new = foreign "wg_device_new" (void @-> returning (ptr wg_device))

(* void wg_device_set_name(wg_device *device, const char *name); *)
let wg_device_set_name =
  foreign "wg_device_set_name" (ptr wg_device @-> string @-> returning void)

(* void wg_device_set_flags(wg_device *device, enum wg_device_flags flags); *)
let wg_device_set_flags =
  foreign "wg_device_set_flags" (ptr wg_device @-> int64_t @-> returning void)

(* void wg_device_set_public_key(wg_device *device, const wg_key public_key); *)
let wg_device_set_public_key =
  foreign "wg_device_set_public_key"
    (ptr wg_device @-> Ctypes_static.const wg_key @-> returning void)

(* void wg_device_set_private_key(wg_device *device, const wg_key private_key); *)
let wg_device_set_private_key =
  foreign "wg_device_set_private_key"
    (ptr wg_device @-> Ctypes_static.const wg_key @-> returning void)

(* void wg_device_set_listen_port(wg_device *device, uint16_t listen_port); *)
let wg_device_set_listen_port =
  foreign "wg_device_set_listen_port"
    (ptr wg_device @-> uint16_t @-> returning void)

(* void wg_device_set_first_peer(wg_device *device, wg_peer *peer); *)
(* void wg_device_set_last_peer(wg_device *device, wg_peer *peer); *)
