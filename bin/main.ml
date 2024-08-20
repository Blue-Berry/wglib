(* let _ = Wglib.Wireguard.wg_add_device "wg9" *)
(* let names = Wglib.Wireguard.wg_list_device_names () *)
(* let () = print_endline names *)

(* wg_key temp_private_key; *)
(**)
(* wg_generate_private_key(temp_private_key); *)
(* wg_generate_public_key(new_peer.public_key, temp_private_key); *)
(* wg_generate_private_key(new_device.private_key); *)
open Wglib.Wireguard

let () =
  let new_peer = Ctypes.make Wglib.Wireguard.Wg_peer.wg_peer in
  let flags =
    Unsigned.UInt32.of_int
      (Wg_peer.Wg_peer_flags.wgpeer_has_public_key
     lor Wg_peer.Wg_peer_flags.wgpeer_replace_allowedips)
  in
  let () = Ctypes.setf new_peer Wglib.Wireguard.Wg_peer.flags flags in
  let new_device = Ctypes.make Wglib.Wireguard.Wg_device.wg_device in
  let () = Ctypes.setf new_device Wglib.Wireguard.Wg_device.name "wgtest1" in
  let () =
    Ctypes.setf new_device Wglib.Wireguard.Wg_device.listen_port
      (Unsigned.UInt16.of_int 1234)
  in
  let flags =
    Wg_device.Wg_device_flags.wgdevice_has_private_key
    lor Wg_device.Wg_device_flags.wgdevice_has_listen_port
    |> Unsigned.UInt32.of_int
  in
  let () =
    Ctypes.setf new_device Wglib.Wireguard.Wg_device.wg_device_flags flags
  in
  let () =
    Ctypes.setf new_device Wglib.Wireguard.Wg_device.first_peer
      (Ctypes.addr new_peer)
  in
  let () =
    Ctypes.setf new_device Wglib.Wireguard.Wg_device.last_peer
      (Ctypes.addr new_peer)
  in
  let temp_private_key = Ctypes.CArray.make Ctypes_static.uint8_t 32 in
  let () = wg_generate_private_key (Ctypes.CArray.start temp_private_key) in
  let public_key = Ctypes.CArray.make Ctypes_static.uint8_t 32 in
  let () =
    wg_generate_public_key
      (Ctypes.CArray.start public_key)
      (Ctypes.CArray.start temp_private_key)
  in
  let () =
    Ctypes.setf new_peer Wglib.Wireguard.Wg_peer.public_key
      (Ctypes.CArray.start public_key)
  in
  let private_key = Ctypes.CArray.make Ctypes_static.uint8_t 32 in
  let () = wg_generate_private_key (Ctypes.CArray.start private_key) in
  let () =
    Ctypes.setf new_device Wglib.Wireguard.Wg_device.private_key
      (Ctypes.CArray.start private_key)
  in
  let () = print_endline (Ctypes.getf new_device Wg_device.name) in
  let add = wg_add_device (Ctypes.getf new_device Wg_device.name) in
  let () = print_endline (string_of_int add) in
  let set = wg_set_device (Ctypes.addr new_device) in
  let () = print_endline (string_of_int set) in
  ()
