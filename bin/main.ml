let new_peer = Ctypes.make Wglib.Wireguard.Wg_peer.wg_peer

let peer_key =
  Wglib.Wgapi.Key.generate_private_key () |> Wglib.Wgapi.Key.generate_public_key

let () =
  Ctypes.setf new_peer Wglib.Wireguard.Wg_peer.public_key
    (Ctypes.CArray.start peer_key)

let () =
  Ctypes.setf new_peer Wglib.Wireguard.Wg_peer.flags (Unsigned.UInt32.of_int 6)

let private_key = Wglib.Wgapi.Key.generate_private_key ()
let () = print_endline (Wglib.Wgapi.Key.to_base64 private_key)
let public_key = Wglib.Wgapi.Key.generate_public_key private_key
let () = print_endline (Wglib.Wgapi.Key.to_base64 public_key)
let name = "wgtest0"
let new_device = Ctypes.make Wglib.Wireguard.Wg_device.wg_device
let () = Ctypes.setf new_device Wglib.Wireguard.Wg_device.name name

let () =
  Ctypes.setf new_device Wglib.Wireguard.Wg_device.listen_port
    (Unsigned.UInt16.of_int 1234)

let () =
  Ctypes.setf new_device Wglib.Wireguard.Wg_device.wg_device_flags
    (Int64.of_int 10)

let () =
  Ctypes.setf new_device Wglib.Wireguard.Wg_device.private_key
    (Ctypes.CArray.start private_key)

let () =
  print_endline
    ("Name: "
    ^ Ctypes.getf
        (new_device |> Ctypes.addr |> Ctypes.( !@ ))
        Wglib.Wireguard.Wg_device.name)
(* let () = *)
(*   Ctypes.setf new_device Wglib.Wireguard.Wg_device.first_peer *)
(*     (Ctypes.addr new_peer) *)
(* let () = *)
(*   Ctypes.setf new_device Wglib.Wireguard.Wg_device.last_peer *)
(*     (Ctypes.addr new_peer) *)

let err = Wglib.Wireguard.wg_del_device name
let () = Printf.printf "wg_del_device: %d\n" err
let err = Wglib.Wireguard.wg_add_device name
let () = Printf.printf "wg_add_device: %d\n" err
let err = Wglib.Wireguard.wg_set_device (Ctypes.addr new_device)
let () = Printf.printf "wg_set_device: %d\n" err
