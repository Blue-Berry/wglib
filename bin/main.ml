open Ctypes
open Wglib.Wireguard

let device = make Wg_device.wg_device

let () =
  let () =
    let name = "wgtest0" |> String.to_seq |> Array.of_seq in
    Array.iteri
      (fun i c ->
        Ctypes.setf device (Array.get Wglib.Wireguard.Wg_device.name i) c)
      name
  in
  let () = setf device Wg_device.flags (Unsigned.UInt16.of_int 10) in
  let () = setf device Wg_device.listen_port (Unsigned.UInt16.of_int 1234) in
  let private_key = Wglib.Wgapi.Key.generate_private_key () in
  let () =
    CArray.iteri
      (fun i c ->
        Ctypes.setf device (Array.get Wglib.Wireguard.Wg_device.private_key i) c)
      private_key
  in
  ()

let () =
  print_endline
    ("Size: "
    ^ (Ctypes.sizeof Wglib.Wireguard.Wg_device.wg_device |> Int.to_string))

let name =
  Array.fold_left
    (fun acc c -> acc ^ String.make 1 (Ctypes.getf device c))
    "" Wglib.Wireguard.Wg_device.name

let () = print_endline ("Name: " ^ name)

let () =
  let index = Ctypes.getf device Wglib.Wireguard.Wg_device.ifindex in
  print_endline ("Index: " ^ Unsigned.UInt32.to_string index)

let () =
  print_endline
    ("Flags: "
    ^ (Ctypes.getf device Wglib.Wireguard.Wg_device.flags
      |> Unsigned.UInt16.to_string))

let () =
  print_endline
    ("Fwmark:"
    ^ (Ctypes.getf device Wglib.Wireguard.Wg_device.fwmark
      |> Unsigned.UInt32.to_string))

let () =
  print_endline
    ("Port: "
    ^ (Ctypes.getf device Wglib.Wireguard.Wg_device.listen_port
      |> Unsigned.UInt16.to_string))

let new_device = Ctypes.make Wglib.Wireguard.Wg_device.wg_device

let () =
  Ctypes.setf new_device Wglib.Wireguard.Wg_device.listen_port
    (Unsigned.UInt16.of_int 1234)

let () =
  Ctypes.setf new_device Wglib.Wireguard.Wg_device.flags
    (Unsigned.UInt16.of_int 10)

let err = Wglib.Wireguard.wg_del_device name
let () = Printf.printf "wg_del_device: %d\n" err
let err = Wglib.Wireguard.wg_add_device name
let () = Printf.printf "wg_add_device: %d\n" err
let err = Wglib.Wireguard.wg_set_device (Ctypes.addr device)
let () = Printf.printf "wg_set_device: %d\n" err
