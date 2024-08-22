let device = Wglib.Wireguard.wg_device_new ()
let () = Wglib.Wireguard.wg_device_set_name device "wgtest0"

let () =
  Wglib.Wireguard.wg_device_set_listen_port device (Unsigned.UInt16.of_int 1234)

let device = device |> Ctypes.( !@ )

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
    ("Port: "
    ^ (Ctypes.getf device Wglib.Wireguard.Wg_device.listen_port
      |> Unsigned.UInt16.to_string))

let () =
  print_endline
    ("Fwmark:"
    ^ (Ctypes.getf device Wglib.Wireguard.Wg_device.fwmark
      |> Unsigned.UInt32.to_string))

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
