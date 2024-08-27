(*
open Ctypes
open Wglib.Wireguard

(* -------------------------- CTypes way -------------------------- *)
 let new_peer = make Wg_peer.wg_peer
   let () = setf new_peer Wg_peer.flags (Unsigned.UInt16.of_int 6)

   let () =
     let private_key = Wglib.Wgapi.Key.generate_private_key () in
     let public_key = Wglib.Wgapi.Key.generate_public_key private_key in
     let () =
       CArray.iteri
         (fun i c ->
           Ctypes.setf new_peer (Array.get Wglib.Wireguard.Wg_peer.public_key i) c)
         public_key
     in
     ()

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
     let () = setf device Wg_device.first_peer (Some (Ctypes.addr new_peer)) in
     let () = setf device Wg_device.last_peer (Some (Ctypes.addr new_peer)) in
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
   let () = Printf.printf "wg_set_device: %d\n" err *)

(* -------------------------- WgApi way -------------------------- *)
(*
  steps for configureing wireguard device:
    1. generate private key
    2. generate public key
    3. create new peer
    4. set peer public key
    5. set peer flags
    6. create new device
    7. set device name
    8. set device flags
    9. set device listen port
    10. set device private key
    11. set device first peer
    12. set device last peer
    13. add device
    14. set device
  *)

let () =
  Printf.printf "\n";
  print_endline "WgApi way";
  Printf.printf "\n"

let () =
  let allowed_ip : Wglib.Wgapi.Allowed_ip.t =
    let ip =
      Wglib.Wgapi.Allowed_ip.Ip.V4
        (Wglib.Wgapi.Allowed_ip.Ip.V4.of_string_exn "10.10.10.10")
    in
    let cidr : Unsigned.UInt8.t = Unsigned.UInt8.of_int 32 in
    { ip; cidr }
  in
  let peer1 =
    Wglib.Wgapi.Peer.create ~persistent_keepalive_interval:10
      ~public_key:
        Wglib.Wgapi.Key.(generate_private_key () |> generate_public_key)
      ~allowed_ips:[ allowed_ip ] ()
  in
  let peer2 =
    Wglib.Wgapi.Peer.create
      ~public_key:
        Wglib.Wgapi.Key.(generate_private_key () |> generate_public_key)
      ()
  in
  let peers = [ peer1; peer2 ] in
  let device =
    Wglib.Wgapi.Device.create ~name:"wgtest1" ~listen_port:1234
      ~private_key:(Wglib.Wgapi.Key.generate_private_key ())
      ~peers ()
  in
  let err = Wglib.Wgapi.Device.set_device device in
  let () =
    match err with
    | Ok () -> print_endline "Device set successfully"
    | Error err -> (
        match err with
        | `Msg msg -> print_endline msg
        | _ -> print_endline "Unknown error")
  in
  ()
