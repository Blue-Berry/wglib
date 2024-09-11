let () =
  let allowed_ip : int -> Wglib.Wgapi.Allowed_ip.t =
   fun i ->
    let ip =
      Wglib.Wgapi.Allowed_ip.Ip.V4
        (Wglib.Wgapi.Allowed_ip.Ip.V4.of_string_exn
           ("0.0.0." ^ Int.to_string i))
    in
    let cidr : Unsigned.UInt8.t = Unsigned.UInt8.of_int 32 in
    let allowed_ip : Wglib.Wgapi.Allowed_ip.t = { ip; cidr } in
    allowed_ip
  in
  let endpoint : Wglib.Wgapi.Endpoint.t =
    {
      addr =
        `V6 (Ipaddr.V6.of_string_exn "2001:0000:130F:0000:0000:09C0:876A:130B");
      port = 4321;
    }
  in
  let peers =
    List.init 90 (fun i ->
        Wglib.Wgapi.Peer.create
          ~public_key:
            Wglib.Wgapi.Key.(generate_private_key () |> generate_public_key)
          ~endpoint
          ~allowed_ips:[ allowed_ip i ]
          ())
  in
  let private_key = Wglib.Wgapi.Key.generate_private_key () in
  let device =
    Wglib.Wgapi.Interface.create ~name:"wgtest1" ~listen_port:1234 ~private_key
      ~peers ()
  in
  let err = Wglib.Wgapi.Interface.set_device device in
  let () =
    match err with
    | Ok () -> print_endline "Device set successfully"
    | Error err ->
        Wglib.Wgapi.Interface.DeviceError.to_string err |> print_endline
  in
  let _device = Wglib.Wgapi.Interface.get_device "wgtest1" |> Result.get_ok in
  ()
