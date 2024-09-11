let () =
  let allowed_ips : Wglib.Wgapi.Allowed_ip.t list =
    List.init 5 (fun i ->
        let ip =
          Wglib.Wgapi.Allowed_ip.Ip.V4
            (Wglib.Wgapi.Allowed_ip.Ip.V4.of_string_exn
               ("0.0.0." ^ Int.to_string i))
        in
        let cidr : Unsigned.UInt8.t = Unsigned.UInt8.of_int 32 in
        let allowed_ip : Wglib.Wgapi.Allowed_ip.t = { ip; cidr } in
        allowed_ip)
  in
  let endpoint : Wglib.Wgapi.Endpoint.t =
    {
      addr =
        `V6 (Ipaddr.V6.of_string_exn "2001:0000:130F:0000:0000:09C0:876A:130B");
      port = 4321;
    }
  in
  let peer1 =
    Wglib.Wgapi.Peer.create ~persistent_keepalive_interval:10
      ~public_key:
        Wglib.Wgapi.Key.(generate_private_key () |> generate_public_key)
      ~allowed_ips ~endpoint ()
  in
  let endpoint : Wglib.Wgapi.Endpoint.t =
    { addr = `V4 (Ipaddr.V4.of_string_exn "10.10.10.10"); port = 1234 }
  in
  let peer2 =
    Wglib.Wgapi.Peer.create
      ~public_key:
        Wglib.Wgapi.Key.(generate_private_key () |> generate_public_key)
      ~endpoint ()
  in
  let peer3 =
    Wglib.Wgapi.Peer.create
      ~public_key:
        Wglib.Wgapi.Key.(generate_private_key () |> generate_public_key)
      ()
  in
  let peer4 =
    Wglib.Wgapi.Peer.create
      ~public_key:
        Wglib.Wgapi.Key.(generate_private_key () |> generate_public_key)
      ()
  in
  let peers = [ peer1; peer2; peer3; peer4 ] in
  let private_key = Wglib.Wgapi.Key.generate_private_key () in
  let device =
    Wglib.Wgapi.Interface.create ~name:"wgtest1" ~listen_port:1234 ~private_key
      ~peers ()
  in
  let err = Wglib.Wgapi.Interface.set_device device in
  let () =
    match err with
    | Ok () -> print_endline "Device set successfully"
    | Error err -> (
        match err with
        | `Msg msg -> print_endline msg
        | _ -> print_endline "Unknown error")
  in
  let device = Wglib.Wgapi.Interface.get_device "wgtest1" |> Result.get_ok in
  let endpoints =
    List.map (fun (peer : Wglib.Wgapi.Peer.t) -> peer.endpoint) device.peers
  in
  let () =
    print_endline ("Peer number: " ^ (List.length device.peers |> string_of_int))
  in
  let endpoints =
    List.fold_left
      (fun acc e ->
        match e with
        | None -> "None - " ^ acc
        | Some (endpoint : Wglib.Wgapi.Endpoint.t) ->
            let str =
              match endpoint.addr with
              | `V4 ip -> Ipaddr.V4.to_string ip
              | `V6 ip -> Ipaddr.V6.to_string ip
            in
            str ^ " - " ^ acc)
      "" endpoints
  in
  print_endline ("Peer endpoint: " ^ endpoints)
