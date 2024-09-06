open Wireguard

let af_inet = 2
let af_inet6 = 10

module Key = struct
  open Ctypes

  type t = Unsigned.uchar Ctypes_static.carray

  let of_array arr =
    assert (Array.length arr = 32);
    let key = CArray.make Ctypes_static.uchar 32 in
    let () = Array.iteri (fun i c -> CArray.set key i c) arr in
    key

  let generate_private_key () =
    let key = CArray.make Ctypes_static.uchar 32 in
    let () = wg_generate_private_key (CArray.start key) in
    key

  let generate_public_key private_key =
    let public_key = CArray.make Ctypes_static.uchar 32 in
    let () =
      wg_generate_public_key (CArray.start public_key)
        (CArray.start private_key)
    in
    public_key

  let generate_preshared_key () =
    let key = CArray.make Ctypes_static.uchar 32 in
    let () = wg_generate_preshared_key (CArray.start key) in
    key

  let to_string (key : t) =
    let base64 = CArray.make Ctypes_static.char 44 in
    let () = wg_key_to_base64 (CArray.start base64) (CArray.start key) in
    Ctypes.string_from_ptr
      (Ctypes.CArray.start base64)
      ~length:(Ctypes.CArray.length base64)

  let of_string (key_string : string) =
    let base64 = CArray.of_string key_string in
    assert (CArray.length base64 = 45);
    let key = CArray.make Ctypes_static.uchar 32 in
    let err = wg_key_from_base64 (CArray.start key) (CArray.start base64) in
    match err with 0 -> Ok key | _ -> Error "Failed to convert string to key"
end

module Allowed_ip = struct
  open Ctypes
  module Ip = Ipaddr

  type t = { ip : Ip.t; cidr : Unsigned.UInt8.t }

  let to_wg_allowed_ip allowed_ip =
    let family =
      match allowed_ip.ip with Ip.V4 _ -> af_inet | Ip.V6 _ -> af_inet6
    in
    let callowed_ip = make Wg_peer.AllowedIp.wg_allowedip in
    setf callowed_ip Wg_peer.AllowedIp.family (Unsigned.UInt16.of_int family);
    setf callowed_ip Wg_peer.AllowedIp.cidr allowed_ip.cidr;

    (* Set the ip of the allowed ip c struct *)
    let () =
      match allowed_ip.ip with
      | Ip.V4 ip ->
          let addr = make Wg_peer.AllowedIp.in_addr in
          (* Reverse the octets of the ip *)
          (* TODO: figure out which way to flip oc tects is faster *)
          let ip_octets = Ip.V4.to_octets ip |> Base.String.to_array in
          let ip_uint32 =
            Base.Array.fold_right ~init:Unsigned.UInt32.zero
              ~f:(fun c (acc : Unsigned.UInt32.t) ->
                Unsigned.UInt32.logor
                  (Unsigned.UInt32.shift_left acc 8)
                  (Unsigned.UInt32.of_int (Base.Char.to_int c)))
              ip_octets
          in
          (* let ip_uint32 = *)
          (*   Ip.V4.to_octets ip |> Base.String.to_list_rev |> Base.String.of_list *)
          (* |> Ip.V4.of_octets_exn *)
          (* in *)
          setf addr Wg_peer.AllowedIp.s_addr ip_uint32;
          let ip = make Wg_peer.AllowedIp.ip_union in
          setf ip Wg_peer.AllowedIp.ip4 addr;
          setf callowed_ip Wg_peer.AllowedIp.ip ip
      | Ip.V6 ip ->
          let addr = make Wg_peer.AllowedIp.in6_addr in
          let ip_buf = Buffer.create 16 in
          Ip.V6.to_buffer ip_buf ip;
          Array.iteri
            (fun i c ->
              setf addr c
                (Buffer.nth ip_buf i |> Base.Char.to_int
               |> Unsigned.UChar.of_int))
            Wg_peer.AllowedIp.s6_addr;
          let ip = make Wg_peer.AllowedIp.ip_union in
          setf ip Wg_peer.AllowedIp.ip6 addr;
          setf callowed_ip Wg_peer.AllowedIp.ip ip
    in
    callowed_ip

  let of_wg_allowed_ip allowed_ip : t =
    let allowed_ip = !@allowed_ip in
    let family =
      getf allowed_ip Wg_peer.AllowedIp.family |> Unsigned.UInt16.to_int
    in
    let cidr = getf allowed_ip Wg_peer.AllowedIp.cidr in
    let ip_union = getf allowed_ip Wg_peer.AllowedIp.ip in
    let ip : Ip.t =
      match family with
      | x when x == af_inet ->
          let addr = getf ip_union Wg_peer.AllowedIp.ip4 in
          let ip =
            getf addr Wg_peer.AllowedIp.s_addr |> Unsigned.UInt32.to_int32
          in
          Ip.V4 (Ip.V4.of_int32 ip)
      | x when x == af_inet6 ->
          let addr = getf ip_union Wg_peer.AllowedIp.ip6 in
          let ip_buf = Buffer.create 16 in
          Array.iter
            (fun c ->
              Buffer.add_char ip_buf
                (getf addr c |> Unsigned.UChar.to_int |> Base.Char.of_int_exn))
            Wg_peer.AllowedIp.s6_addr;
          let ip =
            Ip.V6.of_octets_exn (ip_buf |> Buffer.to_seq |> String.of_seq)
          in
          Ip.V6 ip
      | _ -> failwith "Invalid family"
    in
    { ip; cidr }

  let set_next_allowedip allowed_ip next =
    setf allowed_ip Wg_peer.AllowedIp.next_allowedip next

  (** [allowed_ips_of_list] [allowed_ip] takes a list ip allowed ips zips them together into a linked list and returns the first an last pointer *)
  let allowed_ips_of_list (allowed_ips : t list) =
    let allowed_ips = List.map to_wg_allowed_ip allowed_ips in
    let rec loop = function
      | [] -> ()
      | [ x ] -> set_next_allowedip x None
      | x :: y :: xs ->
          set_next_allowedip x (Some (addr y));
          loop (y :: xs)
    in
    loop allowed_ips;
    let first = List.hd allowed_ips |> addr in
    let last = Base.List.last_exn allowed_ips |> addr in
    (first, last)

  let list_of_first_last first last =
    let rec loop acc current =
      if current == last then acc
      else
        let next = getf !@current Wg_peer.AllowedIp.next_allowedip in
        match next with None -> acc | Some next -> loop (current :: acc) next
    in
    loop [] first |> List.map of_wg_allowed_ip
end

(* TODO: define endpoint *)
module Peer = struct
  open Ctypes

  (* WGPEER_REMOVE_ME = 1U << 0,
     WGPEER_REPLACE_ALLOWEDIPS = 1U << 1,
     WGPEER_HAS_PUBLIC_KEY = 1U << 2,
     WGPEER_HAS_PRESHARED_KEY = 1U << 3,
     WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL = 1U << 4 *)
  type t = {
    public_key : Key.t Option.t;
    preshared_key : Key.t Option.t;
    endpoint : Unix.sockaddr Option.t;
    last_handshake_time : Float.t;
    rx_bytes : int;
    tx_bytes : int;
    persistent_keepalive_interval : int Option.t;
    allowed_ips : Allowed_ip.t list;
  }

  let create ?(public_key : Key.t option) ?(preshared_key : Key.t option)
      ?(endpoint : Unix.sockaddr option)
      ?(persistent_keepalive_interval : int option) ?allowed_ips () =
    {
      public_key;
      preshared_key;
      endpoint;
      last_handshake_time = 0.0;
      rx_bytes = 0;
      tx_bytes = 0;
      persistent_keepalive_interval;
      allowed_ips = Option.value ~default:[] allowed_ips;
    }

  (* Note: does this need to be a pointer? *)
  type s = Wg_peer.wg_peer structure
  type p = s ptr

  let to_wg_peer peer : s =
    let flags = ref Wg_peer.Wg_peer_flags.wgpeer_replace_allowedips in
    let cpeer = make Wg_peer.wg_peer in
    (* Set public key *)
    let () =
      match peer.public_key with
      | None -> ()
      | Some key ->
          let () =
            CArray.iteri
              (fun i c ->
                Ctypes.setf cpeer (Array.get Wireguard.Wg_peer.public_key i) c)
              key
          in
          flags := !flags lor Wg_peer.Wg_peer_flags.wgpeer_has_public_key
    in
    (* Set preshared key *)
    let () =
      match peer.preshared_key with
      | None -> ()
      | Some key ->
          let () =
            CArray.iteri
              (fun i c ->
                Ctypes.setf cpeer
                  (Array.get Wireguard.Wg_peer.preshared_key i)
                  c)
              key
          in
          flags := !flags lor Wg_peer.Wg_peer_flags.wgpeer_has_preshared_key
    in
    (* Set persistent_keepalive_interval *)
    let () =
      match peer.persistent_keepalive_interval with
      | None -> ()
      | Some interval ->
          let () =
            setf cpeer Wg_peer.persistent_keepalive_interval
              (Unsigned.UInt16.of_int interval)
          in
          flags :=
            !flags
            lor Wg_peer.Wg_peer_flags.wgpeer_has_persistent_keepalive_interval
    in

    (* Set allowed ips *)
    let () =
      match List.is_empty peer.allowed_ips with
      | true -> ()
      | false ->
          let first_allowedip, last_allowedip =
            Allowed_ip.allowed_ips_of_list peer.allowed_ips
          in
          let () = setf cpeer Wg_peer.first_allowedip (Some first_allowedip) in
          let () = setf cpeer Wg_peer.last_allowedip (Some last_allowedip) in
          flags := !flags lor Wg_peer.Wg_peer_flags.wgpeer_replace_allowedips
    in

    (* Set flags *)
    setf cpeer Wg_peer.flags (Unsigned.UInt16.of_int !flags);

    (* Set endpoint *)
    (* let () = failwith "Not implemented" in *)
    cpeer

  let of_wg_peer (peer : s) : t =
    let flags = getf peer Wg_peer.flags |> Unsigned.UInt16.to_int in
    let public_key : Key.t Option.t =
      match flags land Wg_peer.Wg_peer_flags.wgpeer_has_public_key with
      | 0 -> None
      | _ ->
          Some
            (Array.map (fun c -> getf peer c) Wg_peer.public_key |> Key.of_array)
    in
    let preshared_key : Key.t Option.t =
      match flags land Wg_peer.Wg_peer_flags.wgpeer_has_preshared_key with
      | 0 -> None
      | _ ->
          Some
            (Array.map (fun c -> getf peer c) Wg_peer.preshared_key
            |> Key.of_array)
    in
    let persistent_keepalive_interval =
      match
        flags
        land Wg_peer.Wg_peer_flags.wgpeer_has_persistent_keepalive_interval
      with
      | 0 -> None
      | _ ->
          Some
            (getf peer Wg_peer.persistent_keepalive_interval
            |> Unsigned.UInt16.to_int)
    in
    let last_handshake_time = getf peer Wg_peer.last_handshake_time in
    let last_handshake_time_sec =
      getf last_handshake_time TimeSpec64.tv_sec |> Int64.to_int
    in
    let last_handshake_time_nsec =
      getf last_handshake_time TimeSpec64.tv_nsec |> Int64.to_int
    in
    let last_handshake_time =
      Float.of_int last_handshake_time_sec
      +. (Float.of_int last_handshake_time_nsec /. 1_000_000_000.)
    in
    let rx_bytes = getf peer Wg_peer.rx_bytes |> Unsigned.UInt64.to_int in
    let tx_bytes = getf peer Wg_peer.tx_bytes |> Unsigned.UInt64.to_int in
    let first_allowedip = getf peer Wg_peer.first_allowedip in
    let last_allowedip = getf peer Wg_peer.last_allowedip in
    let allowed_ips =
      match (first_allowedip, last_allowedip) with
      | Some first, Some last -> Allowed_ip.list_of_first_last first last
      | _, _ -> []
    in
    {
      public_key;
      preshared_key;
      endpoint = None;
      last_handshake_time;
      rx_bytes;
      tx_bytes;
      persistent_keepalive_interval;
      allowed_ips;
    }

  let list_of_first_last (start : p) (stop : p) : t list =
    let rec loop acc current : s list =
      if current == stop then acc
      else
        let next = getf !@current Wg_peer.next_peer in
        match next with
        | None -> acc
        | Some next -> loop (!@current :: acc) next
    in
    loop [] start |> List.map of_wg_peer

  let set_next_peer (peer : s) next = setf peer Wg_peer.next_peer next

  let s_list_of_list (peers : t list) =
    let cpeers = List.map to_wg_peer peers in
    let rec loop = function
      | [] -> ()
      | [ x ] -> set_next_peer x None
      | x :: y :: xs ->
          set_next_peer x (Some (addr y));
          loop (y :: xs)
    in
    loop cpeers;
    cpeers

  let first_last_of_list (peers : t list) =
    assert (List.is_empty peers |> not);
    let cpeers = s_list_of_list peers in
    let first = Base.List.hd_exn cpeers |> addr in
    let last = Base.List.last_exn cpeers |> addr in
    (first, last)

  (* TODO:
        - Need to be able to allocate a new peer in memory
        - Need to construct a list
        - Remove a peer
        - Set allowed Ips
        - add allowed ips *)
end

module Interface = struct
  open Ctypes

  (* typedef struct wg_device { *)
  (* 	char name[IFNAMSIZ]; *)
  (* 	uint32_t ifindex; *)
  (* 	enum wg_device_flags flags; *)
  (* 	wg_key public_key; *)
  (* 	wg_key private_key; *)
  (* 	uint32_t fwmark; *)
  (* 	uint16_t listen_port; *)
  (* 	struct wg_peer *first_peer, *last_peer; *)
  (* } wg_device; *)

  type t = {
    name : string;
    ifindex : int;
    public_key : Key.t Option.t;
    private_key : Key.t Option.t;
    fwmark : int Option.t;
    listen_port : int Option.t;
    peers : Peer.t List.t;
  }

  module Config = struct
    type t = {
      name : string;
      private_key : Key.t Option.t;
      listen_port : int Option.t;
      peers : Peer.t List.t;
    }
  end

  let create ~name ?(public_key : Key.t option) ?(private_key : Key.t option)
      ?(fwmark : int option) ?(listen_port : int option) ?peers () =
    let _ = Wireguard.wg_add_device name in
    {
      name;
      ifindex = -1;
      public_key;
      private_key;
      fwmark;
      listen_port;
      peers = Option.value ~default:[] peers;
    }

  let to_wg_device device =
    let flags = ref Wg_device.Wg_device_flags.wgdevice_replace_peers in
    let cdevice = make Wg_device.wg_device in
    let name_arr = Base.String.to_array device.name in
    (* Set name *)
    let () =
      Base.Array.iteri
        ~f:(fun i c -> setf cdevice (Array.get Wireguard.Wg_device.name i) c)
        name_arr
    in
    (* Set port *)
    let () =
      match device.listen_port with
      | None -> ()
      | Some port ->
          let () =
            setf cdevice Wg_device.listen_port (Unsigned.UInt16.of_int port)
          in
          flags := !flags lor Wg_device.Wg_device_flags.wgdevice_has_listen_port
    in
    (* Set public key *)
    let () =
      match device.public_key with
      | None -> ()
      | Some key ->
          let () =
            CArray.iteri
              (fun i c ->
                Ctypes.setf cdevice
                  (Array.get Wireguard.Wg_device.public_key i)
                  c)
              key
          in
          flags := !flags lor Wg_device.Wg_device_flags.wgdevice_has_public_key
    in
    (* Set Private key *)
    let () =
      match device.private_key with
      | None -> ()
      | Some key ->
          let () =
            CArray.iteri
              (fun i c ->
                Ctypes.setf cdevice
                  (Array.get Wireguard.Wg_device.private_key i)
                  c)
              key
          in
          flags := !flags lor Wg_device.Wg_device_flags.wgdevice_has_private_key
    in
    (* Set fwmark *)
    let () =
      match device.fwmark with
      | None -> ()
      | Some fwmark ->
          let () =
            setf cdevice Wg_device.fwmark (Unsigned.UInt32.of_int fwmark)
          in
          flags := !flags lor Wg_device.Wg_device_flags.wgdevice_has_fwmark
    in
    (* Set flags *)
    let () = setf cdevice Wg_device.flags (Unsigned.UInt16.of_int !flags) in
    (* set first and last peer *)
    let first_peer, last_peer = Peer.first_last_of_list device.peers in
    let () = setf cdevice Wg_device.first_peer (Some first_peer) in
    let () = setf cdevice Wg_device.last_peer (Some last_peer) in
    cdevice

  let of_wg_device cdevice =
    let device =
      {
        name = "";
        ifindex = 0;
        public_key = None;
        private_key = None;
        fwmark = None;
        listen_port = None;
        peers = [];
      }
    in
    let flags = getf cdevice Wg_device.flags |> Unsigned.UInt16.to_int in
    print_endline (flags |> Int.to_string);
    (* Listen port *)
    let device =
      match flags land Wg_device.Wg_device_flags.wgdevice_has_listen_port with
      | 0 -> device
      | _ ->
          {
            device with
            listen_port =
              Some (getf cdevice Wg_device.listen_port |> Unsigned.UInt16.to_int);
          }
    in
    (* Public key *)
    let device =
      match flags land Wg_device.Wg_device_flags.wgdevice_has_public_key with
      | 0 -> device
      | _ ->
          let public_key =
            Array.map (fun c -> getf cdevice c) Wg_device.public_key
          in
          { device with public_key = Some (Key.of_array public_key) }
    in
    (* private key *)
    let device =
      match flags land Wg_device.Wg_device_flags.wgdevice_has_private_key with
      | 0 -> device
      | _ ->
          let private_key =
            Array.map (fun c -> getf cdevice c) Wg_device.private_key
          in
          { device with private_key = Some (Key.of_array private_key) }
    in
    (* fwmark *)
    let device =
      match flags land Wg_device.Wg_device_flags.wgdevice_has_fwmark with
      | 0 -> device
      | _ ->
          {
            device with
            fwmark =
              Some (getf cdevice Wg_device.fwmark |> Unsigned.UInt32.to_int);
          }
    in
    (* Name *)
    let device =
      let name = Array.map (fun c -> getf cdevice c) Wg_device.name in
      { device with name = Base.String.of_array name }
    in
    (* Ifindex *)
    let device =
      let ifindex = getf cdevice Wg_device.ifindex |> Unsigned.UInt32.to_int in
      { device with ifindex }
    in
    let first_peer = getf cdevice Wg_device.first_peer in
    let last_peer = getf cdevice Wg_device.last_peer in
    match (first_peer, last_peer) with
    | Some first, Some last ->
        { device with peers = Peer.list_of_first_last first last }
    | _, None -> device
    | None, _ -> device

  let get_device name =
    let cdevice = make Wg_device.wg_device in
    let cdevice = allocate (ptr Wg_device.wg_device) (addr cdevice) in
    let res = wg_get_device cdevice name in
    match res with
    | 0 -> Ok (of_wg_device !@(!@cdevice))
    | _ -> Error "Failed to get device"
  (* Note: when sending peers they need to be stored in stable memory (bigarray, CArray, malloc, Ctypes.allocate) I assume Ctypes.make *)

  (* Wireguard.Wg_device.Wg_device_flags.wgdevice_replace_peers <- Used to replace peers instead of adding them *)
  (* Set device without the public key flag *)
  let add_peers _device _peers = failwith "Not implemented"
  let set_peers _device _peers = failwith "Not implemented"

  let set_device device =
    let cdevice = to_wg_device device in
    let res = wg_set_device (addr cdevice) in
    (* TODO: create error type with all possible errors *)
    match res with 0 -> Ok () | _ -> Error (`Msg "Failed to set device")

  let configure_peer _peer = failwith "Not implemented"
  let remove_peer _peer = failwith "Not implemented"
  let configure_peers _peers = failwith "Not implemented"
  let remove_peers _pers = failwith "Not impolemented"
end
