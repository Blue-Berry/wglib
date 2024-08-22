open Wireguard

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

  let to_base64 key =
    let base64 = CArray.make Ctypes_static.char 44 in
    let () = wg_key_to_base64 (CArray.start base64) (CArray.start key) in
    Ctypes.string_from_ptr
      (Ctypes.CArray.start base64)
      ~length:(Ctypes.CArray.length base64)
end

module Peer = struct
  open Ctypes

  (* Note: does this need to be a pointer? *)
  type t = Wg_peer.wg_peer structure
  (* TODO: Implement *)

  let list_from_start_stop (start : t) (stop : t) =
    let rec loop acc current =
      if addr current == addr stop then acc
      else
        let next = getf current Wg_peer.next_peer in
        loop (current :: acc) !@next
    in
    loop [] start
end

module Device = struct
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
    peer : Peer.t List.t;
  }

  let to_wg_device device =
    let flags = ref 0 in
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
                  (Array.get Wglib.Wireguard.Wg_device.public_key i)
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
                  (Array.get Wglib.Wireguard.Wg_device.private_key i)
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
    let () =
      match device.peer |> Base.List.hd with
      | None -> ()
      | Some peer -> setf cdevice Wg_device.first_peer (addr peer)
    in
    let () =
      match device.peer |> Base.List.last with
      | None -> ()
      | Some peer -> setf cdevice Wg_device.last_peer (addr peer)
    in

    cdevice

  let from_wg_device cdevice =
    let device =
      {
        name = "";
        ifindex = 0;
        public_key = None;
        private_key = None;
        fwmark = None;
        listen_port = None;
        peer = [];
      }
    in
    let flags = getf cdevice Wg_device.flags |> Unsigned.UInt16.to_int in
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
    let start_peer = getf cdevice Wg_device.first_peer in
    let stop_peer = getf cdevice Wg_device.last_peer in
    match start_peer with
    | start_peer when Ctypes.is_null start_peer -> device
    | start_peer when start_peer == stop_peer ->
        { device with peer = [ !@start_peer ] }
    | _ ->
        let peers = Peer.list_from_start_stop !@start_peer !@stop_peer in
        { device with peer = peers }

  (* Wireguard.Wg_device.Wg_device_flags.wgdevice_replace_peers <- Used to replace peers instead of adding them *)
end
