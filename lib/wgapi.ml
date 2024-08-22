open Wireguard

module Key = struct
  open Ctypes

  type t = Unsigned.uchar Ctypes_static.carray

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
  type t = (Wg_peer.wg_peer, [ `Struct ]) Ctypes.structured
  (* TODO: Implement *)
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
    let () =
      match device.peer |> Base.List.hd with
      | None -> ()
      | Some peer -> setf cdevice Wg_device.first_peer (addr peer)
    in
    cdevice

  (* Wireguard.Wg_device.Wg_device_flags.wgdevice_replace_peers <- Used to replace peers instead of adding them *)
end
