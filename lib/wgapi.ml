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
  type t
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
    let cdevice = make Wg_device.wg_device in
    let name_arr = Base.String.to_array device.name in
    let () =
      Base.Array.for_alli
        ~f:(fun i c ->
          Ctypes.setf cdevice (Array.get Wglib.Wireguard.Wg_device.name i) c
          |> ignore;
          true)
        name_arr
      |> ignore
    in

    cdevice

  (* Array.iteri *)
  (*       (fun i c -> *)
  (*         Ctypes.setf device (Array.get Wglib.Wireguard.Wg_device.name i) c) *)
  (*       name *)

  (* Wireguard.Wg_device.Wg_device_flags.wgdevice_replace_peers <- Used to replace peers instead of adding them *)
end
