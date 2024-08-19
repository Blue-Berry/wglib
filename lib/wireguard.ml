open Ctypes

type wg_device = unit ptr

let wg_device : wg_device typ = ptr void

open Foreign

let wg_set_device = foreign "wg_set_device" (wg_device @-> returning int)

let wg_get_device =
  foreign "wg_get_device" (wg_device @-> string @-> returning int)

let wg_add_device = foreign "wg_add_device" (string @-> returning int)
let wg_del_device = foreign "wg_del_device" (string @-> returning int)
let wg_free_device = foreign "wg_free_device" (wg_device @-> returning void)

let wg_list_device_names =
  foreign "wg_list_device_names" (void @-> returning string)

(* void wg_key_to_base64(wg_key_b64_string base64, const wg_key key); *)
(* int wg_key_from_base64(wg_key key, const wg_key_b64_string base64); *)
(* bool wg_key_is_zero(const wg_key key); *)
(* void wg_generate_public_key(wg_key public_key, const wg_key private_key); *)
(* void wg_generate_private_key(wg_key private_key); *)
(* void wg_generate_preshared_key(wg_key preshared_key); *)
