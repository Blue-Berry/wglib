let _ = Wglib.Wireguard.wg_add_device "wg9"
let names = Wglib.Wireguard.wg_list_device_names ()
let () = print_endline names
