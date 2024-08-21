let key = Wglib.Wgapi.Key.generate_private_key ()
let () = print_endline (Wglib.Wgapi.Key.to_base64 key)
let public_key = Wglib.Wgapi.Key.generate_public_key key
let () = print_endline (Wglib.Wgapi.Key.to_base64 public_key)
