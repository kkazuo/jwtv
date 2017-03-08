open Core.Std
open Async.Std
open Yojson.Basic


let () =
  Command.async
    ~summary:"JWT verifier"
    Command.Spec.(
      empty
      +> flag "-alg" (optional_with_default "RS256" string)
        ~doc:"Algorithm [RS256]"
      +> flag "-offline" (optional string)
        ~doc:"jwks Offline JWKs json file"
      +> anon ("jwt" %: string))
    (fun alg keysfile jwt () ->
       Jwtv.verify_online ~alg ~keysfile jwt
       >>= fun r ->
       begin match r with
         | Some x -> print_endline (to_string x)
         | _      -> ()
       end
       |> return)
  |> Command.run
