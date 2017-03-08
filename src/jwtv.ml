open Core.Std
open Async.Std


let http_get uri_str =
  let open Cohttp_async in
  let uri = Uri.of_string uri_str in
  Client.get uri
  >>= fun (_, body) ->
  Body.to_string body
  >>| Yojson.Basic.from_string


let get_openid_configuration issuer =
  http_get
    (String.concat [ issuer; "/.well-known/openid-configuration" ])


let get_issuer_jwks issuer =
  let open Yojson.Basic.Util in
  get_openid_configuration issuer
  >>= fun config ->
  begin match member "jwks_uri" config with
    | `String jwks_uri -> http_get jwks_uri
    | _                -> return (`List [])
  end


let find_jwk alg kid kty jwks =
  let open Yojson.Basic.Util in
  let f x =
    match (member "alg" x, member "kid" x, member "kty" x) with
    | `String a, `String k, `String t ->
      String.equal a alg
      && String.equal k kid
      && String.equal t kty
    | _ -> false
  in
  match List.find ~f jwks with
  | Some key ->
    begin match (member "n" key, member "e" key) with
      | `String n, `String e ->
        Some (n, e)
      | _ -> None
    end
  | None -> None


let asn1_sha256 =
  Cstruct.of_string "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"


let pkcs1_sig header body =
  let open Cstruct in
  let hlen = len header in
  if check_bounds body hlen
  then
    match split ~start:0 body hlen with
    | a, b when equal a header -> Some b
    | _ -> None
  else
    None


let rs256 ~n ~e ~signature data =
  let unbase64 = B64.decode ~alphabet:B64.uri_safe_alphabet in
  let open Nocrypto in
  let open Cstruct in
  let sign = signature |> unbase64 |> of_string in
  let n = n |> unbase64 |> of_string |> Numeric.Z.of_cstruct_be in
  let e = e |> unbase64 |> of_string |> Numeric.Z.of_cstruct_be in
  let key = Rsa.({ n = n; e = e }) in
  begin match Rsa.PKCS1.sig_decode ~key sign with
    | Some asn1_sign ->
      begin match pkcs1_sig asn1_sha256 asn1_sign with
        | Some decrypted_sign ->
          Cstruct.equal decrypted_sign
            (Hash.SHA256.digest (of_string data))
      | _ -> false
      end
    | _ -> false
  end


let verify_online ~alg ~keysfile jwt =
  let tks = String.split ~on:'.' jwt in
  if 3 <= List.count ~f:(const true) tks
  then
    let header = List.nth_exn tks 0 in
    let payload = List.nth_exn tks 1 in
    let signature = List.nth_exn tks 2 in
    let message = String.concat [ header; "."; payload ] in
    let unbase64 = B64.decode ~alphabet:B64.uri_safe_alphabet in
    let open Yojson.Basic in
    let open Yojson.Basic.Util in
    let hdr = unbase64 header |> from_string in
    let pay = unbase64 payload |> from_string in

    begin match keysfile with
      | Some filename ->
        Reader.file_contents filename
        >>| from_string
      | None ->
        begin match member "iss" pay with
          | `String iss -> get_issuer_jwks iss
          | _           -> return (`List [])
        end
    end
    >>= fun jwks ->
    begin match member "keys" jwks with
      | `List keys -> return keys
      | _          -> return []
    end
    >>= fun jwks ->
    begin match (alg, member "alg" hdr, member "kid" hdr) with
      | "RS256", `String ("RS256" as alg), `String kid ->
        begin match find_jwk alg kid "RSA" jwks with
          | Some (n, e) ->
            if rs256 ~n ~e ~signature message
            then Some pay
            else None
          | None -> None
        end
      | _ -> None
    end
    |> return
  else return None
