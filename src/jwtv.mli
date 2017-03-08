(** JWT signature verifier *)


(** Verify JWT's signature online *)
val verify_online :
  alg:string ->
  keysfile:string option ->
  string -> Yojson.Basic.json option Async.Std.Deferred.t
(** alg is algorithm (default "RS256")

    keysfile is jwks filename with json format.
    Download public keys if this is None.

    returns Some (json payload) if signature is valid. *)


(** Verify with RS256 *)
val rs256 :
  n:string ->
  e:string ->
  signature:string ->
  string ->
  bool
(** n and e is RSA public key's n and e with base64urlsafe.

    signature is JWT's signature part with base64urlsafe.

    last arg must be first 2 components of JWT (i.e. without signature part)

    returns true if and only if valid signature. *)
