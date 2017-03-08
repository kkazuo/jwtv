#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  Pkg.describe "jwtv" @@ fun c ->
  Ok [ Pkg.mllib ~api:["Jwtv"] "src/jwtv.mllib";
       Pkg.bin ~dst:"jwtv" "app/main" ]
