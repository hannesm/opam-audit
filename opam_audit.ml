let ( let* ) = Result.bind

type package = {
  name : string ;
}

let make_package name = { name }

type affected = {
  package : package ;
  versions : string list option ;
}

let make_affected package versions = { package ; versions }

let affected_json =
  let package_json =
    Jsont.Object.map ~kind:"package" make_package
    |> Jsont.Object.mem "name" Jsont.string ~enc:(fun { name ; _ } -> name)
    |> Jsont.Object.finish
  in
  Jsont.Object.map ~kind:"affected" make_affected
  |> Jsont.Object.mem "package" package_json ~enc:(fun { package ; _ } -> package)
  |> Jsont.Object.mem "versions" Jsont.(option (list string)) ~dec_absent:None ~enc_omit:Option.is_none ~enc:(fun { versions ; _ } -> versions)
  |> Jsont.Object.finish

type osv = {
  id : string ;
  summary : string ;
  affected : affected list ;
}

let make_osv id summary affected = { id ; summary ; affected }

let osv_json =
  Jsont.Object.map ~kind:"osv" make_osv
  |> Jsont.Object.mem "id" Jsont.string ~enc:(fun { id ; _ } -> id)
  |> Jsont.Object.mem "summary" Jsont.string ~enc:(fun { summary ; _ } -> summary)
  |> Jsont.Object.mem "affected" (Jsont.list affected_json) ~enc:(fun { affected ; _ } -> affected)
  |> Jsont.Object.finish

let decode_one_advisory file =
  let* content = Bos.OS.File.read file in
  let* osv =
    Result.map_error (fun s -> `Msg s)
      (Jsont_bytesrw.decode_string osv_json content)
  in
  let id, summary, vs =
    osv.id, osv.summary,
    List.filter_map (fun aff ->
        match aff.versions with
        | None | Some [] -> None
        | Some versions -> Some (aff.package.name, versions))
      osv.affected
  in
  Ok (id, summary, vs)

let get_advisories () =
  let* dir = Bos.OS.Dir.user () in
  let location = Fpath.(dir / ".config" / "opam-audit") in
  let git_repo = Fpath.(location / "security-advisories") in
  let* res =
    let* exists = Bos.OS.Dir.exists Fpath.(git_repo / ".git") in
    if exists then
      Bos.OS.Dir.with_current git_repo (fun () ->
          let cmd = Bos.Cmd.(v "git" % "pull") in
          Bos.OS.Cmd.(run_out cmd |> out_null |> success)) ()
    else
      let* _created = Bos.OS.Dir.create location in
      Bos.OS.Dir.with_current location (fun () ->
          let cmd = Bos.Cmd.(v "git" % "clone" % "-b" % "generated-osv" % "https://github.com/ocaml/security-advisories") in
          Bos.OS.Cmd.(run_out cmd |> out_null |> success)) ()
  in
  let* () = res in
  Result.join
    (Bos.OS.Dir.fold_contents ~elements:`Files (fun path acc ->
         let* acc = acc in
         let* thing = decode_one_advisory path in
         Ok (thing :: acc)) (Ok []) git_repo)

let search_in ~gt sw advisories =
  Logs.app (fun m -> m "Looking for vulnerable packages in switch %s" (OpamSwitch.to_string sw));
  let selections = OpamSwitchState.load_selections ~lock_kind:`Lock_read gt sw in
  let installed = selections.sel_installed in
  let found = ref 0 in
  List.iter (fun (id, summ, pkgs) ->
      List.iter (fun pkg ->
          let inter = OpamPackage.Set.inter installed pkg in
          if OpamPackage.Set.is_empty inter then
            ()
          else begin
            incr found;
            OpamPackage.Set.iter (fun pkg ->
                Logs.warn (fun m -> m "%s has the known vulnerability %s: %s (read full advisory https://osv.dev/vulnerability/%s)"
                              (OpamPackage.to_string pkg) id summ id))
              inter
          end)
        pkgs)
    advisories;
  if !found > 0 then
    Error (`Msg (Fmt.str "Found %u vulnerabilit%s" !found (if !found = 1 then "y" else "ies")))
  else begin
    Logs.app (fun m -> m "Great, no known vulnerabilities found  through %u advisories"
                 (List.length advisories));
    Ok ()
  end

let jump () =
  OpamSystem.init ();
  OpamGlobalState.with_ `Lock_none @@ fun gt ->
  let gt = OpamGlobalState.fix_switch_list gt in
  let current =
    match OpamStateConfig.load ~lock_kind:`Lock_read (OpamStateConfig.opamroot ()) with
    | Some t -> OpamFile.Config.switch t
    | None -> None
  in
  let cur_dir = OpamStateConfig.get_current_switch_from_cwd gt.root in
  let* advisories = get_advisories () in
  let advisories =
    let to_pkg_set (name, vs) =
      OpamPackage.Set.of_list (List.map (fun v -> OpamPackage.of_string (name ^ "." ^ v)) vs)
    in
    List.map (fun (id, summ, vs) -> id, summ, List.map to_pkg_set vs) advisories
  in
  match cur_dir, current with
  | None, None ->
    Logs.err (fun m -> m "no switch!");
    Error (`Msg "couldn't find switch")
  | Some sw, _ -> search_in ~gt sw advisories
  | None, Some sw -> search_in ~gt sw advisories

let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ~dst:Format.std_formatter ())

open Cmdliner

let setup_log =
  Term.(const setup_log
        $ Fmt_cli.style_renderer ()
        $ Logs_cli.level ())

let exits =
    Cmd.Exit.info ~doc:"on vulnerability finding(s)." 1 ::
    Cmd.Exit.defaults

let cmd =
  let info = Cmd.info "opam-audit" ~version:"%%VERSION_NUM%%" ~exits
  and term =
    Term.(term_result (const jump $ setup_log))
  in
  Cmd.v info term

let () = exit (Cmd.eval ~term_err:1 cmd)
