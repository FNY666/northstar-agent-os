# Committed Git Snapshot Exporter

`security/export_git_snapshot.py` provides a deliberately small bridge from a CI-supplied, **full immutable Git commit ID** to a filesystem candidate view:

```python
export_git_snapshot(repository_path, commit, output_dir) -> dict
```

It is intended for **already committed CI source**. It is not an SDK base-plus-patch rebuilder and it does not invoke a parser, apply dynamic patches, checkout a revision, or build/install/scan candidate code.

## Accepted repository and commit

- `commit` is required to be exactly **40 or 64 hexadecimal characters**. Branches, tags, `HEAD`, abbreviated IDs, revision expressions, and path syntax are rejected before Git is invoked.
- `repository_path` may name a conventional checkout containing a real `.git` **directory**, or a normal bare repository. `.git` symlinks, gitfiles, linked worktrees, and `commondir` layouts are rejected.
- The exporter uses the fixed executable `/usr/bin/git`, never a shell. Every Git child gets a newly constructed environment rather than the caller's environment. System and global configuration are disabled; replacement objects, optional locks, system attributes, terminal prompts, and lazy fetch are disabled.
- The installed Git must pass a direct version check for the `GIT_NO_LAZY_FETCH` control. The Git available in this development environment is 2.43.0 and contains that control.
- Before Git plumbing reads objects, the exporter rejects local-config includes, partial-clone/promisor settings, alternate object stores (including `http-alternates`), `.promisor` packs, and unsafe relevant object-store entries. This matters because a missing promisor object must **fail**, not induce a remote fetch.

A normal local or bare repository is accepted; the checks are not a blanket rejection of repositories with ordinary local configuration, remotes, `.gitignore`, `.gitattributes`, or hooks.

## What is read and written

The implementation reads raw `commit`, `tree`, and `blob` objects via fixed `git cat-file` argv. It never calls:

- `git archive` — so candidate-controlled `export-ignore` and `export-subst` cannot select or substitute source;
- `git checkout`, `restore`, or worktree operations;
- `git cat-file --filters` / `--textconv` — so custom clean/smudge/text conversion commands are not run;
- a Git network, fetch, clone, hook, build, installer, package manager, or candidate executable.

Tree traversal is raw and recursive. Only `100644` and `100755` blob entries are accepted. `120000` symlinks, `160000` gitlinks/submodules, unsupported/special modes, malformed tree records, unsafe names (`.`, `..`, slash, backslash), invalid UTF-8 paths, collisions, excessive depth, excessive paths, and excessive path length fail closed.

The exporter verifies each raw object against its Git content-addressed object ID (`"<type> <length>\\0" + bytes`) while it is read. It caps Git stdout/stderr/time, commit and tree bytes, individual blob bytes, file count, nesting, path length, and aggregate blob bytes.

On success, `output_dir` is a new read-only directory with this fixed layout:

```text
output_dir/
├── candidate-manifest.json
└── source/
    └── ... exact nested committed regular files ...
```

`source/` prevents a committed file named `candidate-manifest.json` from colliding with exporter metadata. Regular committed modes become `0444`; executable committed modes become `0555`; directories are `0555`. No symlinks are created.

Publication uses a private `0700` staging directory below the requested output parent, writes and fsyncs files, seals modes, then uses Linux `renameat2(RENAME_NOREPLACE)`. An existing output name is never replaced, and failed exports do not publish a partial directory.

## Manifest and return value

`candidate-manifest.json` is canonical Northstar JSON (sorted keys, compact ASCII encoding, trailing newline) with this shape:

```json
{
  "schema": "northstar.git-snapshot.v1",
  "git": {
    "commit": "<full object id>",
    "tree": "<full object id>",
    "object_format": "sha1-or-sha256"
  },
  "files": [
    {
      "path": "relative/committed/path",
      "git_blob": "<full object id>",
      "mode": "100644-or-100755",
      "sha256": "<sha256 of raw blob bytes>",
      "bytes": 123
    }
  ],
  "file_count": 1,
  "total_bytes": 123
}
```

The return dictionary includes `git_commit`, `git_tree`, sorted `files`, `file_count`, `total_bytes`, `output_dir`, and both `candidate_manifest_sha256` and the compatibility alias `manifest_sha256`. These are SHA-256 values for the exact written manifest bytes. A manifest cannot contain its own digest without circularity, so the digest is returned to the caller rather than inserted into the manifest.

## Boundaries

This is a source-materialization primitive, not a statement that all CI input is safe. Git content addressing catches object-byte mismatch during the bounded traversal, but it does **not** claim to defend against a malicious local host/kernel, a privileged writer that modifies the filesystem after publication, or a compromised `/usr/bin/git`. Callers still need a trusted CI worker/filesystem and must treat the result as the candidate scope for separately controlled tooling.

The native tests use only temporary repositories and demonstrate a passing conventional and bare-repository export. They also demonstrate that tracked `.gitignore` and `export-ignore` content remains present; custom filters and a `post-checkout` hook do not execute; uncommitted and untracked working-tree files do not influence output; and refs, existing targets, gitfiles/gitdir links, unsafe tree paths, symlinks, gitlinks, special entries, alternates, partial config, damaged objects, and oversize blobs fail without publication.
