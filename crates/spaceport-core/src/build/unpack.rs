//! Turning the bytes of a source archive into a directory on disk.
//!
//! These bytes came from GitHub, but they are not GitHub's. They are a
//! tarball of a commit, and the commit is whatever somebody who can push to a
//! tracked branch decided to write — a file named `../../etc/cron.d/anything`,
//! a symlink at `config` pointing at `/root/.ssh`, a hundred megabytes of
//! zeroes that compress to a kilobyte. Nothing between that person and this
//! function checks any of it: GitHub serves the tree it was given, and the
//! only thing spaceport's transport proved is that the bytes really are the
//! ones GitHub holds for that revision. So this module treats the archive as
//! hostile, and the threat model is exactly that — anybody with push access to
//! a branch a spaceport tracks is, at this point, writing files on the host.
//!
//! That is why nothing here calls [`tar::Archive::unpack`]. It is a good
//! function and it makes several of these decisions already, but it makes them
//! on its own terms and it can change them in a patch release. Every rule
//! below is spaceport's, is stated where an operator can read it, and has a
//! test that builds the archive which would break it. The rules are: exactly
//! one leading path component is stripped and every entry must share it; no
//! entry may be absolute or hold a `..` anywhere; a link may not point out of
//! the tree; nothing but regular files, directories and links exists; the
//! expansion is bounded in bytes and in entries and is stopped in the middle
//! rather than measured at the end; and the setuid and setgid bits do not
//! survive the journey.
//!
//! Judgements are made on the archive's own bytes and never on the filesystem.
//! A check that stats a link target to decide whether it is safe is a check
//! that can be true when it is asked and false a moment later, and the moment
//! is exactly the one an attacker who can also write into the destination gets
//! to choose. Link targets are therefore resolved lexically against the
//! entry's own directory, which is sound here for a reason worth stating: no
//! entry path may contain `..`, and every symlink written lands inside the
//! tree, so a path traversing symlinks this module created still lands inside
//! the tree.
//!
//! Refusal leaves whatever was written before the refusal where it is. That is
//! deliberate rather than sloppy: unwinding a half-expanded tree is more
//! deletion logic on a path an attacker influences, and the caller in
//! [`super::dir`] destroys the whole build directory anyway.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use flate2::read::GzDecoder;
use tar::{Archive, EntryType};
use tracing::debug;

/// The permission bits an archive is allowed to put on the host.
///
/// The mask's whole point is the three bits above it. Setuid and setgid on a
/// file in a build context are of no use to any build and of obvious use to
/// somebody who has just persuaded a spaceport to write a root-owned binary
/// onto its host, and the sticky bit means nothing outside a shared temporary
/// directory. Everything below is kept, the executable bit included: a
/// repository's `./configure` and its `scripts/build.sh` are meant to run, and
/// a build that fails with "permission denied" because spaceport flattened
/// every file to `0644` would be a bug reported against the repository rather
/// than against spaceport.
const PERMISSION_MASK: u32 = 0o0777;

/// Owner read and write, added to every mode taken from the archive.
///
/// An entry may honestly declare `0o444`, and a build that then cannot write
/// its own generated file fails for a reason nobody will find. The archive is
/// a build context rather than an installation, so its files belong to the
/// process expanding them.
const OWNER_ACCESS: u32 = 0o600;

/// The same for a directory, which additionally has to be enterable.
const OWNER_DIRECTORY_ACCESS: u32 = 0o700;

/// What an entry with an unreadable mode field gets instead.
const DEFAULT_FILE_MODE: u32 = 0o644;

/// The same for a directory.
const DEFAULT_DIRECTORY_MODE: u32 = 0o755;

/// How much of an entry is decompressed before the budget is consulted again.
///
/// The number matters only in that it is small. A bomb is refused after at
/// most this many bytes past the limit, so the disk cost of an archive lying
/// about its own sizes is bounded by one buffer rather than by the archive.
const CHUNK: usize = 64 * 1024;

/// What an archive is allowed to be.
///
/// Both numbers are the caller's, because what is generous for a source
/// repository is absurd for something else, and a limit written into this
/// module is one an operator cannot move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The most bytes all entries may come to once expanded.
    pub total: u64,
    /// The most entries an archive may hold.
    pub entries: usize,
}

/// What came out of an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unpacked {
    /// The single directory GitHub wrapped the commit in, as it was named.
    pub prefix: String,
    /// How many entries were written, the wrapper directory not among them.
    pub entries: usize,
    /// How many bytes of file content were written.
    pub bytes: u64,
}

/// Expand `archive` into `into`, and say what came out.
///
/// `into` is the caller's directory and must already exist. Nothing is ever
/// created outside it — not a sibling, not a parent, not a directory an entry
/// implies by naming itself `a/b/c` when `a` was never in the archive, because
/// that directory is made under `into` like everything else.
///
/// The returned prefix is read off the archive rather than reconstructed.
/// GitHub wraps a commit in one directory called `{owner}-{repo}-{short-sha}`,
/// which is behaviour it has never documented anywhere — building that name
/// from what spaceport knows would be spaceport asserting a convention GitHub
/// never promised, and it would break on the day GitHub shortens a sha
/// differently. So the first entry names the prefix, every other entry has to
/// agree, and the name is handed back for whoever wants to say what it was.
pub fn unpack(archive: &[u8], into: &Path, limits: &Limits) -> Result<Unpacked> {
    let mut tar = Archive::new(GzDecoder::new(archive));
    let entries = tar
        .entries()
        .context("reading the entries of a source archive")?;

    let mut prefix: Option<String> = None;
    let mut written = 0usize;
    let mut bytes = 0u64;

    for entry in entries {
        let mut entry = entry.context("reading an entry of a source archive")?;
        let kind = entry.header().entry_type();

        // `git archive` puts a global pax header at the front of every tarball
        // it makes, carrying the commit id as a comment, and GitHub's tarballs
        // are `git archive`'s. It describes the archive rather than naming
        // anything in it, so it is neither counted nor judged for a path it
        // does not have.
        if kind == EntryType::XGlobalHeader {
            continue;
        }

        let raw = String::from_utf8(entry.path_bytes().into_owned()).map_err(|_| {
            anyhow!(
                "an entry of this archive is named in bytes that are not utf-8, and spaceport will not guess at a path it cannot read"
            )
        })?;
        let components = components(&raw)?;

        let Some((root, rest)) = components.split_first() else {
            bail!("an entry of this archive is named `{raw}`, which names nothing at all");
        };

        match &prefix {
            None => prefix = Some((*root).to_owned()),
            Some(seen) if seen.as_str() == *root => {}
            Some(seen) => bail!(
                "this archive holds entries under `{seen}` and under `{root}`, and a github source archive wraps a commit in exactly one directory — this is not one"
            ),
        }

        // The wrapper directory itself. It is `into`, which the caller made,
        // so there is nothing to create and nothing to count.
        if rest.is_empty() {
            continue;
        }

        if written == limits.entries {
            bail!(
                "this archive holds more than the {} entries a build context may have",
                limits.entries
            );
        }

        let relative = rest.join("/");
        let destination = into.join(&relative);

        match kind {
            EntryType::Directory => {
                std::fs::create_dir_all(&destination)
                    .with_context(|| format!("creating the directory `{relative}` of a commit"))?;
                let mode = mode(entry.header(), DEFAULT_DIRECTORY_MODE) | OWNER_DIRECTORY_ACCESS;
                set_mode(&destination, mode, &relative)?;
            }
            EntryType::Regular | EntryType::Continuous => {
                if let Some(parent) = destination.parent() {
                    std::fs::create_dir_all(parent).with_context(|| {
                        format!("creating the directory `{relative}` is written into")
                    })?;
                }

                // The declared size first, so an entry that says outright it
                // will not fit is refused before a single byte of it is on the
                // disk. The streaming check below is what catches an entry
                // that lied.
                if entry.size() > limits.total - bytes {
                    bail!(
                        "`{relative}` alone expands past the {} bytes a build context may come to",
                        limits.total
                    );
                }

                bytes += write_file(&mut entry, &destination, bytes, limits, &relative)?;

                let mode = mode(entry.header(), DEFAULT_FILE_MODE) | OWNER_ACCESS;
                set_mode(&destination, mode, &relative)?;
            }
            EntryType::Symlink => {
                let target = link_target(&entry, &relative)?;
                // Against the directory the symlink itself sits in, which is
                // what a relative symlink means to the kernel.
                resolve(&rest[..rest.len() - 1], &target).ok_or_else(|| {
                    anyhow!(
                        "the symlink `{relative}` in this archive points at `{target}`, which is outside the commit — spaceport will not unpack an archive that links out of its own build context"
                    )
                })?;

                symlink(&target, &destination, &relative)?;
            }
            EntryType::Link => {
                // A hardlink's target is named from the root of the archive
                // rather than from the link's own directory, so it carries the
                // wrapper directory too and has to agree about it like every
                // other path in here.
                let target = link_target(&entry, &relative)?;
                let resolved = resolve(&[], &target).ok_or_else(|| {
                    anyhow!(
                        "the hard link `{relative}` in this archive points at `{target}`, which is outside the commit — spaceport will not unpack an archive that links out of its own build context"
                    )
                })?;
                let Some((root, rest)) = resolved.split_first() else {
                    bail!("the hard link `{relative}` in this archive points at nothing");
                };
                if Some(root) != prefix.as_ref() {
                    bail!(
                        "the hard link `{relative}` in this archive points at `{target}`, which is outside the commit"
                    );
                }

                std::fs::hard_link(into.join(rest.join("/")), &destination).with_context(|| {
                    format!("linking `{relative}` to `{target}` inside a commit")
                })?;
            }
            other => bail!(
                "`{relative}` in this archive is a {}, and a build context may hold only regular files, directories and links",
                describe(other)
            ),
        }

        written += 1;
    }

    let Some(prefix) = prefix else {
        bail!(
            "this source archive holds no entries at all, so there is nothing here to build from"
        );
    };

    if written == 0 {
        bail!(
            "this source archive holds nothing but its `{prefix}` directory, so there is nothing here to build from"
        );
    }

    debug!(prefix, entries = written, bytes, "unpacked a commit");

    Ok(Unpacked {
        prefix,
        entries: written,
        bytes,
    })
}

/// The components of an entry's path, once it has been found fit to have any.
///
/// Both refusals are outright rather than repaired. An absolute path is not
/// silently relativised, because an archive naming `/etc/passwd` is not an
/// archive that meant `etc/passwd` and pretending otherwise unpacks something
/// nobody asked for. A `..` is refused even where the whole path would resolve
/// back inside the tree: a path that has to be *evaluated* before it can be
/// called safe is a path that will one day be evaluated by different code, or
/// by the same code after a change, and get a different answer. The rule that
/// survives that is the one that never evaluates anything.
fn components(raw: &str) -> Result<Vec<&str>> {
    if raw.starts_with('/') {
        bail!(
            "an entry of this archive is named `{raw}`, which is an absolute path — a source archive names paths relative to the commit, and spaceport will not write outside the directory it was given"
        );
    }

    let mut components = Vec::new();
    for component in raw.split('/') {
        match component {
            // A trailing slash on a directory entry, or a doubled separator.
            "" => {}
            // `git archive` never emits one, and it means the entry's own
            // directory, so dropping it changes nothing about where the entry
            // lands.
            "." => {}
            ".." => bail!(
                "an entry of this archive is named `{raw}`, and spaceport refuses any path holding `..` — even one that would resolve back inside the commit, because a path that has to be evaluated to be judged safe is a path that will be evaluated wrongly one day"
            ),
            name => components.push(name),
        }
    }

    Ok(components)
}

/// Where `target` lands, as components below the destination root, or `None`
/// when it lands outside it.
///
/// `base` is the directory the target is relative to. Purely lexical, and
/// deliberately so — resolving a link by asking the filesystem where it points
/// is a check whose answer can be changed between the asking and the using.
fn resolve(base: &[&str], target: &str) -> Option<Vec<String>> {
    // Absolute link targets are refused rather than reinterpreted. `/etc` in a
    // repository means `/etc` on whatever host the tree ends up on, and that
    // is precisely the thing this module exists to prevent.
    if target.starts_with('/') {
        return None;
    }

    let mut resolved: Vec<String> = base.iter().map(|name| (*name).to_owned()).collect();
    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                resolved.pop()?;
            }
            name => resolved.push(name.to_owned()),
        }
    }

    Some(resolved)
}

/// What a link entry says it points at.
fn link_target(entry: &tar::Entry<'_, impl Read>, relative: &str) -> Result<String> {
    let bytes = entry
        .link_name_bytes()
        .ok_or_else(|| anyhow!("`{relative}` in this archive is a link that points at nothing"))?;

    String::from_utf8(bytes.into_owned()).map_err(|_| {
        anyhow!(
            "`{relative}` in this archive points somewhere named in bytes that are not utf-8, and spaceport will not guess at a link target it cannot read"
        )
    })
}

/// The mode an entry asks for, with everything spaceport will not carry onto
/// the host taken off it.
fn mode(header: &tar::Header, default: u32) -> u32 {
    // An unreadable mode field is an archive that is malformed in a way that
    // says nothing about safety, so it gets the ordinary mode rather than a
    // refusal.
    header.mode().unwrap_or(default) & PERMISSION_MASK
}

/// The bytes of one entry, written and counted as they go.
///
/// The counting happens per chunk rather than at the end, which is the whole
/// difference between refusing a decompression bomb and reporting one. An
/// archive's header can claim any size it likes; the stream is what actually
/// lands on the disk, and a limit checked after the copy has already been paid
/// in full.
fn write_file(
    entry: &mut impl Read,
    destination: &Path,
    already: u64,
    limits: &Limits,
    relative: &str,
) -> Result<u64> {
    let mut file = File::create(destination)
        .with_context(|| format!("creating `{relative}` from a source archive"))?;
    let mut buffer = vec![0u8; CHUNK];
    let mut written = 0u64;

    loop {
        let read = entry
            .read(&mut buffer)
            .with_context(|| format!("reading `{relative}` out of a source archive"))?;
        if read == 0 {
            break;
        }

        written += read as u64;
        if already + written > limits.total {
            bail!(
                "this archive expands to more than the {} bytes a build context may come to, and it was still expanding at `{relative}`",
                limits.total
            );
        }

        file.write_all(&buffer[..read])
            .with_context(|| format!("writing `{relative}` from a source archive"))?;
    }

    Ok(written)
}

/// What to call an entry type spaceport will not unpack.
fn describe(kind: EntryType) -> &'static str {
    match kind {
        EntryType::Char => "character device",
        EntryType::Block => "block device",
        EntryType::Fifo => "fifo",
        _ => "kind of entry spaceport does not unpack",
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32, relative: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting the mode of `{relative}` from a source archive"))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32, _relative: &str) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn symlink(target: &str, destination: &Path, relative: &str) -> Result<()> {
    std::os::unix::fs::symlink(target, destination)
        .with_context(|| format!("linking `{relative}` to `{target}` inside a commit"))
}

#[cfg(not(unix))]
fn symlink(_target: &str, _destination: &Path, relative: &str) -> Result<()> {
    bail!("`{relative}` in this archive is a symlink, which spaceport unpacks only on unix")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::{Builder, Header};

    /// A directory of this test run's own, under the system temp dir.
    ///
    /// The same helper as `crate::state::tests::temp_dir`, written out again
    /// because that one lives inside a private `#[cfg(test)] mod tests` and is
    /// reachable only from `state`'s own descendants. Widening its visibility
    /// would be editing another module for this one's convenience.
    fn temp_dir(name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("spaceport-test-{name}-{unique}"));
        let _ = std::fs::remove_dir_all(&directory);

        directory
    }

    /// The wrapper directory GitHub puts a commit in, spelled as GitHub spells
    /// it — undocumented, and therefore only ever read rather than assumed.
    const PREFIX: &str = "an-organisation-site-0123abc";

    /// Room enough that no test trips a limit it did not mean to.
    const ROOMY: Limits = Limits {
        total: 1 << 20,
        entries: 1000,
    };

    /// A destination the caller has already made, as `unpack` requires.
    fn destination(name: &str) -> PathBuf {
        let path = temp_dir(name);
        std::fs::create_dir_all(&path).unwrap();

        path
    }

    /// A tarball built entry by entry and gzipped, so the tests go in through
    /// the same door GitHub's bytes do.
    fn tarball(entries: impl FnOnce(&mut Builder<Vec<u8>>)) -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        entries(&mut builder);
        let tar = builder.into_inner().unwrap();

        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&tar).unwrap();

        encoder.finish().unwrap()
    }

    /// A header whose path is written into the name field by hand.
    ///
    /// `Header::set_path` refuses an absolute path and refuses a `..`, which
    /// is the library making one of the decisions this module has to make for
    /// itself. A test that could not express those paths could not prove
    /// spaceport refuses them, so the bytes go in directly — exactly as an
    /// attacker's `tar` implementation would write them.
    fn header(path: &str, kind: EntryType, mode: u32, size: u64) -> Header {
        let mut header = Header::new_gnu();
        let name = &mut header.as_old_mut().name;
        name.fill(0);
        name[..path.len()].copy_from_slice(path.as_bytes());
        header.set_entry_type(kind);
        header.set_mode(mode);
        header.set_size(size);
        header.set_cksum();

        header
    }

    fn file(builder: &mut Builder<Vec<u8>>, path: &str, mode: u32, contents: &str) {
        let header = header(path, EntryType::Regular, mode, contents.len() as u64);
        builder.append(&header, contents.as_bytes()).unwrap();
    }

    fn directory(builder: &mut Builder<Vec<u8>>, path: &str) {
        let header = header(path, EntryType::Directory, 0o755, 0);
        builder.append(&header, std::io::empty()).unwrap();
    }

    fn link(builder: &mut Builder<Vec<u8>>, path: &str, kind: EntryType, target: &str) {
        let mut header = header(path, kind, 0o777, 0);
        header.set_link_name_literal(target).unwrap();
        header.set_cksum();
        builder.append(&header, std::io::empty()).unwrap();
    }

    /// An ordinary commit: the wrapper directory, a subdirectory, a readme and
    /// a build script that has to stay executable.
    fn a_commit() -> Vec<u8> {
        tarball(|builder| {
            directory(builder, &format!("{PREFIX}/"));
            file(builder, &format!("{PREFIX}/README.md"), 0o644, "a readme\n");
            directory(builder, &format!("{PREFIX}/scripts/"));
            file(
                builder,
                &format!("{PREFIX}/scripts/build.sh"),
                0o755,
                "#!/bin/sh\n",
            );
        })
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;

        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn unpacks_a_commit_into_the_directory_it_was_given() {
        let into = destination("unpack-happy");

        let unpacked = unpack(&a_commit(), &into, &ROOMY).unwrap();

        assert_eq!(unpacked.prefix, PREFIX);
        // The wrapper directory is not among them; the other three are.
        assert_eq!(unpacked.entries, 3);
        assert_eq!(unpacked.bytes, "a readme\n".len() as u64 + 10);
        assert_eq!(
            std::fs::read_to_string(into.join("README.md")).unwrap(),
            "a readme\n"
        );
        assert_eq!(
            std::fs::read_to_string(into.join("scripts/build.sh")).unwrap(),
            "#!/bin/sh\n"
        );
        assert!(into.join("scripts").is_dir());

        let _ = std::fs::remove_dir_all(&into);
    }

    /// A repository's build scripts are meant to run, and a build that dies
    /// with "permission denied" would be blamed on the repository.
    #[cfg(unix)]
    #[test]
    fn keeps_the_executable_bit_a_build_script_needs() {
        let into = destination("unpack-executable");

        unpack(&a_commit(), &into, &ROOMY).unwrap();

        assert_eq!(mode_of(&into.join("scripts/build.sh")) & 0o111, 0o111);
        assert_eq!(mode_of(&into.join("README.md")) & 0o111, 0);

        let _ = std::fs::remove_dir_all(&into);
    }

    /// The prefix is whatever the archive says it is. Reconstructing GitHub's
    /// `{owner}-{repo}-{sha}` would be spaceport asserting a convention GitHub
    /// has never documented.
    #[test]
    fn reads_the_wrapper_directorys_name_off_the_archive() {
        let into = destination("unpack-prefix");
        let archive = tarball(|builder| {
            file(builder, "some-other-name/README.md", 0o644, "hello\n");
        });

        let unpacked = unpack(&archive, &into, &ROOMY).unwrap();

        assert_eq!(unpacked.prefix, "some-other-name");
        assert!(into.join("README.md").is_file());

        let _ = std::fs::remove_dir_all(&into);
    }

    /// Prevents an archive writing to `/etc/passwd`, or anywhere else on the
    /// host, by naming it outright.
    #[test]
    fn refuses_an_entry_naming_an_absolute_path() {
        let into = destination("unpack-absolute");
        let archive = tarball(|builder| {
            file(builder, &format!("{PREFIX}/README.md"), 0o644, "a readme\n");
            file(builder, "/etc/passwd", 0o644, "root::0:0::/:/bin/sh\n");
        });

        let error = unpack(&archive, &into, &ROOMY).unwrap_err().to_string();

        assert!(error.contains("absolute"), "{error}");
        assert!(!into.join("etc").exists());

        let _ = std::fs::remove_dir_all(&into);
    }

    /// Prevents the oldest tar escape there is: climbing out of the extraction
    /// directory with `..` and writing wherever the process can reach.
    #[test]
    fn refuses_an_entry_climbing_out_with_a_parent_component() {
        let into = destination("unpack-parent");
        let archive = tarball(|builder| {
            file(
                builder,
                &format!("{PREFIX}/../../../etc/cron.d/anything"),
                0o644,
                "* * * * * root sh\n",
            );
        });

        let error = unpack(&archive, &into, &ROOMY).unwrap_err().to_string();

        assert!(error.contains(".."), "{error}");
        assert!(!into.parent().unwrap().join("etc").exists());

        let _ = std::fs::remove_dir_all(&into);
    }

    /// Prevents the escape that hides inside an evaluation. This path resolves
    /// back inside the tree and is still refused, because judging it safe
    /// means evaluating it, and the day some other code evaluates it
    /// differently is the day the rule stops holding.
    #[test]
    fn refuses_a_parent_component_that_resolves_back_inside() {
        let into = destination("unpack-parent-inside");
        let archive = tarball(|builder| {
            file(
                builder,
                &format!("{PREFIX}/scripts/../README.md"),
                0o644,
                "a readme\n",
            );
        });

        let error = unpack(&archive, &into, &ROOMY).unwrap_err().to_string();

        assert!(error.contains(".."), "{error}");
        assert!(!into.join("README.md").exists());

        let _ = std::fs::remove_dir_all(&into);
    }

    /// Prevents an archive planting a symlink the build then reads or writes
    /// through, which is how a build context reaches `/etc` or `/root/.ssh`
    /// without ever naming a path outside itself.
    #[test]
    fn refuses_a_symlink_pointing_at_a_system_directory() {
        let into = destination("unpack-symlink-absolute");
        let archive = tarball(|builder| {
            link(
                builder,
                &format!("{PREFIX}/config"),
                EntryType::Symlink,
                "/etc",
            );
        });

        let error = unpack(&archive, &into, &ROOMY).unwrap_err().to_string();

        assert!(error.contains("outside the commit"), "{error}");
        assert!(!into.join("config").exists());

        let _ = std::fs::remove_dir_all(&into);
    }

    /// Prevents the relative version of the same escape, which no absolute
    /// path check would catch.
    #[test]
    fn refuses_a_symlink_pointing_out_of_the_tree() {
        let into = destination("unpack-symlink-relative");
        let archive = tarball(|builder| {
            directory(builder, &format!("{PREFIX}/scripts/"));
            link(
                builder,
                &format!("{PREFIX}/scripts/escape"),
                EntryType::Symlink,
                "../../../outside",
            );
        });

        let error = unpack(&archive, &into, &ROOMY).unwrap_err().to_string();

        assert!(error.contains("outside the commit"), "{error}");
        assert!(!into.join("scripts/escape").exists());

        let _ = std::fs::remove_dir_all(&into);
    }

    /// A symlink is resolved against its own directory rather than against the
    /// root, so a link that stays inside has to survive — a rule that refused
    /// every symlink would be safe and would not unpack a real repository.
    #[test]
    fn keeps_a_symlink_that_stays_inside_the_tree() {
        let into = destination("unpack-symlink-inside");
        let archive = tarball(|builder| {
            file(builder, &format!("{PREFIX}/README.md"), 0o644, "a readme\n");
            directory(builder, &format!("{PREFIX}/docs/"));
            link(
                builder,
                &format!("{PREFIX}/docs/readme"),
                EntryType::Symlink,
                "../README.md",
            );
        });

        let unpacked = unpack(&archive, &into, &ROOMY).unwrap();

        assert_eq!(unpacked.entries, 3);
        assert_eq!(
            std::fs::read_link(into.join("docs/readme")).unwrap(),
            Path::new("../README.md")
        );

        let _ = std::fs::remove_dir_all(&into);
    }

    /// Prevents an archive making a second name for a file on the host, which
    /// a later entry could then write through — the hardlink variant of the
    /// symlink escape, and one that survives a check that only looks at
    /// symlinks.
    #[test]
    fn refuses_a_hardlink_pointing_out_of_the_tree() {
        let into = destination("unpack-hardlink");
        let archive = tarball(|builder| {
            link(
                builder,
                &format!("{PREFIX}/passwd"),
                EntryType::Link,
                "../../../etc/passwd",
            );
        });

        let error = unpack(&archive, &into, &ROOMY).unwrap_err().to_string();

        assert!(error.contains("outside the commit"), "{error}");
        assert!(!into.join("passwd").exists());

        let _ = std::fs::remove_dir_all(&into);
    }

    /// Prevents an archive putting a device node or a fifo on the host, either
    /// of which is a thing no build context needs and a thing a later step
    /// might read from and block on forever.
    #[test]
    fn refuses_an_entry_that_is_a_fifo() {
        let into = destination("unpack-fifo");
        let archive = tarball(|builder| {
            let header = header(&format!("{PREFIX}/pipe"), EntryType::Fifo, 0o644, 0);
            builder.append(&header, std::io::empty()).unwrap();
        });

        let error = unpack(&archive, &into, &ROOMY).unwrap_err().to_string();

        assert!(error.contains("fifo"), "{error}");
        assert!(!into.join("pipe").exists());

        let _ = std::fs::remove_dir_all(&into);
    }

    /// Prevents a decompression bomb filling the host's disk. An entry that
    /// declares outright that it will not fit is refused before any of it
    /// reaches the disk at all.
    #[test]
    fn refuses_an_archive_expanding_past_the_byte_budget() {
        let into = destination("unpack-bomb");
        let big = "0".repeat(4096);
        let archive = tarball(|builder| {
            file(builder, &format!("{PREFIX}/zeroes"), 0o644, &big);
        });

        let error = unpack(
            &archive,
            &into,
            &Limits {
                total: 64,
                entries: 1000,
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("64 bytes"), "{error}");
        assert!(!into.join("zeroes").exists());

        let _ = std::fs::remove_dir_all(&into);
    }

    /// Prevents the bomb that lies about itself. A header can declare any size
    /// at all, so the copy is stopped in the middle rather than measured at
    /// the end — a bomb weighed after it has expanded is one the disk has
    /// already paid for.
    #[test]
    fn refuses_a_stream_that_grows_past_the_budget_while_it_is_being_written() {
        let into = destination("unpack-bomb-streaming");
        let limits = Limits {
            total: 64,
            entries: 1000,
        };

        let error = write_file(
            &mut std::io::repeat(b'0').take(4096),
            &into.join("zeroes"),
            0,
            &limits,
            "zeroes",
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("still expanding"), "{error}");
        // Nothing past the budget was ever handed to the filesystem.
        assert_eq!(std::fs::metadata(into.join("zeroes")).unwrap().len(), 0);

        let _ = std::fs::remove_dir_all(&into);
    }

    /// The budget is over the whole archive rather than over any one entry, so
    /// a bomb split into innocent-looking pieces is refused at the piece that
    /// crosses the line.
    #[test]
    fn refuses_an_archive_whose_entries_add_up_past_the_byte_budget() {
        let into = destination("unpack-bomb-cumulative");
        let chunk = "0".repeat(40);
        let archive = tarball(|builder| {
            file(builder, &format!("{PREFIX}/one"), 0o644, &chunk);
            file(builder, &format!("{PREFIX}/two"), 0o644, &chunk);
            file(builder, &format!("{PREFIX}/three"), 0o644, &chunk);
        });

        let error = unpack(
            &archive,
            &into,
            &Limits {
                total: 100,
                entries: 1000,
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("100 bytes"), "{error}");
        assert!(!into.join("three").exists());

        let _ = std::fs::remove_dir_all(&into);
    }

    /// Prevents the other shape of the same attack: an archive of a million
    /// empty files, which costs no bytes worth counting and exhausts the
    /// host's inodes.
    #[test]
    fn refuses_an_archive_holding_more_entries_than_the_budget() {
        let into = destination("unpack-entries");
        let archive = tarball(|builder| {
            for index in 0..10 {
                file(builder, &format!("{PREFIX}/file-{index}"), 0o644, "");
            }
        });

        let error = unpack(
            &archive,
            &into,
            &Limits {
                total: 1 << 20,
                entries: 4,
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("4 entries"), "{error}");
        assert!(!into.join("file-4").exists());

        let _ = std::fs::remove_dir_all(&into);
    }

    /// Prevents a repository shipping a setuid binary into a build context and
    /// having spaceport write it onto the host with the bit intact.
    #[cfg(unix)]
    #[test]
    fn strips_the_setuid_and_setgid_bits_from_a_file() {
        let into = destination("unpack-setuid");
        let archive = tarball(|builder| {
            file(builder, &format!("{PREFIX}/suid"), 0o4755, "an elf\n");
            file(builder, &format!("{PREFIX}/sgid"), 0o2755, "an elf\n");
        });

        unpack(&archive, &into, &ROOMY).unwrap();

        assert_eq!(mode_of(&into.join("suid")), 0o755);
        assert_eq!(mode_of(&into.join("sgid")), 0o755);

        let _ = std::fs::remove_dir_all(&into);
    }

    /// Stripping one leading component is only safe if there is exactly one to
    /// strip. Two roots would mean the second one's entries land a directory
    /// higher than they were meant to.
    #[test]
    fn refuses_an_archive_whose_entries_have_two_different_roots() {
        let into = destination("unpack-two-roots");
        let archive = tarball(|builder| {
            file(builder, &format!("{PREFIX}/README.md"), 0o644, "a readme\n");
            file(builder, "another-commit/README.md", 0o644, "another\n");
        });

        let error = unpack(&archive, &into, &ROOMY).unwrap_err().to_string();

        assert!(error.contains("another-commit"), "{error}");

        let _ = std::fs::remove_dir_all(&into);
    }

    /// An archive with no wrapper directory at all is not a GitHub source
    /// archive, and stripping a component from it would throw away a real
    /// file's name.
    #[test]
    fn refuses_an_archive_with_no_wrapper_directory_at_all() {
        let into = destination("unpack-no-root");
        let archive = tarball(|builder| {
            file(builder, "README.md", 0o644, "a readme\n");
            file(builder, "Dockerfile", 0o644, "FROM scratch\n");
        });

        let error = unpack(&archive, &into, &ROOMY).unwrap_err().to_string();

        assert!(error.contains("exactly one directory"), "{error}");
        assert!(!into.join("Dockerfile").exists());

        let _ = std::fs::remove_dir_all(&into);
    }

    /// The clearest place to say there is nothing to build is here, rather
    /// than three steps later where it looks like a missing manifest.
    #[test]
    fn refuses_an_empty_archive() {
        let into = destination("unpack-empty");
        let archive = tarball(|_| {});

        let error = unpack(&archive, &into, &ROOMY).unwrap_err().to_string();

        assert!(error.contains("no entries at all"), "{error}");

        let _ = std::fs::remove_dir_all(&into);
    }

    #[test]
    fn refuses_an_archive_holding_only_the_wrapper_directory() {
        let into = destination("unpack-only-root");
        let archive = tarball(|builder| {
            directory(builder, &format!("{PREFIX}/"));
        });

        let error = unpack(&archive, &into, &ROOMY).unwrap_err().to_string();

        assert!(error.contains("nothing but"), "{error}");

        let _ = std::fs::remove_dir_all(&into);
    }

    /// The lexical resolver is what stands in for asking the filesystem, so
    /// its answers are worth pinning down on their own.
    #[test]
    fn resolves_a_link_target_without_leaving_the_tree() {
        assert_eq!(
            resolve(&["docs"], "../README.md"),
            Some(vec!["README.md".to_owned()])
        );
        assert_eq!(
            resolve(&["docs"], "./guide/../intro.md"),
            Some(vec!["docs".to_owned(), "intro.md".to_owned()])
        );
        assert_eq!(resolve(&[], ".."), None);
        assert_eq!(resolve(&["docs"], "../../elsewhere"), None);
        assert_eq!(resolve(&["docs"], "/etc"), None);
    }
}
