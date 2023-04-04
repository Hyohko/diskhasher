/*
    DISKHASHER v0.2 - 2023 by Hyohko

    ##################################
    GPLv3 NOTICE AND DISCLAIMER
    ##################################

    This file is part of DISKHASHER.

    DISKHASHER is free software: you can redistribute it
    and/or modify it under the terms of the GNU General
    Public License as published by the Free Software
    Foundation, either version 3 of the License, or (at
    your option) any later version.

    DISKHASHER is distributed in the hope that it will
    be useful, but WITHOUT ANY WARRANTY; without even
    the implied warranty of MERCHANTABILITY or FITNESS
    FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General
    Public License along with DISKHASHER. If not, see
    <https://www.gnu.org/licenses/>.
*/
#[cfg(target_os = "linux")]
use crate::constants::ALIGNMENT;

use crate::{
    constants::{O_FLAGS, SIZE_128MB, SIZE_2MB},
    enums::HashAlg,
    error::HasherError,
    filedata::FileData,
};
// Macros at crate top-level
use crate::{filelog, hashobj, known_zero_hash};

use {
    digest::DynDigest,
    indicatif::{MultiProgress, ProgressBar, ProgressStyle},
    std::{
        fs::{File, OpenOptions},
        io::{Read, Write},
        sync::{Arc, Mutex},
    },
};

#[cfg(target_os = "linux")]
use {aligned_box::AlignedBox, std::os::unix::fs::OpenOptionsExt};

#[cfg(target_os = "windows")]
use std::os::windows::fs::OpenOptionsExt;

macro_rules! read_all_into_hasher {
    ($fd:expr, $hash:expr) => {
        #[cfg(target_os = "windows")]
        let mut buf = vec![0_u8; SIZE_2MB].into_boxed_slice();
        #[cfg(target_os = "linux")]
        let mut buf = AlignedBox::<[u8]>::slice_from_value(ALIGNMENT, SIZE_2MB, 0_u8)
            .expect("Heap read buffer allocation failed, panic");
        let mut read_count: usize;
        loop {
            {
                read_count = $fd.read(&mut buf[..SIZE_2MB])?;
                $hash.update(&buf[..read_count]);
            }
            if read_count < SIZE_2MB {
                break;
            }
        }
    };
}

/// Compute the hash
fn hash_file(
    fdata: &FileData,
    alg: HashAlg,
    opt_mp: &Option<MultiProgress>,
) -> Result<String, HasherError> {
    // If the file size is zero, then the hashes are already known. Don't bother computing them.
    if fdata.size() == 0 {
        return Ok(known_zero_hash!(alg));
    }

    let mut hasher: Box<dyn DynDigest> = hashobj!(alg);
    // the unwrap will not fail if you don't monkey with the constants that make up O_FLAGS
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(
            O_FLAGS
                .try_into()
                .expect("O_FLAGS integer conversion failed b/c the programmer messed with it"),
        )
        .open(fdata.path())?;

    if let Some(mp) = opt_mp {
        if fdata.size() >= SIZE_128MB as u64 {
            let style: ProgressStyle = ProgressStyle::with_template(
                "[{elapsed_precise}] \
                ({percent:3}%) \
                {bar:30.cyan/blue} \
                {bytes:>10.green}/{total_bytes:<10.green} \
                {msg}",
            )?
            .progress_chars("##-");
            let bar = mp.add(ProgressBar::new(fdata.size()).with_style(style));
            bar.set_message(format!("{:?}", fdata.path().file_name().unwrap()));
            read_all_into_hasher!(bar.wrap_read(&file), hasher);
            bar.finish_and_clear();
            mp.remove(&bar);
            drop(bar);
        } else {
            // smaller than 128 MB
            read_all_into_hasher!(file, hasher);
        }
    } else {
        // No progress bars
        read_all_into_hasher!(file, hasher);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn perform_hash_threadfunc(
    fdata: FileData,
    alg: HashAlg,
    force: bool,
    verbose: bool,
    loghandle: Option<Arc<Mutex<File>>>,
    opt_mp: Option<MultiProgress>,       // is already an Arc
    total_progress: Option<ProgressBar>, // is already an Arc
) -> Result<(), HasherError> {
    let actual_hash = hash_file(&fdata, alg, &opt_mp)?;
    if let Some(tp) = total_progress {
        tp.inc(1);
    }
    let result: String;
    if force {
        result = format!(
            "[*] Checksum value :\n\t{:?}\n\tHash         : {:?}\n",
            fdata.path(),
            actual_hash
        );
        // omitting zero-length hashes from console print in FORCE mode
        if fdata.size() > 0 {
            if let Some(mp) = opt_mp {
                mp.println(&result).ok();
            }
        }
        filelog!(result, loghandle);
    } else {
        // Compare
        if fdata.hash() == &actual_hash {
            if verbose {
                result = format!(
                    "[+] Checksum passed:\n\t{:?}\n\tActual hash  : {:?}\n",
                    fdata.path(),
                    actual_hash
                );
                if let Some(mp) = opt_mp {
                    mp.println(&result).ok();
                }
                filelog!(result, loghandle);
            }
        } else {
            result = format!(
                "[-] Checksum failed:\n\t{:?}\n\tExpected hash: {:?}\n\tActual hash  : {:?}\n",
                fdata.path(),
                fdata.hash(),
                actual_hash
            );
            if let Some(mp) = opt_mp {
                mp.println(&result).ok();
            }
            filelog!(result, loghandle);
        }
    }
    Ok(())
}
