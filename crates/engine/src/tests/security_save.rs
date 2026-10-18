//! Security changes must stay coherent when undo crosses the last saved revision (#3276).
use super::*;
use pdfcraft_cos::{Algorithm, Document as CosDocument, NewEncryption, Object, SaveOptions, write_full};

fn encrypted_fixture(algorithm: Algorithm, inline: bool) -> Arc<Vec<u8>> {
    let mut doc = CosDocument::open(Arc::new(fixture(2))).unwrap();
    pdfcraft_organize::set_info(&mut doc, "Title", "Security regression title").unwrap();
    let mut metadata = pdfcraft_cos::Dict::new();
    metadata.set(b"Type".to_vec(), Object::name("Metadata"));
    metadata.set(b"Subtype".to_vec(), Object::name("XML"));
    let metadata = doc.add(Object::Stream(pdfcraft_cos::Stream::from_raw(metadata, b"<metadata>Security regression</metadata>".to_vec())));
    doc.update_dict(doc.root().unwrap(), |d| d.set(b"Metadata".to_vec(), Object::Ref(metadata))).unwrap();
    doc.set_encryption(&NewEncryption {
        algorithm,
        user_password: "user",
        owner_password: "owner",
        permissions: -1,
        encrypt_metadata: true,
        seed: [7; 32],
    })
    .unwrap();
    if inline {
        let r = doc.trailer().reference(b"Encrypt").unwrap();
        let dict = doc.get(r).as_dict().cloned().unwrap();
        doc.trailer_mut().set(b"Encrypt".to_vec(), Object::Dict(dict));
    }
    Arc::new(write_full(&doc, &SaveOptions::default()).unwrap())
}

/// Check the saved file, not the still-correct in-memory snapshot. A catalog/page-count
/// check alone accepts the broken reverse transition with two blank pages.
fn assert_saved_content(s: &Session, id: DocId, bytes: Arc<Vec<u8>>, password: Option<&str>, encrypted: bool) -> Result<(), String> {
    let check = s.check_save(id, &bytes);
    let plain_marker = bytes.windows(b"(Page 1)".len()).any(|w| w == b"(Page 1)");
    let mut reopened = Session::new();
    let restored = reopened.open("saved.pdf", None, bytes.clone(), password);
    let restored = restored.map_err(|e| format!("check_save={check:?}, plaintext marker={plain_marker}, reopen={e:?}"))?;
    let texts = page_texts(&reopened, restored);
    if check.is_err() || texts != ["Page 1", "Page 2"] {
        return Err(format!("check_save={check:?}, plaintext marker={plain_marker}, text={texts:?}"));
    }
    assert_eq!(reopened.get(restored).unwrap().info.encrypted, encrypted);
    assert_eq!(reopened.get(restored).unwrap().info_value("Title"), s.get(id).unwrap().info_value("Title"));
    fn metadata(doc: &CosDocument) -> Option<Vec<u8>> {
        let catalog = doc.get(doc.root()?);
        let stream = doc.resolve(catalog.as_dict()?.get(b"Metadata")?);
        let Object::Stream(stream) = stream.as_ref() else { return None };
        Some(stream.decoded().unwrap().to_vec())
    }
    assert_eq!(metadata(&reopened.get(restored).unwrap().editor.as_ref().unwrap().cos), metadata(&s.get(id).unwrap().editor.as_ref().unwrap().cos));
    if encrypted {
        assert!(!plain_marker, "encrypted saves must not expose page content");
        assert!(CosDocument::open_with_password(bytes, Some("wrong")).is_err());
    } else {
        // The fixture's content is stored unfiltered: without this, the check above could pass
        // only because the writer started compressing streams.
        assert!(plain_marker, "a plain save shows the page content");
    }
    Ok(())
}

#[test]
fn undo_saved_security_removal_restores_encrypted_content() {
    let mut failures = Vec::new();
    for algorithm in [Algorithm::Rc4_40, Algorithm::Rc4_128, Algorithm::Aes128, Algorithm::Aes256] {
        for inline in [false, true] {
            for password in ["owner", "user"] {
                let mut s = Session::new();
                let id = s.open("encrypted.pdf", None, encrypted_fixture(algorithm, inline), Some(password)).unwrap();
                s.apply(id, Edit::RemoveProtection).unwrap();
                let plain = s.save_bytes(id).unwrap();
                assert_saved_content(&s, id, plain.clone(), None, false).unwrap();
                s.mark_saved(id, plain, None).unwrap();
                s.undo(id).unwrap();
                assert_saved_content(&s, id, s.save_full_bytes(id).unwrap(), Some(password), true).unwrap();
                let restored = s.save_bytes(id).unwrap();
                if let Err(error) = assert_saved_content(&s, id, restored.clone(), Some(password), true) {
                    failures.push(format!("{algorithm:?}, inline={inline}, {password}: {error}"));
                    continue;
                }
                // Both original passwords still work; saving also retains this session's rights.
                assert_saved_content(&s, id, restored.clone(), Some("user"), true).unwrap();
                assert_saved_content(&s, id, restored.clone(), Some("owner"), true).unwrap();
                s.mark_saved(id, restored.clone(), None).unwrap();
                assert!(!s.get(id).unwrap().dirty);
                assert_eq!(*s.save_bytes(id).unwrap(), *restored, "an unchanged save is byte-stable");
                s.redo(id).unwrap();
                let plain = s.save_bytes(id).unwrap();
                assert_saved_content(&s, id, plain.clone(), None, false).unwrap();
                s.mark_saved(id, plain, None).unwrap();
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn undo_saved_protection_restores_plain_content() {
    let mut failures = Vec::new();
    for algorithm in [Algorithm::Rc4_128, Algorithm::Aes128, Algorithm::Aes256] {
        let (mut s, id) = session_with(2);
        s.apply(id, Edit::Protect(Protection { algorithm, ..protection(Some("user"), Some("owner")) })).unwrap();
        let protected = s.save_bytes(id).unwrap();
        assert_saved_content(&s, id, protected.clone(), Some("owner"), true).unwrap();
        s.mark_saved(id, protected, None).unwrap();
        s.undo(id).unwrap();
        assert_saved_content(&s, id, s.save_full_bytes(id).unwrap(), None, false).unwrap();
        let restored = s.save_bytes(id).unwrap();
        if let Err(error) = assert_saved_content(&s, id, restored.clone(), None, false) {
            failures.push(format!("{algorithm:?}: {error}"));
            continue;
        }
        s.mark_saved(id, restored.clone(), None).unwrap();
        assert!(!s.get(id).unwrap().dirty);
        assert_eq!(*s.save_bytes(id).unwrap(), *restored);
        s.redo(id).unwrap();
        let protected = s.save_bytes(id).unwrap();
        assert_saved_content(&s, id, protected.clone(), Some("owner"), true).unwrap();
        s.mark_saved(id, protected, None).unwrap();
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn undo_saved_rekey_with_the_same_passwords_restores_original_security() {
    let mut failures = Vec::new();
    // Identical password strings are not a security identity: changing algorithm, permission
    // bits, metadata encryption, or simply generating a fresh AES-256 key changes the output.
    for (algorithm, copy, encrypt_metadata) in [
        (Algorithm::Rc4_128, true, true),
        (Algorithm::Aes128, true, true),
        (Algorithm::Aes256, false, true),
        (Algorithm::Aes256, true, false),
        (Algorithm::Aes256, true, true),
    ] {
        let (mut s, id) = session_with(2);
        s.apply(id, Edit::Protect(protection(Some("user"), Some("owner")))).unwrap();
        let protected = s.save_bytes(id).unwrap();
        s.mark_saved(id, protected, None).unwrap();
        let original = s.get(id).unwrap().editor.as_ref().unwrap().cos.output_handler().unwrap().dict().clone();
        s.apply(id, Edit::Protect(Protection { algorithm, copy, encrypt_metadata, ..protection(Some("user"), Some("owner")) })).unwrap();
        let protected = s.save_bytes(id).unwrap();
        s.mark_saved(id, protected, None).unwrap();
        s.undo(id).unwrap();
        let restored = s.save_bytes(id).unwrap();
        let editor = s.get(id).unwrap().editor.as_ref().unwrap();
        assert_eq!(editor.keys, editor.saved_keys, "password strings alone cannot detect this transition");
        if let Err(error) = assert_saved_content(&s, id, restored.clone(), Some("owner"), true) {
            failures.push(format!("{algorithm:?}, copy={copy}, metadata={encrypt_metadata}: {error}"));
            continue;
        }
        let reopened = CosDocument::open_with_password(restored, Some("owner")).unwrap();
        assert_eq!(reopened.security().unwrap().dict(), &original);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn undo_encrypted_compaction_restores_the_encrypt_dictionary_exemption() {
    let mut cos = CosDocument::open(Arc::new(fixture(3))).unwrap();
    cos.set_encryption(&NewEncryption {
        algorithm: Algorithm::Aes256,
        user_password: "user",
        owner_password: "owner",
        permissions: -1,
        encrypt_metadata: true,
        seed: [7; 32],
    })
    .unwrap();
    let original = Arc::new(write_full(&cos, &SaveOptions::default()).unwrap());
    let original = CosDocument::open_with_password(original, Some("owner")).unwrap();
    let mut s = Session::new();
    let id = s.open("compact.pdf", None, original.bytes().clone(), Some("owner")).unwrap();
    s.apply(id, Edit::DeletePages { pages: vec![0] }).unwrap();
    let compact = s.save_full_bytes(id).unwrap();
    let compact_doc = CosDocument::open_with_password(compact.clone(), Some("owner")).unwrap();
    assert_eq!(original.security().unwrap().dict(), compact_doc.security().unwrap().dict());
    assert_ne!(original.trailer().reference(b"Encrypt"), compact_doc.trailer().reference(b"Encrypt"), "compaction renumbered /Encrypt");
    s.mark_saved(id, compact, None).unwrap();
    s.undo(id).unwrap();
    let restored = s.save_bytes(id).unwrap();
    s.check_save(id, &restored).unwrap();
    assert!(!restored.windows(b"(Page 1)".len()).any(|w| w == b"(Page 1)"), "page content stays encrypted");
    assert!(CosDocument::open(restored.clone()).is_err() && CosDocument::open_with_password(restored.clone(), Some("wrong")).is_err());
    let mut reopened = Session::new();
    let id = reopened.open("restored.pdf", None, restored, Some("user")).unwrap();
    assert!(reopened.get(id).unwrap().info.encrypted);
    assert_eq!(page_texts(&reopened, id), ["Page 1", "Page 2", "Page 3"]);
}

/// A restricted user who unlocks with the owner password, removes protection, saves and undoes
/// gets the original restrictions back, not an unrestricted or owner-only file.
#[test]
fn undo_saved_removal_after_unlock_keeps_the_user_restrictions() {
    for algorithm in [Algorithm::Rc4_128, Algorithm::Aes128, Algorithm::Aes256] {
        let (mut s, id) = session_with(2);
        s.apply(id, Edit::Protect(Protection { algorithm, ..protection(Some("user"), Some("owner")) })).unwrap();
        let protected = s.save_bytes(id).unwrap();
        let p = CosDocument::open_with_password(protected.clone(), Some("user")).unwrap().permissions().unwrap();
        assert!(!p.owner && !p.copy() && !p.modify(), "{algorithm:?}: the fixture restricts the user");

        let mut s = Session::new();
        let id = s.open("restricted.pdf", None, protected, Some("user")).unwrap();
        assert!(matches!(s.apply(id, Edit::RemoveProtection), Err(EditError::NotPermitted(_))), "{algorithm:?}");
        s.unlock(id, "owner").unwrap();
        s.apply(id, Edit::RemoveProtection).unwrap();
        let plain = s.save_bytes(id).unwrap();
        assert_saved_content(&s, id, plain.clone(), None, false).unwrap();
        s.mark_saved(id, plain, None).unwrap();
        s.undo(id).unwrap();
        let restored = s.save_bytes(id).unwrap();
        assert_saved_content(&s, id, restored.clone(), Some("owner"), true).unwrap();
        let user = CosDocument::open_with_password(restored.clone(), Some("user")).unwrap();
        let p = user.permissions().unwrap();
        assert!(!p.owner && !p.copy() && !p.modify(), "{algorithm:?}: restrictions survive the undo and save");
        assert!(CosDocument::open_with_password(restored.clone(), Some("owner")).unwrap().permissions().unwrap().owner, "{algorithm:?}");
        s.mark_saved(id, restored.clone(), None).unwrap();
        assert!(!s.get(id).unwrap().dirty, "{algorithm:?}");
        assert_eq!(*s.save_bytes(id).unwrap(), *restored, "{algorithm:?}: an unchanged save is byte-stable");
    }
}

#[test]
fn undo_ordinary_encrypted_edits_keeps_the_last_saved_revision() {
    let mut s = Session::new();
    let id = s.open("encrypted.pdf", None, encrypted_fixture(Algorithm::Aes256, false), Some("user")).unwrap();
    s.apply(id, Edit::RotatePages { pages: vec![0], degrees: 90 }).unwrap();
    let saved = s.save_bytes(id).unwrap();
    s.mark_saved(id, saved.clone(), None).unwrap();
    s.undo(id).unwrap();
    let restored = s.save_bytes(id).unwrap();
    assert!(restored.starts_with(saved.as_slice()), "compatible encryption still appends to the latest saved bytes");
    assert_saved_content(&s, id, restored.clone(), Some("user"), true).unwrap();
    s.mark_saved(id, restored, None).unwrap();
    s.redo(id).unwrap();
    let rotated = s.save_bytes(id).unwrap();
    assert_saved_content(&s, id, rotated, Some("user"), true).unwrap();
}

#[test]
fn undo_saved_password_change_restores_original_passwords() {
    let mut s = Session::new();
    let id = s.open("encrypted.pdf", None, encrypted_fixture(Algorithm::Aes256, true), Some("owner")).unwrap();
    s.apply(id, Edit::Protect(protection(Some("new-user"), Some("new-owner")))).unwrap();
    let changed = s.save_bytes(id).unwrap();
    s.mark_saved(id, changed, None).unwrap();
    s.undo(id).unwrap();
    let restored = s.save_bytes(id).unwrap();
    assert_saved_content(&s, id, restored.clone(), Some("user"), true).unwrap();
    assert_saved_content(&s, id, restored.clone(), Some("owner"), true).unwrap();
    assert!(CosDocument::open_with_password(restored.clone(), Some("new-user")).is_err());
    assert!(CosDocument::open_with_password(restored, Some("new-owner")).is_err());
}
