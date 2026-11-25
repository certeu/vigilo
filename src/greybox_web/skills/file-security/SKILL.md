---
name: file-security
description: Assess upload download metadata and path handling without unsafe files.
when: the target accepts or serves files, attachments, imports, exports, or path-like resource names.
requires: [http]
modes: [web]
phases: [{id: A, title: Map file workflow}, {id: B, title: Compare identities}, {id: C, title: Validate handling}]
criteria:
  - {id: workflow, phase: A, text: Upload and download interfaces and ownership recorded}
  - {id: access, phase: B, text: At least one owned file compared across relevant identities}
  - {id: handling, phase: C, text: Metadata content disposition type and safe path controls assessed}
---
# file-security
Use a small text file with a unique inert marker and disposable synthetic resources. Record owner, container, download interface, metadata and expected readers before testing. Verify unauthorized reads with the owner/control response and a different identity. For path handling, change only a synthetic filename or identifier; never target host files. Upload only when explicitly permitted, never executable content. A changed filename, error, or accepted extension is not exploitability; require the marker to be stored or served in an unintended place. Report blocked writes and unobservable storage behavior as inconclusive.
