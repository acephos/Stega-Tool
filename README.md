# Stega-Tool

Educational text/audio/video concealment with an explicit UTF-8 byte format. This is earlier learning work, not a secure messaging system. Concealment and CRC checksums do not provide confidentiality, authentication, or resilience to content transformations. The earlier RC4/menu implementation remains in Git history; maintained encoding deliberately makes no encryption claim.

## Setup

Use Python 3.12+, create a virtual environment, and install `requirements.txt`. Text and PCM WAV use the standard library; video requires pinned NumPy/OpenCV. The earlier unused pandas/matplotlib imports are removed.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python Steganography.py encode text --input Sample_cover_files/cover_text.txt --output stego-text.txt --message 'Hello 🌍'
python Steganography.py decode text --input stego-text.txt
```

Replace `text` with `audio` for an uncompressed PCM WAV. For video, choose a zero-based frame and write lossless AVI:

```bash
python Steganography.py encode video --input Sample_cover_files/cover_video.mp4 --output stego-video.avi --frame 0 --message 'Hello'
python Steganography.py decode video --input stego-video.avi --frame 0
```

`--message-file message.txt` preserves multiline text and avoids putting the message in shell arguments. Decoders read the persisted file, including video frames. Video output uses FFV1, requires an OpenCV build with that encoder, and is decoded again before success. It contains video only; source audio tracks are not copied. Lossy MP4 output is rejected because it destroys embedded bits. Do not recompress an encoded file.

## Format and capacity

The frame is `STG1`, a big-endian 32-bit UTF-8 byte length, a 32-bit CRC32, then the payload. The 12-byte header is included in capacity calculations. Unicode character counts are not byte counts. Unframed legacy files are incompatible and fail clearly rather than returning guessed messages.

- Text embeds one framed byte as four zero-width characters per cover word and preserves visible whitespace. Capacity is `word_count - 12` payload bytes. Reserved zero-width characters in a cover are rejected.
- WAV embeds one bit per sample in the least-significant byte. Supported sample widths are 8/16/24/32-bit PCM, including multiple channels. Capacity is `floor(sample_count / 8) - 12` payload bytes.
- Video embeds one bit per color-channel byte of the selected frame. Capacity is `floor(width * height * 3 / 8) - 12` payload bytes. Other frames are written through the lossless codec.

Existing outputs and source overwrites are rejected. Missing/truncated headers, bad checksums, invalid UTF-8, insufficient covers, and nonexistent frames fail. Payloads also have a 128 MiB implementation limit.

## Verification

`python -m unittest discover -s tests -v` generates its own covers and verifies fresh-process decode, Unicode, empty/multiline payloads, exact capacities, malformed inputs, sample widths/stereo, frame selection, unchanged other frames, and output failure cleanup. CI does not use private payloads or downloaded media.

The bundled covers are historical examples; use generated fixtures or your own permitted material. The [OpenCV VideoWriter documentation](https://docs.opencv.org/5.0/main_modules/classcv_1_1VideoWriter.html) describes the lossless codec requirement.
