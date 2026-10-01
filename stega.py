"""Educational, byte-framed steganography. Concealment is not encryption."""
from __future__ import annotations
import argparse
import math
import os
from pathlib import Path
import re
import struct
import sys
import tempfile
import wave
import zlib

MAGIC = b'STG1'
HEADER = struct.Struct('>4sII')
ZWC = ('\u200b','\u200c','\u200d','\u2060')
MAX_PAYLOAD = 128 * 1024 * 1024

class StegaError(ValueError): pass

def frame(message: str) -> bytes:
    payload=message.encode('utf-8')
    if len(payload)>MAX_PAYLOAD: raise StegaError('Payload exceeds the implementation limit')
    return HEADER.pack(MAGIC,len(payload),zlib.crc32(payload))+payload

def unpack(data: bytes) -> str:
    if len(data)<HEADER.size: raise StegaError('Missing payload header')
    magic,length,checksum=HEADER.unpack(data[:HEADER.size])
    if magic!=MAGIC or length>MAX_PAYLOAD: raise StegaError('Invalid payload header')
    if length>len(data)-HEADER.size: raise StegaError('Truncated payload')
    payload=data[HEADER.size:HEADER.size+length]
    if zlib.crc32(payload)!=checksum: raise StegaError('Payload checksum mismatch')
    try:return payload.decode('utf-8')
    except UnicodeDecodeError as error:raise StegaError('Payload is not UTF-8') from error

def bits(data: bytes):
    for byte in data:
        for shift in range(7,-1,-1): yield (byte>>shift)&1

def extract_bits(values) -> str:
    # Read only a bounded header first; malformed covers cannot request unbounded allocation.
    iterator=iter(values)
    def read_bytes(count):
        output=bytearray()
        for _ in range(count):
            byte=0
            for _ in range(8):
                try:byte=(byte<<1)|(int(next(iterator))&1)
                except StopIteration as error:raise StegaError('Truncated payload bits') from error
            output.append(byte)
        return bytes(output)
    header=read_bytes(HEADER.size)
    magic,length,_=HEADER.unpack(header)
    if magic!=MAGIC or length>MAX_PAYLOAD:raise StegaError('No valid framed payload')
    return unpack(header+read_bytes(length))

def output_path(cover: Path, output: Path):
    if cover.resolve()==output.resolve():raise StegaError('Output must differ from the cover')
    if output.exists():raise StegaError('Output already exists; choose a new file')

def encode_text(cover: Path, output: Path, message: str):
    output_path(cover,output)
    text=cover.read_text(encoding='utf-8')
    if any(char in text for char in ZWC):raise StegaError('Cover already contains reserved zero-width characters')
    payload=frame(message)
    words=len(re.findall(r'\S+',text))
    if len(payload)>words:raise StegaError(f'Cover capacity is {max(0,words-HEADER.size)} UTF-8 payload bytes')
    position=0
    def insert(match):
        nonlocal position
        word=match.group()
        if position<len(payload):
            byte=payload[position];position+=1
            word+=''.join(ZWC[(byte>>shift)&3] for shift in (6,4,2,0))
        return word
    output.write_text(re.sub(r'\S+',insert,text),encoding='utf-8')

def decode_text(path: Path) -> str:
    reverse={char:index for index,char in enumerate(ZWC)}
    text=path.read_text(encoding='utf-8')
    return extract_bits(bit for char in text if char in reverse for bit in ((reverse[char]>>1)&1,reverse[char]&1))

def encode_audio(cover: Path, output: Path, message: str):
    output_path(cover,output)
    with wave.open(str(cover),'rb') as source:
        if source.getcomptype()!='NONE' or source.getsampwidth() not in (1,2,3,4):raise StegaError('Use uncompressed 8/16/24/32-bit PCM WAV')
        params=source.getparams();width=source.getsampwidth();samples=bytearray(source.readframes(source.getnframes()))
    payload=frame(message)
    if len(payload)*8>len(samples)//width:raise StegaError('Audio cover is too small for the framed UTF-8 payload')
    for index,bit in enumerate(bits(payload)):
        offset=index*width;samples[offset]=(samples[offset]&254)|bit
    with wave.open(str(output),'wb') as target:
        target.setparams(params);target.writeframes(samples)

def decode_audio(path: Path) -> str:
    with wave.open(str(path),'rb') as source:
        if source.getcomptype()!='NONE' or source.getsampwidth() not in (1,2,3,4):raise StegaError('Unsupported WAV format')
        width=source.getsampwidth();data=source.readframes(source.getnframes())
    return extract_bits(data[index]&1 for index in range(0,len(data),width))

def video_frame(path: Path, index: int):
    import cv2
    if index<0:raise StegaError('Frame index must be nonnegative')
    capture=cv2.VideoCapture(str(path))
    try:
        if not capture.isOpened():raise StegaError('Cannot open video')
        for i in range(index+1):
            ok,image=capture.read()
            if not ok:raise StegaError('Requested video frame does not exist')
        return image
    finally:capture.release()

def decode_video(path: Path, index: int=0) -> str:
    image=video_frame(path,index)
    return extract_bits(image.reshape(-1)&1)

def encode_video(cover: Path, output: Path, message: str, index: int=0):
    import cv2
    import numpy as np
    output_path(cover,output)
    if output.suffix.lower()!='.avi':raise StegaError('Video output must be lossless FFV1 .avi, not a lossy MP4')
    if index<0:raise StegaError('Frame index must be nonnegative')
    payload=frame(message);capture=cv2.VideoCapture(str(cover));writer=None;temporary=None
    try:
        if not capture.isOpened():raise StegaError('Cannot open video cover')
        width=int(capture.get(cv2.CAP_PROP_FRAME_WIDTH));height=int(capture.get(cv2.CAP_PROP_FRAME_HEIGHT));fps=capture.get(cv2.CAP_PROP_FPS)
        if width<1 or height<1:raise StegaError('Invalid video dimensions')
        if len(payload)*8>width*height*3:raise StegaError('Selected frame has insufficient payload capacity')
        if not math.isfinite(fps) or fps<=0:raise StegaError('Video frame rate is unavailable')
        descriptor,name=tempfile.mkstemp(suffix='.avi',prefix='.stega-',dir=output.parent);os.close(descriptor);temporary=Path(name)
        writer=cv2.VideoWriter(str(temporary),cv2.VideoWriter_fourcc(*'FFV1'),fps,(width,height))
        if not writer.isOpened():raise StegaError('FFV1 encoder is unavailable in this OpenCV build')
        count=0;embedded=False
        while True:
            ok,image=capture.read()
            if not ok:break
            if count==index:
                flat=image.reshape(-1);binary=np.unpackbits(np.frombuffer(payload,dtype=np.uint8));flat[:len(binary)]=(flat[:len(binary)]&254)|binary;embedded=True
            writer.write(image);count+=1
        if not embedded:raise StegaError('Requested video frame does not exist')
        writer.release();writer=None;capture.release()
        # Verify the on-disk output; lossy/reformatted output must never be reported as success.
        if decode_video(temporary,index)!=message:raise StegaError('Persisted video failed verification')
        os.replace(temporary,output);temporary=None
    finally:
        capture.release()
        if writer is not None:writer.release()
        if temporary is not None:temporary.unlink(missing_ok=True)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=['encode','decode']);parser.add_argument('format',choices=['text','audio','video'])
    parser.add_argument('--input',type=Path,required=True);parser.add_argument('--output',type=Path);parser.add_argument('--message');parser.add_argument('--message-file',type=Path);parser.add_argument('--frame',type=int,default=0)
    args=parser.parse_args(argv)
    try:
        if args.operation=='encode':
            if args.output is None:parser.error('encode requires --output')
            if (args.message is None)==(args.message_file is None):parser.error('choose --message or --message-file')
            message=args.message_file.read_text(encoding='utf-8') if args.message_file else args.message
            if args.format=='video':encode_video(args.input,args.output,message,args.frame)
            else:globals()['encode_'+args.format](args.input,args.output,message)
        else:
            message=decode_video(args.input,args.frame) if args.format=='video' else globals()['decode_'+args.format](args.input)
            print(message)
        return 0
    except (StegaError,OSError,wave.Error,ImportError) as error:
        print(f'Error: {error}',file=sys.stderr);return 1

if __name__=='__main__':raise SystemExit(main())
