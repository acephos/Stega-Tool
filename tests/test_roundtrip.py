import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import wave
import zlib
import cv2
import numpy as np
import stega

class RoundTripTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
 def tearDown(self):self.temp.cleanup()
 def audio(self,path,samples=1024,width=2,channels=1):
  with wave.open(str(path),'wb') as out:
   out.setnchannels(channels);out.setsampwidth(width);out.setframerate(8000);out.writeframes(bytes([128])*samples*width)
 def video(self,path):
  writer=cv2.VideoWriter(str(path),cv2.VideoWriter_fourcc(*'FFV1'),10,(32,32))
  self.assertTrue(writer.isOpened(),'FFV1 codec unavailable')
  for color in (20,100,200):writer.write(np.full((32,32,3),color,dtype=np.uint8))
  writer.release()
 def cli(self,*args):return subprocess.run([sys.executable,'Steganography.py',*map(str,args)],capture_output=True,text=True,timeout=30)
 def test_fresh_process_utf8_empty_and_multiline_roundtrips(self):
  for format in ('text','audio','video'):
   for number,message in enumerate(('', 'Hi 🌍 नमस्ते\nsecond line *^*^*')):
    with self.subTest(format=format,message=message):
     cover=self.root/f'cover-{format}-{number}';output=self.root/f'encoded-{format}-{number}'
     if format=='text':cover=cover.with_suffix('.txt');output=output.with_suffix('.txt');cover.write_text('word '*200)
     elif format=='audio':cover=cover.with_suffix('.wav');output=output.with_suffix('.wav');self.audio(cover)
     else:cover=cover.with_suffix('.avi');output=output.with_suffix('.avi');self.video(cover)
     extra=['--frame','1'] if format=='video' else []
     encoded=self.cli('encode',format,'--input',cover,'--output',output,'--message',message,*extra)
     self.assertEqual(encoded.returncode,0,encoded.stderr)
     decoded=self.cli('decode',format,'--input',output,*extra)
     self.assertEqual(decoded.returncode,0,decoded.stderr);self.assertEqual(decoded.stdout,message+'\n')
     if format=='video':
      np.testing.assert_array_equal(stega.video_frame(output,0),stega.video_frame(cover,0))
      np.testing.assert_array_equal(stega.video_frame(output,2),stega.video_frame(cover,2))
 def test_exact_text_capacity_and_rejection_leave_cover_intact(self):
  cover=self.root/'cover.txt';cover.write_text('word '*(stega.HEADER.size+3));original=cover.read_bytes()
  stega.encode_text(cover,self.root/'fits.txt','€');self.assertEqual(stega.decode_text(self.root/'fits.txt'),'€')
  with self.assertRaises(stega.StegaError):stega.encode_text(cover,self.root/'too-big.txt','€x')
  self.assertFalse((self.root/'too-big.txt').exists());self.assertEqual(cover.read_bytes(),original)
 def test_exact_pcm_capacity_sample_widths_and_stereo(self):
  for width in (1,2,3,4):
   cover=self.root/f'cover-{width}.wav';self.audio(cover,samples=(stega.HEADER.size+1)*8,width=width,channels=2)
   output=self.root/f'out-{width}.wav';stega.encode_audio(cover,output,'x');self.assertEqual(stega.decode_audio(output),'x')
   with self.assertRaises(stega.StegaError):stega.encode_audio(cover,self.root/f'overflow-{width}.wav','xx')
 def test_malformed_header_checksum_truncation_and_invalid_utf8(self):
  for data in (b'',b'garbage',stega.frame('x')[:-1],stega.frame('x')[:-1]+b'y',stega.HEADER.pack(stega.MAGIC,stega.MAX_PAYLOAD+1,0),stega.HEADER.pack(stega.MAGIC,1,zlib.crc32(b'\xff'))+b'\xff'):
   with self.assertRaises(stega.StegaError):stega.unpack(data)
  text=self.root/'plain.txt';text.write_text('plain words')
  with self.assertRaises(stega.StegaError):stega.decode_text(text)
  audio=self.root/'plain.wav';self.audio(audio)
  with self.assertRaises(stega.StegaError):stega.decode_audio(audio)
 def test_lossy_output_missing_frame_and_overwrite_are_rejected(self):
  cover=self.root/'cover.avi';self.video(cover)
  with self.assertRaises(stega.StegaError):stega.encode_video(cover,self.root/'out.mp4','x')
  with self.assertRaises(stega.StegaError):stega.encode_video(cover,self.root/'missing.avi','x',10)
  self.assertFalse((self.root/'missing.avi').exists());self.assertEqual(list(self.root.glob('.stega-*')),[])
  output=self.root/'existing.avi';output.write_bytes(b'keep')
  with self.assertRaises(stega.StegaError):stega.encode_video(cover,output,'x')
  self.assertEqual(output.read_bytes(),b'keep')

if __name__=='__main__':unittest.main()
