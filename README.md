# JHU EN.605.731 CCS project

## how to run:
1) Install pip dependencies:
      Run `pip install bitarray mmh3`

2) Start server:
      Run `python powserver.py -ip 127.0.0.1 -port 9998 -pow_type {powtype}`

2) Once Server has started, start client:
      Run `python powclient.py -ip 127.0.0.1 -port 9998 -action upload -pow_type {powtype}`

   If you run it once, it will upload the file, and the server will save it
   as server_flamingo.jpg.  If the client command again, then the server will
   challenge the client to prove ownership over the file, verify it, and
   then skip the upload.