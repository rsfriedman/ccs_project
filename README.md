# JHU EN.605.731 CCS project

## how to run:
1) Run `python server.py`

2) Once Server has started: `python client.py`


# POW example client/server
1) Start the server first from one command window:
      python powserver.py -ip 127.0.0.1 -port 9998
2) Run the client once to upload the file (currently hardcoded to flamingo.jpg)
      python powclient.py -ip 127.0.0.1 -port 9998 -action upload
      
   If you run it once, it will upload the file, and the server will save it
   as server_flamingo.jpg.  If the client command again, then the server will
   challenge the client to prove ownership over the file, verify it, and
   then skip the upload.
